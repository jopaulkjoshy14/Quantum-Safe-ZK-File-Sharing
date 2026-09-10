import {
  bytesToBase64,
  base64ToBytes,
  generateIV,
} from "./crypto.js";

const AES_ALGORITHM = "AES-GCM";

/**
 * Import a raw 256-bit key as an AES-256-GCM CryptoKey.
 *
 * Used for the application Master Key.
 */
export async function importMasterKey(masterKey) {
  if (!(masterKey instanceof Uint8Array)) {
    throw new Error("Master Key must be a Uint8Array.");
  }

  if (masterKey.length !== 32) {
    throw new Error("Master Key must be exactly 32 bytes.");
  }

  return crypto.subtle.importKey(
    "raw",
    masterKey,
    {
      name: AES_ALGORITHM,
    },
    false,
    ["encrypt", "decrypt"]
  );
}

/**
 * Protect the ML-KEM secret key using the Master Key.
 *
 * Master Key
 *     ↓
 * AES-256-GCM
 *     ↓
 * Wrapped ML-KEM Secret Key
 *
 * The plaintext ML-KEM secret key never leaves the browser.
 */
export async function wrapMLKEMSecretKey(masterKey, secretKey) {
  if (!(masterKey instanceof Uint8Array)) {
    throw new Error("Master Key must be a Uint8Array.");
  }

  if (masterKey.length !== 32) {
    throw new Error("Master Key must be exactly 32 bytes.");
  }

  if (!(secretKey instanceof Uint8Array)) {
    throw new Error("ML-KEM secret key must be a Uint8Array.");
  }

  const masterKeyCryptoKey = await importMasterKey(masterKey);

  const iv = generateIV();

  const wrappedSecretKey = await crypto.subtle.encrypt(
    {
      name: AES_ALGORITHM,
      iv,
    },
    masterKeyCryptoKey,
    secretKey
  );

  return {
    wrappedMlKemPrivateKey: bytesToBase64(
      new Uint8Array(wrappedSecretKey)
    ),
    privateKeyIV: bytesToBase64(iv),
  };
}

/**
 * Unprotect an ML-KEM secret key using the Master Key.
 *
 * Used later when Bob needs to decrypt a shared file.
 */
export async function unwrapMLKEMSecretKey(
  masterKey,
  wrappedMlKemPrivateKey,
  privateKeyIV
) {
  if (!(masterKey instanceof Uint8Array)) {
    throw new Error("Master Key must be a Uint8Array.");
  }

  const masterKeyCryptoKey = await importMasterKey(masterKey);

  const ciphertext = base64ToBytes(wrappedMlKemPrivateKey);
  const iv = base64ToBytes(privateKeyIV);

  const secretKey = await crypto.subtle.decrypt(
    {
      name: AES_ALGORITHM,
      iv,
    },
    masterKeyCryptoKey,
    ciphertext
  );

  return new Uint8Array(secretKey);
}
