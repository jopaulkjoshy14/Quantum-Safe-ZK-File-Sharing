import {
  base64ToBytes,
  deriveKEK,
} from "./crypto.js";

import {
  unwrapMLKEMSecretKey,
} from "./keyProtection.js";

const MASTER_KEY_LENGTH = 32;
const AES_GCM_IV_LENGTH = 12;

/**
 * Recover the Master Key from the protected Master Key
 * returned by the backend.
 *
 * Password → PBKDF2 → KEK → AES-GCM → Master Key
 *
 * IMPORTANT:
 * The Master Key is recovered entirely inside the browser.
 */
export async function recoverMasterKey({
  password,
  passwordKdfSalt,
  passwordKdfParams,
  wrappedMasterKey,
  masterKeyIV,
}) {
  if (
    typeof password !== "string" ||
    password.length === 0
  ) {
    throw new Error("Password is required.");
  }

  if (
    typeof passwordKdfSalt !== "string" ||
    passwordKdfSalt.length === 0
  ) {
    throw new Error("Password KDF salt is missing.");
  }

  if (
    !passwordKdfParams ||
    passwordKdfParams.algorithm !==
      "PBKDF2-HMAC-SHA-256" ||
    passwordKdfParams.iterations !== 310000 ||
    passwordKdfParams.keyLength !== 256
  ) {
    throw new Error(
      "Unsupported password KDF parameters."
    );
  }

  if (
    typeof wrappedMasterKey !== "string" ||
    wrappedMasterKey.length === 0
  ) {
    throw new Error(
      "Protected Master Key is missing."
    );
  }

  if (
    typeof masterKeyIV !== "string" ||
    masterKeyIV.length === 0
  ) {
    throw new Error("Master Key IV is missing.");
  }

  const salt = base64ToBytes(passwordKdfSalt);
  const iv = base64ToBytes(masterKeyIV);
  const ciphertext = base64ToBytes(wrappedMasterKey);

  if (salt.length !== 16) {
    throw new Error("Invalid password KDF salt.");
  }

  if (iv.length !== AES_GCM_IV_LENGTH) {
    throw new Error("Invalid Master Key IV.");
  }

  const kek = await deriveKEK(password, salt);

  let masterKey;

  try {
    const plaintext = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv,
      },
      kek,
      ciphertext
    );

    masterKey = new Uint8Array(plaintext);
  } catch {
    throw new Error(
      "Unable to recover Master Key. Invalid password or corrupted key data."
    );
  }

  if (masterKey.length !== MASTER_KEY_LENGTH) {
    throw new Error(
      "Recovered Master Key has an invalid length."
    );
  }

  return masterKey;
}

/**
 * Recover the ML-KEM-768 private key using the
 * recovered Master Key.
 *
 * Master Key → AES-GCM → ML-KEM private key
 *
 * The private key remains in browser memory.
 */
export async function recoverMLKEMPrivateKey({
  masterKey,
  wrappedMlKemPrivateKey,
  privateKeyIV,
}) {
  if (!(masterKey instanceof Uint8Array)) {
    throw new Error(
      "Master Key must be a Uint8Array."
    );
  }

  if (masterKey.length !== MASTER_KEY_LENGTH) {
    throw new Error(
      "Master Key must be exactly 32 bytes."
    );
  }

  if (
    typeof wrappedMlKemPrivateKey !== "string" ||
    wrappedMlKemPrivateKey.length === 0
  ) {
    throw new Error(
      "Protected ML-KEM private key is missing."
    );
  }

  if (
    typeof privateKeyIV !== "string" ||
    privateKeyIV.length === 0
  ) {
    throw new Error(
      "ML-KEM private key IV is missing."
    );
  }

  const iv = base64ToBytes(privateKeyIV);
  const ciphertext = base64ToBytes(
    wrappedMlKemPrivateKey
  );

  if (iv.length !== AES_GCM_IV_LENGTH) {
    throw new Error(
      "Invalid ML-KEM private key IV."
    );
  }

  let secretKey;

  try {
    secretKey = await unwrapMLKEMSecretKey(
      masterKey,
      wrappedMlKemPrivateKey,
      privateKeyIV
    );
  } catch {
    throw new Error(
      "Unable to recover ML-KEM private key."
    );
  }

  /*
   * ML-KEM-768 secret key size:
   * 2400 bytes.
   */
  if (secretKey.length !== 2400) {
    throw new Error(
      "Recovered ML-KEM private key has an invalid length."
    );
  }

  return secretKey;
}

/**
 * Complete browser-side cryptographic login recovery.
 *
 * Backend authentication happens first.
 * This function then reconstructs the user's protected
 * cryptographic state locally.
 */
export async function recoverLoginKeys({
  password,
  passwordKdfSalt,
  passwordKdfParams,
  wrappedMasterKey,
  masterKeyIV,
  wrappedMlKemPrivateKey,
  privateKeyIV,
}) {
  const masterKey = await recoverMasterKey({
    password,
    passwordKdfSalt,
    passwordKdfParams,
    wrappedMasterKey,
    masterKeyIV,
  });

  const mlKemPrivateKey =
    await recoverMLKEMPrivateKey({
      masterKey,
      wrappedMlKemPrivateKey,
      privateKeyIV,
    });

  return {
    masterKey,
    mlKemPrivateKey,
  };
}
