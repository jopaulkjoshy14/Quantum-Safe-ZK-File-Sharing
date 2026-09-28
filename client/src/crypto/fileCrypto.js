import {
  generateIV,
} from "./crypto.js";

const AES_ALGORITHM = "AES-GCM";

const FEK_LENGTH = 32; // 256 bits
const IV_LENGTH = 12;  // 96 bits

/**
 * Generate a fresh random File Encryption Key (FEK).
 *
 * IMPORTANT:
 * Every file receives its own independent FEK.
 *
 * The FEK is never derived from:
 * - filename
 * - password
 * - file contents
 * - user ID
 */
export function generateFileEncryptionKey() {
  return crypto.getRandomValues(
    new Uint8Array(FEK_LENGTH)
  );
}

/**
 * Import a raw FEK as an AES-256-GCM CryptoKey.
 */
async function importFileEncryptionKey(fek) {
  if (!(fek instanceof Uint8Array)) {
    throw new Error(
      "File Encryption Key must be a Uint8Array."
    );
  }

  if (fek.length !== FEK_LENGTH) {
    throw new Error(
      "File Encryption Key must be exactly 32 bytes."
    );
  }

  return crypto.subtle.importKey(
    "raw",
    fek,
    {
      name: AES_ALGORITHM,
    },
    false,
    ["encrypt", "decrypt"]
  );
}

/**
 * Encrypt a File object using a fresh FEK.
 *
 * File
 *   ↓
 * AES-256-GCM
 *   ↓
 * Ciphertext
 *
 * Returns:
 * - encryptedData
 * - FEK
 * - IV
 *
 * IMPORTANT:
 * The plaintext file never leaves the browser
 * during this operation.
 */
export async function encryptFile(file) {
  if (!(file instanceof File)) {
    throw new Error(
      "A valid File object is required."
    );
  }

  const fek = generateFileEncryptionKey();

  const fileKey = await importFileEncryptionKey(
    fek
  );

  const iv = generateIV();

  const plaintext = await file.arrayBuffer();

  const ciphertext =
    await crypto.subtle.encrypt(
      {
        name: AES_ALGORITHM,
        iv,
      },
      fileKey,
      plaintext
    );

  return {
    encryptedData: new Uint8Array(ciphertext),

    /*
     * This is sensitive and must remain in
     * browser memory until it is wrapped.
     */
    fek,

    iv,
  };
}

/**
 * Decrypt encrypted file data using the FEK.
 *
 * Ciphertext
 *    ↓
 * AES-256-GCM
 *    ↓
 * Plaintext
 *
 * The decrypted bytes are returned to the browser.
 */
export async function decryptFile(
  encryptedData,
  fek,
  iv
) {
  if (
    !(
      encryptedData instanceof
      Uint8Array
    )
  ) {
    throw new Error(
      "Encrypted file data must be a Uint8Array."
    );
  }

  if (!(fek instanceof Uint8Array)) {
    throw new Error(
      "File Encryption Key must be a Uint8Array."
    );
  }

  if (fek.length !== FEK_LENGTH) {
    throw new Error(
      "File Encryption Key must be exactly 32 bytes."
    );
  }

  if (!(iv instanceof Uint8Array)) {
    throw new Error(
      "File encryption IV must be a Uint8Array."
    );
  }

  if (iv.length !== IV_LENGTH) {
    throw new Error(
      "File encryption IV must be exactly 12 bytes."
    );
  }

  const fileKey =
    await importFileEncryptionKey(fek);

  let plaintext;

  try {
    plaintext =
      await crypto.subtle.decrypt(
        {
          name: AES_ALGORITHM,
          iv,
        },
        fileKey,
        encryptedData
      );
  } catch {
    throw new Error(
      "File decryption failed. The key, IV, or ciphertext may be invalid or corrupted."
    );
  }

  return new Uint8Array(plaintext);
}
