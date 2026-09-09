import {
  bytesToBase64,
  base64ToBytes,
  generateIV,
} from "./crypto.js";

const AES_ALGORITHM = "AES-GCM";
const HKDF_ALGORITHM = "HKDF";

const MASTER_KEY_LENGTH = 32;
const FEK_LENGTH = 32;
const IV_LENGTH = 12;
const WRAPPING_KEY_LENGTH = 32;

/*
 * Domain separation label.
 *
 * This ensures the key derived here is specifically
 * intended for wrapping File Encryption Keys.
 */
const FEK_WRAPPING_INFO = new TextEncoder().encode(
  "QSZKFSS-V1-FEK-WRAPPING-KEY"
);

/**
 * Derive a dedicated FEK-Wrapping Key from the
 * user's Master Key.
 *
 * Master Key
 *     ↓
 * HKDF-SHA-256
 *     ↓
 * Owner FEK-Wrapping Key
 *
 * IMPORTANT:
 * The Master Key is NOT used directly to encrypt FEKs.
 */
export async function deriveOwnerFEKWrappingKey(
  masterKey
) {
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

  /*
   * Import Master Key as HKDF key material.
   */
  const masterKeyMaterial =
    await crypto.subtle.importKey(
      "raw",
      masterKey,
      {
        name: HKDF_ALGORITHM,
      },
      false,
      ["deriveKey"]
    );

  /*
   * HKDF with:
   * - SHA-256
   * - empty salt
   * - domain-separated info
   *
   * The dedicated wrapping key is 256 bits.
   */
  return crypto.subtle.deriveKey(
    {
      name: HKDF_ALGORITHM,
      hash: "SHA-256",
      salt: new Uint8Array(32),
      info: FEK_WRAPPING_INFO,
    },
    masterKeyMaterial,
    {
      name: AES_ALGORITHM,
      length: 256,
    },
    false,
    ["encrypt", "decrypt"]
  );
}

/**
 * Wrap a File Encryption Key (FEK) using the
 * dedicated Owner FEK-Wrapping Key.
 *
 * FEK
 *  ↓
 * AES-256-GCM
 *  ↓
 * Wrapped FEK
 *
 * The plaintext FEK remains in browser memory.
 */
export async function wrapOwnerFEK(
  masterKey,
  fek
) {
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

  const wrappingKey =
    await deriveOwnerFEKWrappingKey(
      masterKey
    );

  const iv = generateIV();

  const wrappedFEK =
    await crypto.subtle.encrypt(
      {
        name: AES_ALGORITHM,
        iv,
      },
      wrappingKey,
      fek
    );

  return {
    wrappedFEK: bytesToBase64(
      new Uint8Array(wrappedFEK)
    ),

    ownerFEKIV: bytesToBase64(iv),
  };
}

/**
 * Unwrap the owner's FEK.
 *
 * Wrapped FEK
 *     ↓
 * AES-256-GCM
 *     ↓
 * FEK
 *
 * Used when the owner wants to decrypt
 * their own file.
 */
export async function unwrapOwnerFEK(
  masterKey,
  wrappedFEK,
  ownerFEKIV
) {
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
    typeof wrappedFEK !== "string" ||
    wrappedFEK.length === 0
  ) {
    throw new Error(
      "Wrapped FEK is required."
    );
  }

  if (
    typeof ownerFEKIV !== "string" ||
    ownerFEKIV.length === 0
  ) {
    throw new Error(
      "Owner FEK IV is required."
    );
  }

  const iv = base64ToBytes(ownerFEKIV);
  const ciphertext =
    base64ToBytes(wrappedFEK);

  if (iv.length !== IV_LENGTH) {
    throw new Error(
      "Owner FEK IV must be exactly 12 bytes."
    );
  }

  const wrappingKey =
    await deriveOwnerFEKWrappingKey(
      masterKey
    );

  let fek;

  try {
    const plaintext =
      await crypto.subtle.decrypt(
        {
          name: AES_ALGORITHM,
          iv,
        },
        wrappingKey,
        ciphertext
      );

    fek = new Uint8Array(plaintext);
  } catch {
    throw new Error(
      "Unable to unwrap File Encryption Key."
    );
  }

  if (fek.length !== FEK_LENGTH) {
    throw new Error(
      "Recovered File Encryption Key must be exactly 32 bytes."
    );
  }

  return fek;
}
