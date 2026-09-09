import {
  bytesToBase64,
  base64ToBytes,
  generateIV,
} from "./crypto.js";

const AES_ALGORITHM = "AES-GCM";
const HKDF_ALGORITHM = "HKDF";

const METADATA_KEY_LENGTH = 32;
const MASTER_KEY_LENGTH = 32;
const IV_LENGTH = 12;

const METADATA_KEY_WRAPPING_INFO =
  new TextEncoder().encode(
    "QSZKFSS-V1-METADATA-KEY-WRAPPING"
  );

/**
 * Generate a fresh random 256-bit metadata key.
 *
 * This key is separate from the File Encryption Key.
 */
export function generateMetadataKey() {
  return crypto.getRandomValues(
    new Uint8Array(METADATA_KEY_LENGTH)
  );
}

/**
 * Import a raw metadata key as an AES-256-GCM CryptoKey.
 */
async function importMetadataKey(
  metadataKey
) {
  if (
    !(metadataKey instanceof Uint8Array)
  ) {
    throw new Error(
      "Metadata Key must be a Uint8Array."
    );
  }

  if (
    metadataKey.length !==
    METADATA_KEY_LENGTH
  ) {
    throw new Error(
      "Metadata Key must be exactly 32 bytes."
    );
  }

  return crypto.subtle.importKey(
    "raw",
    metadataKey,
    {
      name: AES_ALGORITHM,
    },
    false,
    ["encrypt", "decrypt"]
  );
}

/**
 * Derive a dedicated AES-256-GCM wrapping key
 * from the Master Key using HKDF-SHA-256.
 *
 * This provides cryptographic key separation:
 *
 * Master Key
 *     ↓
 *   HKDF
 *     ↓
 * Metadata Key Wrapping Key
 */
async function deriveMetadataKeyWrappingKey(
  masterKey
) {
  if (
    !(masterKey instanceof Uint8Array)
  ) {
    throw new Error(
      "Master Key must be a Uint8Array."
    );
  }

  if (
    masterKey.length !==
    MASTER_KEY_LENGTH
  ) {
    throw new Error(
      "Master Key must be exactly 32 bytes."
    );
  }

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

  return crypto.subtle.deriveKey(
    {
      name: HKDF_ALGORITHM,
      hash: "SHA-256",
      salt: new Uint8Array(32),
      info:
        METADATA_KEY_WRAPPING_INFO,
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
 * Encrypt sensitive file metadata.
 *
 * Metadata should contain information such as:
 *
 * {
 *   name,
 *   type,
 *   size
 * }
 *
 * The metadata is serialized to UTF-8 JSON before
 * AES-256-GCM encryption.
 */
export async function encryptMetadata(
  metadata
) {
  if (
    metadata === null ||
    typeof metadata !== "object"
  ) {
    throw new Error(
      "Metadata must be an object."
    );
  }

  const metadataKey =
    generateMetadataKey();

  const cryptoKey =
    await importMetadataKey(
      metadataKey
    );

  const iv = generateIV();

  const plaintext =
    new TextEncoder().encode(
      JSON.stringify(metadata)
    );

  const encrypted =
    await crypto.subtle.encrypt(
      {
        name: AES_ALGORITHM,
        iv,
      },
      cryptoKey,
      plaintext
    );

  return {
    metadataKey,

    encryptedMetadata:
      bytesToBase64(
        new Uint8Array(encrypted)
      ),

    metadataIV:
      bytesToBase64(iv),
  };
}

/**
 * Wrap the metadata key using a dedicated key
 * derived from the user's Master Key.
 */
export async function wrapMetadataKey(
  masterKey,
  metadataKey
) {
  if (
    !(metadataKey instanceof Uint8Array)
  ) {
    throw new Error(
      "Metadata Key must be a Uint8Array."
    );
  }

  if (
    metadataKey.length !==
    METADATA_KEY_LENGTH
  ) {
    throw new Error(
      "Metadata Key must be exactly 32 bytes."
    );
  }

  const wrappingKey =
    await deriveMetadataKeyWrappingKey(
      masterKey
    );

  const iv = generateIV();

  const wrapped =
    await crypto.subtle.encrypt(
      {
        name: AES_ALGORITHM,
        iv,
      },
      wrappingKey,
      metadataKey
    );

  return {
    wrappedMetadataKey:
      bytesToBase64(
        new Uint8Array(wrapped)
      ),

    metadataKeyIV:
      bytesToBase64(iv),
  };
}

/**
 * Unwrap the metadata key using the Master Key.
 *
 * Used later during file retrieval.
 */
export async function unwrapMetadataKey(
  masterKey,
  wrappedMetadataKey,
  metadataKeyIV
) {
  if (
    !(masterKey instanceof Uint8Array)
  ) {
    throw new Error(
      "Master Key must be a Uint8Array."
    );
  }

  if (
    masterKey.length !==
    MASTER_KEY_LENGTH
  ) {
    throw new Error(
      "Master Key must be exactly 32 bytes."
    );
  }

  if (
    typeof wrappedMetadataKey !==
      "string" ||
    wrappedMetadataKey.length === 0
  ) {
    throw new Error(
      "Wrapped Metadata Key is required."
    );
  }

  if (
    typeof metadataKeyIV !==
      "string" ||
    metadataKeyIV.length === 0
  ) {
    throw new Error(
      "Metadata Key IV is required."
    );
  }

  const iv =
    base64ToBytes(
      metadataKeyIV
    );

  if (iv.length !== IV_LENGTH) {
    throw new Error(
      "Metadata Key IV must be exactly 12 bytes."
    );
  }

  const ciphertext =
    base64ToBytes(
      wrappedMetadataKey
    );

  const wrappingKey =
    await deriveMetadataKeyWrappingKey(
      masterKey
    );

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

    const metadataKey =
      new Uint8Array(plaintext);

    if (
      metadataKey.length !==
      METADATA_KEY_LENGTH
    ) {
      throw new Error(
        "Recovered Metadata Key must be exactly 32 bytes."
      );
    }

    return metadataKey;
  } catch {
    throw new Error(
      "Unable to unwrap Metadata Key."
    );
  }
}

/**
 * Decrypt metadata using the recovered
 * Metadata Key.
 *
 * Used later during file retrieval.
 */
export async function decryptMetadata(
  encryptedMetadata,
  metadataKey,
  metadataIV
) {
  if (
    typeof encryptedMetadata !==
      "string" ||
    encryptedMetadata.length === 0
  ) {
    throw new Error(
      "Encrypted metadata is required."
    );
  }

  if (
    !(metadataKey instanceof Uint8Array)
  ) {
    throw new Error(
      "Metadata Key must be a Uint8Array."
    );
  }

  if (
    metadataKey.length !==
    METADATA_KEY_LENGTH
  ) {
    throw new Error(
      "Metadata Key must be exactly 32 bytes."
    );
  }

  const iv =
    base64ToBytes(
      metadataIV
    );

  if (iv.length !== IV_LENGTH) {
    throw new Error(
      "Metadata IV must be exactly 12 bytes."
    );
  }

  const ciphertext =
    base64ToBytes(
      encryptedMetadata
    );

  const cryptoKey =
    await importMetadataKey(
      metadataKey
    );

  try {
    const plaintext =
      await crypto.subtle.decrypt(
        {
          name: AES_ALGORITHM,
          iv,
        },
        cryptoKey,
        ciphertext
      );

    const metadataText =
      new TextDecoder().decode(
        plaintext
      );

    return JSON.parse(
      metadataText
    );
  } catch {
    throw new Error(
      "Metadata decryption failed."
    );
  }
}
