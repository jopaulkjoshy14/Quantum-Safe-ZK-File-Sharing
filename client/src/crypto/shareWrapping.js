import {
  base64ToBytes,
  bytesToBase64,
  generateIV,
} from "./crypto.js";

const AES_ALGORITHM = "AES-GCM";
const HKDF_ALGORITHM = "HKDF";
const KEY_LENGTH = 32;
const IV_LENGTH = 12;
const SHARE_WRAP_INFO_PREFIX =
  "QSZKFSS-V1-SHARED-KEY-WRAPPING";

function validateBytes(value, name, length) {
  if (!(value instanceof Uint8Array)) {
    throw new Error(`${name} must be a Uint8Array.`);
  }

  if (value.length !== length) {
    throw new Error(
      `${name} must be exactly ${length} bytes.`
    );
  }
}

function buildContext(fileId, senderId, recipientId) {
  if (
    typeof fileId !== "string" ||
    typeof senderId !== "string" ||
    typeof recipientId !== "string"
  ) {
    throw new Error("Invalid sharing context.");
  }

  return new TextEncoder().encode(
    `${SHARE_WRAP_INFO_PREFIX}:${fileId}:${senderId}:${recipientId}`
  );
}

/**
 * Derive a dedicated AES-256-GCM wrapping key from
 * the ML-KEM shared secret.
 *
 * ML-KEM shared secret
 *        ↓
 * HKDF-SHA-256 + domain/context
 *        ↓
 * Shared-key wrapping key
 */
export async function deriveShareWrappingKey(
  sharedSecret,
  fileId,
  senderId,
  recipientId
) {
  validateBytes(
    sharedSecret,
    "ML-KEM shared secret",
    KEY_LENGTH
  );

  const material = await crypto.subtle.importKey(
    "raw",
    sharedSecret,
    { name: HKDF_ALGORITHM },
    false,
    ["deriveKey"]
  );

  return crypto.subtle.deriveKey(
    {
      name: HKDF_ALGORITHM,
      hash: "SHA-256",
      salt: new Uint8Array(32),
      info: buildContext(
        fileId,
        senderId,
        recipientId
      ),
    },
    material,
    {
      name: AES_ALGORITHM,
      length: 256,
    },
    false,
    ["encrypt", "decrypt"]
  );
}

async function wrapKey(
  wrappingKey,
  keyBytes,
  name
) {
  validateBytes(
    keyBytes,
    name,
    KEY_LENGTH
  );

  const iv = generateIV();

  const ciphertext = await crypto.subtle.encrypt(
    {
      name: AES_ALGORITHM,
      iv,
    },
    wrappingKey,
    keyBytes
  );

  return {
    ciphertext: bytesToBase64(
      new Uint8Array(ciphertext)
    ),
    iv: bytesToBase64(iv),
  };
}

async function unwrapKey(
  wrappingKey,
  wrappedKey,
  ivBase64,
  name
) {
  if (
    typeof wrappedKey !== "string" ||
    wrappedKey.length === 0
  ) {
    throw new Error(`${name} is required.`);
  }

  if (
    typeof ivBase64 !== "string" ||
    ivBase64.length === 0
  ) {
    throw new Error(`${name} IV is required.`);
  }

  const iv = base64ToBytes(ivBase64);

  if (iv.length !== IV_LENGTH) {
    throw new Error(
      `${name} IV must be exactly 12 bytes.`
    );
  }

  const ciphertext =
    base64ToBytes(wrappedKey);

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

    const keyBytes =
      new Uint8Array(plaintext);

    validateBytes(
      keyBytes,
      name,
      KEY_LENGTH
    );

    return keyBytes;
  } catch {
    throw new Error(
      `Unable to unwrap ${name}.`
    );
  }
}

export async function wrapSharedFEK(
  wrappingKey,
  fek
) {
  return wrapKey(
    wrappingKey,
    fek,
    "Shared FEK"
  );
}

export async function unwrapSharedFEK(
  wrappingKey,
  wrappedFEK,
  wrapIV
) {
  return unwrapKey(
    wrappingKey,
    wrappedFEK,
    wrapIV,
    "Shared FEK"
  );
}

export async function wrapSharedMetadataKey(
  wrappingKey,
  metadataKey
) {
  return wrapKey(
    wrappingKey,
    metadataKey,
    "Shared metadata key"
  );
}

export async function unwrapSharedMetadataKey(
  wrappingKey,
  wrappedMetadataKey,
  metadataKeyIV
) {
  return unwrapKey(
    wrappingKey,
    wrappedMetadataKey,
    metadataKeyIV,
    "Shared metadata key"
  );
}
