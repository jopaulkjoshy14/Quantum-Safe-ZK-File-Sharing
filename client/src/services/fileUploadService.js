import {
  bytesToBase64,
} from "../crypto/crypto.js";

import {
  encryptFile,
} from "../crypto/fileCrypto.js";

import {
  encryptMetadata,
  wrapMetadataKey,
} from "../crypto/metadataCrypto.js";

import {
  wrapOwnerFEK,
} from "../crypto/keyWrapping.js";

/**
 * Upload an encrypted file.
 *
 * IMPORTANT:
 *
 * The plaintext file never gets sent to the backend.
 *
 * This function performs all required client-side
 * cryptographic operations before making the API request.
 *
 * Required inputs:
 *
 * {
 *   file,
 *   authToken,
 *   masterKey,
 *   apiBaseUrl
 * }
 */
export async function uploadEncryptedFile({
  file,
  authToken,
  masterKey,
  apiBaseUrl,
}) {
  if (!(file instanceof File)) {
    throw new Error(
      "A valid File object is required."
    );
  }

  if (
    typeof authToken !== "string" ||
    authToken.length === 0
  ) {
    throw new Error(
      "Authenticated session is required."
    );
  }

  if (
    !(masterKey instanceof Uint8Array)
  ) {
    throw new Error(
      "Master Key is required."
    );
  }

  if (masterKey.length !== 32) {
    throw new Error(
      "Master Key must be exactly 32 bytes."
    );
  }

  if (
    typeof apiBaseUrl !== "string" ||
    apiBaseUrl.length === 0
  ) {
    throw new Error(
      "API base URL is required."
    );
  }

  /*
   * ----------------------------------------------------
   * 1. Encrypt the actual file
   * ----------------------------------------------------
   *
   * A fresh random FEK is generated internally
   * by encryptFile().
   */
  const {
    encryptedData,
    fek,
    iv: fileIV,
  } = await encryptFile(file);

  /*
   * ----------------------------------------------------
   * 2. Encrypt file metadata
   * ----------------------------------------------------
   *
   * Metadata is intentionally kept separate from
   * the file encryption key.
   */
  const metadata = {
    name: file.name,
    type:
      file.type ||
      "application/octet-stream",
    size: file.size,
  };

  const {
    metadataKey,
    encryptedMetadata,
    metadataIV,
  } = await encryptMetadata(metadata);

  /*
   * ----------------------------------------------------
   * 3. Protect the Metadata Key
   * ----------------------------------------------------
   *
   * Master Key
   *     ↓
   * HKDF-SHA-256
   *     ↓
   * Metadata Key Wrapping Key
   *     ↓
   * AES-256-GCM
   *     ↓
   * wrappedMetadataKey
   */
  const {
    wrappedMetadataKey,
    metadataKeyIV,
  } = await wrapMetadataKey(
    masterKey,
    metadataKey
  );

  /*
   * ----------------------------------------------------
   * 4. Protect the owner's FEK
   * ----------------------------------------------------
   *
   * Master Key
   *     ↓
   * HKDF-SHA-256
   *     ↓
   * Owner FEK Wrapping Key
   *     ↓
   * AES-256-GCM
   *     ↓
   * wrappedOwnerFEK
   */
  const {
    wrappedFEK: wrappedOwnerFEK,
    ownerFEKIV,
  } = await wrapOwnerFEK(
    masterKey,
    fek
  );

  /*
   * ----------------------------------------------------
   * 5. Prepare API payload
   * ----------------------------------------------------
   *
   * IMPORTANT:
   *
   * ownerId is intentionally NOT included.
   *
   * The backend derives the authenticated owner
   * identity from the verified Bearer token.
   *
   * Binary values are converted to Base64 because
   * the current V1 endpoint accepts JSON.
   */
  const payload = {
    encryptedData:
      bytesToBase64(
        encryptedData
      ),

    fileIV:
      bytesToBase64(
        fileIV
      ),

    encryptedMetadata,

    metadataIV,

    wrappedMetadataKey,

    metadataKeyIV,

    wrappedOwnerFEK,

    ownerFEKIV,

    keyVersion: 1,
  };

  /*
   * ----------------------------------------------------
   * 6. Send ONLY encrypted/protected material
   * ----------------------------------------------------
   *
   * Authentication is supplied separately through
   * the Authorization header.
   */
  const response =
    await fetch(
      `${apiBaseUrl}/files/upload`,
      {
        method: "POST",

        headers: {
          "Content-Type":
            "application/json",

          Authorization:
            `Bearer ${authToken}`,
        },

        body:
          JSON.stringify(payload),
      }
    );

  let result;

  try {
    result =
      await response.json();
  } catch {
    throw new Error(
      "The server returned an invalid response."
    );
  }

  if (!response.ok) {
    throw new Error(
      result.message ||
      "Encrypted file upload failed."
    );
  }

  return {
    ...result,

    /*
     * Useful for debugging/testing.
     *
     * These values remain only in the current
     * browser runtime and are NOT sent back
     * to the server.
     */
    crypto: {
      encryptedFileSize:
        encryptedData.length,

      fileIVLength:
        fileIV.length,

      fekLength:
        fek.length,

      metadataKeyLength:
        metadataKey.length,

      metadataIVLength:
        metadataIV.length,

      metadataKeyIVLength:
        metadataKeyIV.length,
    },
  };
}
