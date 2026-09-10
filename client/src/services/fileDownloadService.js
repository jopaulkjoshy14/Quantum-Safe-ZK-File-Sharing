import {
  base64ToBytes,
} from "../crypto/crypto.js";

import {
  decryptFile,
} from "../crypto/fileCrypto.js";

import {
  unwrapMetadataKey,
  decryptMetadata,
} from "../crypto/metadataCrypto.js";

import {
  unwrapOwnerFEK,
} from "../crypto/keyWrapping.js";

/**
 * Retrieve and decrypt an encrypted file.
 *
 * IMPORTANT:
 *
 * The server returns only:
 * - encrypted file ciphertext
 * - encrypted metadata
 * - protected key material
 * - non-secret IVs
 *
 * All decryption happens inside the browser.
 *
 * Required inputs:
 *
 * {
 *   fileId,
 *   authToken,
 *   masterKey,
 *   apiBaseUrl
 * }
 *
 * Returns:
 *
 * {
 *   fileId,
 *   plaintext,
 *   metadata
 * }
 */
export async function downloadAndDecryptFile({
  fileId,
  authToken,
  masterKey,
  apiBaseUrl,
  onProgress,
}) {
  /*
   * ----------------------------------------------------
   * Validate inputs
   * ----------------------------------------------------
   */

  if (
    typeof fileId !== "string" ||
    fileId.length === 0
  ) {
    throw new Error(
      "File ID is required."
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
   * Retrieve encrypted file package
   * ----------------------------------------------------
   *
   * The authentication token identifies the requester.
   *
   * The server independently determines ownership
   * from the authenticated identity.
   */
  onProgress?.({ id: "auth" });
  const response =
    await fetch(
      `${apiBaseUrl}/files/${encodeURIComponent(
        fileId
      )}/download`,
      {
        method: "GET",

        headers: {
          Authorization:
            `Bearer ${authToken}`,
        },
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
      "Encrypted file retrieval failed."
    );
  }

  if (
    !result ||
    result.ok !== true ||
    !result.file
  ) {
    throw new Error(
      "The server returned an invalid encrypted file package."
    );
  }

  const encryptedFile =
    result.file;

  /*
   * ----------------------------------------------------
   * Validate encrypted package
   * ----------------------------------------------------
   */

  if (
    typeof encryptedFile.encryptedData !==
      "string" ||
    encryptedFile.encryptedData.length === 0
  ) {
    throw new Error(
      "Encrypted file ciphertext is missing."
    );
  }

  if (
    typeof encryptedFile.fileIV !==
      "string" ||
    encryptedFile.fileIV.length === 0
  ) {
    throw new Error(
      "File encryption IV is missing."
    );
  }

  if (
    typeof encryptedFile.encryptedMetadata !==
      "string" ||
    encryptedFile.encryptedMetadata.length === 0
  ) {
    throw new Error(
      "Encrypted metadata is missing."
    );
  }

  if (
    typeof encryptedFile.metadataIV !==
      "string" ||
    encryptedFile.metadataIV.length === 0
  ) {
    throw new Error(
      "Metadata IV is missing."
    );
  }

  if (
    typeof encryptedFile.wrappedMetadataKey !==
      "string" ||
    encryptedFile.wrappedMetadataKey.length === 0
  ) {
    throw new Error(
      "Wrapped metadata key is missing."
    );
  }

  if (
    typeof encryptedFile.metadataKeyIV !==
      "string" ||
    encryptedFile.metadataKeyIV.length === 0
  ) {
    throw new Error(
      "Metadata key IV is missing."
    );
  }

  if (
    typeof encryptedFile.wrappedOwnerFEK !==
      "string" ||
    encryptedFile.wrappedOwnerFEK.length === 0
  ) {
    throw new Error(
      "Wrapped owner FEK is missing."
    );
  }

  if (
    typeof encryptedFile.ownerFEKIV !==
      "string" ||
    encryptedFile.ownerFEKIV.length === 0
  ) {
    throw new Error(
      "Owner FEK IV is missing."
    );
  }

  /*
   * ----------------------------------------------------
   * Decode encrypted file ciphertext
   * ----------------------------------------------------
   */
  onProgress?.({ id: "retrieve" });

  let encryptedData;
  let fileIV;

  try {
    encryptedData =
      base64ToBytes(
        encryptedFile.encryptedData
      );

    fileIV =
      base64ToBytes(
        encryptedFile.fileIV
      );
  } catch {
    throw new Error(
      "Encrypted file transport data is invalid."
    );
  }

  onProgress?.({ id: "fek" });

  /*
   * ----------------------------------------------------
   * Recover owner's FEK
   * ----------------------------------------------------
   *
   * Master Key
   *     ↓
   * HKDF-SHA-256
   *     ↓
   * Owner FEK-Wrapping Key
   *     ↓
   * AES-256-GCM
   *     ↓
   * FEK
   */
  const fek =
    await unwrapOwnerFEK(
      masterKey,
      encryptedFile.wrappedOwnerFEK,
      encryptedFile.ownerFEKIV
    );

  /*
   * ----------------------------------------------------
   * Decrypt file
   * ----------------------------------------------------
   *
   * Ciphertext
   *     ↓
   * AES-256-GCM + FEK
   *     ↓
   * Plaintext bytes
   *
   * The plaintext exists only in browser memory
   * during this operation.
   */
  onProgress?.({ id: "decrypt" });

  const plaintext =
    await decryptFile(
      encryptedData,
      fek,
      fileIV
    );

  /*
   * ----------------------------------------------------
   * Recover metadata key
   * ----------------------------------------------------
   *
   * Master Key
   *     ↓
   * HKDF-SHA-256
   *     ↓
   * Metadata Key-Wrapping Key
   *     ↓
   * AES-256-GCM
   *     ↓
   * Metadata Key
   */
  onProgress?.({ id: "metadata" });

  const metadataKey =
    await unwrapMetadataKey(
      masterKey,
      encryptedFile.wrappedMetadataKey,
      encryptedFile.metadataKeyIV
    );

  /*
   * ----------------------------------------------------
   * Decrypt metadata
   * ----------------------------------------------------
   */
  onProgress?.({ id: "metadata-decrypt" });

  const metadata =
    await decryptMetadata(
      encryptedFile.encryptedMetadata,
      metadataKey,
      encryptedFile.metadataIV
    );

  /*
   * ----------------------------------------------------
   * Validate recovered metadata
   * ----------------------------------------------------
   */
  if (
    !metadata ||
    typeof metadata !== "object"
  ) {
    throw new Error(
      "Recovered file metadata is invalid."
    );
  }

  if (
    typeof metadata.name !== "string" ||
    metadata.name.length === 0
  ) {
    throw new Error(
      "Recovered filename is invalid."
    );
  }

  if (
    typeof metadata.type !== "string" ||
    metadata.type.length === 0
  ) {
    throw new Error(
      "Recovered file MIME type is invalid."
    );
  }

  if (
    !Number.isSafeInteger(metadata.size) ||
    metadata.size < 0
  ) {
    throw new Error(
      "Recovered file size is invalid."
    );
  }

  /*
   * ----------------------------------------------------
   * Return decrypted package
   * ----------------------------------------------------
   *
   * The caller is responsible for creating the
   * browser download.
   *
   * No decrypted data is persisted here.
   */
  onProgress?.({ id: "reconstruct" });

  return {
    fileId:
      encryptedFile.id,

    plaintext,

    metadata: {
      name:
        metadata.name,

      type:
        metadata.type,

      size:
        metadata.size,
    },

    keyVersion:
      encryptedFile.keyVersion,
  };
}
