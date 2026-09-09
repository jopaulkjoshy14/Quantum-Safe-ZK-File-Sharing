import { Readable } from "node:stream";

import { getGridFSBucket } from "../config/gridfs.js";

import {
  createFileDocument,
  insertFile,
} from "../models/file.js";

/**
 * Maximum encrypted file size for V1.
 *
 * This is intentionally conservative for the first
 * implementation. It can be increased later if needed.
 */
const MAX_FILE_SIZE = 100 * 1024 * 1024; // 100 MB

/**
 * Validate a Base64 string.
 *
 * The frontend sends encrypted binary data as Base64
 * because the current API uses JSON.
 */
function validateBase64(
  value,
  fieldName
) {
  if (
    typeof value !== "string" ||
    value.length === 0
  ) {
    throw new Error(
      `${fieldName} is required.`
    );
  }

  /*
   * Base64 characters may contain:
   * A-Z, a-z, 0-9, +, / and optional =
   */
  if (
    !/^[A-Za-z0-9+/]*={0,2}$/.test(value)
  ) {
    throw new Error(
      `${fieldName} contains invalid Base64 data.`
    );
  }

  return value;
}

/**
 * Decode Base64 into a Buffer.
 */
function base64ToBuffer(
  value,
  fieldName
) {
  validateBase64(
    value,
    fieldName
  );

  const buffer =
    Buffer.from(value, "base64");

  if (buffer.length === 0) {
    throw new Error(
      `${fieldName} contains no data.`
    );
  }

  return buffer;
}

/**
 * Validate a 12-byte AES-GCM IV.
 */
function validateIV(
  value,
  fieldName
) {
  const buffer =
    base64ToBuffer(
      value,
      fieldName
    );

  if (buffer.length !== 12) {
    throw new Error(
      `${fieldName} must contain exactly 12 bytes.`
    );
  }

  return buffer;
}

/**
 * Upload an already-encrypted file.
 *
 * IMPORTANT:
 *
 * The server does NOT:
 * - receive the plaintext file
 * - generate the FEK
 * - decrypt the file
 * - unwrap the FEK
 * - perform AES encryption
 *
 * The browser performs all cryptographic operations.
 *
 * Server responsibility:
 * - receive ciphertext
 * - store ciphertext in GridFS
 * - store protected metadata/key material
 */
export async function uploadFile(
  req,
  res
) {
  let gridFsFileId = null;

  try {
    const {
      ownerId,

      /*
       * AES-256-GCM encrypted file.
       */
      encryptedData,

      /*
       * IV used for file encryption.
       */
      fileIV,

      /*
       * Encrypted metadata.
       */
      encryptedMetadata,
      metadataIV,
      wrappedMetadataKey,

      /*
       * Owner FEK protected using:
       *
       * Master Key
       *     ↓
       * HKDF
       *     ↓
       * Owner FEK-Wrapping Key
       *     ↓
       * AES-GCM
       *     ↓
       * wrappedOwnerFEK
       */
      wrappedOwnerFEK,
      ownerFEKIV,

      /*
       * Cryptographic version.
       */
      keyVersion,
    } = req.body;

    /*
     * ----------------------------------------------------
     * Validate owner
     * ----------------------------------------------------
     *
     * TEMPORARY V1:
     *
     * Authentication middleware has not yet been added,
     * so ownerId is supplied by the frontend.
     *
     * Before production use, this MUST come from the
     * authenticated server-side identity instead.
     */
    if (
      typeof ownerId !== "string" ||
      ownerId.length === 0
    ) {
      throw new Error(
        "Owner ID is required."
      );
    }

    /*
     * ----------------------------------------------------
     * Decode encrypted file
     * ----------------------------------------------------
     */
    const encryptedBuffer =
      base64ToBuffer(
        encryptedData,
        "Encrypted file"
      );

    /*
     * AES-GCM adds a 16-byte authentication tag.
     *
     * Therefore even an empty plaintext produces
     * at least a 16-byte encrypted result.
     */
    if (encryptedBuffer.length < 16) {
      throw new Error(
        "Encrypted file data is invalid."
      );
    }

    if (
      encryptedBuffer.length >
      MAX_FILE_SIZE + 16
    ) {
      throw new Error(
        "Encrypted file exceeds the V1 size limit of 100 MB."
      );
    }

    /*
     * ----------------------------------------------------
     * Validate file IV
     * ----------------------------------------------------
     */
    validateIV(
      fileIV,
      "File encryption IV"
    );

    /*
     * ----------------------------------------------------
     * Validate encrypted metadata
     * ----------------------------------------------------
     */
    validateBase64(
      encryptedMetadata,
      "Encrypted metadata"
    );

    validateIV(
      metadataIV,
      "Metadata IV"
    );

    validateBase64(
      wrappedMetadataKey,
      "Wrapped metadata key"
    );

    /*
     * ----------------------------------------------------
     * Validate wrapped owner FEK
     * ----------------------------------------------------
     */
    validateBase64(
      wrappedOwnerFEK,
      "Wrapped owner FEK"
    );

    validateIV(
      ownerFEKIV,
      "Owner FEK IV"
    );

    /*
     * ----------------------------------------------------
     * Validate key version
     * ----------------------------------------------------
     */
    const normalizedKeyVersion =
      Number.isInteger(keyVersion)
        ? keyVersion
        : 1;

    if (
      normalizedKeyVersion < 1
    ) {
      throw new Error(
        "Invalid cryptographic key version."
      );
    }

    /*
     * ----------------------------------------------------
     * Store encrypted bytes in GridFS
     * ----------------------------------------------------
     *
     * The bytes written here are ciphertext.
     *
     * GridFS never receives the original plaintext file.
     */
    const bucket =
      getGridFSBucket();

    const uploadStream =
      bucket.openUploadStream(
        `encrypted-${Date.now()}`,
        {
          metadata: {
            encrypted: true,
            keyVersion:
              normalizedKeyVersion,
          },
        }
      );

    gridFsFileId =
      uploadStream.id;

    /*
     * Convert the encrypted Buffer into
     * a readable stream.
     */
    const readable =
      Readable.from(
        [encryptedBuffer]
      );

    /*
     * Pipe ciphertext into GridFS.
     */
    await new Promise(
      (resolve, reject) => {
        readable
          .pipe(uploadStream)
          .on("finish", resolve)
          .on("error", reject);

        readable.on(
          "error",
          reject
        );
      }
    );

    /*
     * ----------------------------------------------------
     * Create the corresponding database record
     * ----------------------------------------------------
     */
    const fileDocument =
      createFileDocument({
        ownerId,

        gridFsFileId:
          gridFsFileId.toString(),

        encryptedMetadata,
        metadataIV,
        wrappedMetadataKey,

        wrappedOwnerFEK,
        ownerFEKIV,

        keyVersion:
          normalizedKeyVersion,
      });

    const result =
      await insertFile(
        fileDocument
      );

    /*
     * ----------------------------------------------------
     * Success
     * ----------------------------------------------------
     *
     * Do NOT return plaintext file information.
     *
     * The frontend receives identifiers required
     * for future retrieval.
     */
    return res.status(201).json({
      ok: true,
      message:
        "Encrypted file uploaded successfully.",

      file: {
        id: result.insertedId,
        gridFsFileId,
        keyVersion:
          normalizedKeyVersion,
      },
    });
  } catch (error) {
    console.error(
      "Encrypted file upload error:",
      error
    );

    /*
     * ----------------------------------------------------
     * Cleanup
     * ----------------------------------------------------
     *
     * If GridFS upload succeeded but creating the
     * metadata record failed, remove the orphaned
     * encrypted object.
     */
    if (gridFsFileId) {
      try {
        const bucket =
          getGridFSBucket();

        await bucket.delete(
          gridFsFileId
        );
      } catch (cleanupError) {
        console.error(
          "Failed to clean up orphaned GridFS file:",
          cleanupError
        );
      }
    }

    return res.status(400).json({
      ok: false,
      message:
        error.message ||
        "Encrypted file upload failed.",
    });
  }
}
