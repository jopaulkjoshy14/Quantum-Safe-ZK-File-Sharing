import { Readable } from "node:stream";

import { getGridFSBucket } from "../config/gridfs.js";

import {
  createFileDocument,
  insertFile,
  findFileByIdForOwner,
  findFilesByOwner,
} from "../models/file.js";

/**
 * Maximum encrypted file size for V1.
 */
const MAX_FILE_SIZE =
  100 * 1024 * 1024; // 100 MB

/**
 * Validate a Base64 string.
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
 * The browser performs all cryptographic operations.
 *
 * Server responsibility:
 * - receive ciphertext
 * - store ciphertext in GridFS
 * - store protected metadata/key material
 *
 * The server never receives the plaintext file or
 * plaintext File Encryption Key.
 */
export async function uploadFile(
  req,
  res
) {
  let gridFsFileId = null;

  try {
    const {
      ownerId,
      encryptedData,
      fileIV,
      encryptedMetadata,
      metadataIV,
      wrappedMetadataKey,
      metadataKeyIV,
      wrappedOwnerFEK,
      ownerFEKIV,
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
     */
    if (
      encryptedBuffer.length < 16
    ) {
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

    /*
     * ----------------------------------------------------
     * Validate wrapped metadata key
     * ----------------------------------------------------
     */
    validateBase64(
      wrappedMetadataKey,
      "Wrapped metadata key"
    );

    validateIV(
      metadataKeyIV,
      "Metadata key IV"
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

    const readable =
      Readable.from(
        [encryptedBuffer]
      );

    await new Promise(
      (resolve, reject) => {
        readable
          .pipe(uploadStream)
          .on(
            "finish",
            resolve
          )
          .on(
            "error",
            reject
          );

        readable.on(
          "error",
          reject
        );
      }
    );

    /*
     * ----------------------------------------------------
     * Create database record
     * ----------------------------------------------------
     */
    const fileDocument =
      createFileDocument({
        ownerId,

        gridFsFileId:
          gridFsFileId.toString(),

        fileIV,

        encryptedMetadata,
        metadataIV,

        wrappedMetadataKey,
        metadataKeyIV,

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
     */
    return res.status(201).json({
      ok: true,

      message:
        "Encrypted file uploaded successfully.",

      file: {
        id:
          result.insertedId,

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

/**
 * List encrypted files belonging to an owner.
 *
 * IMPORTANT:
 * The server does not decrypt metadata.
 *
 * Therefore the response intentionally does NOT
 * contain the plaintext filename, MIME type, or size.
 *
 * Those values remain inside encryptedMetadata and
 * will be decrypted by the browser later.
 *
 * TEMPORARY V1:
 * ownerId currently comes from the request query.
 *
 * This MUST be replaced with authenticated
 * server-side identity before production use.
 */
export async function listFiles(
  req,
  res
) {
  try {
    const {
      ownerId,
    } = req.query;

    /*
     * ----------------------------------------------------
     * Validate owner
     * ----------------------------------------------------
     */
    if (
      typeof ownerId !== "string" ||
      ownerId.length === 0
    ) {
      return res.status(400).json({
        ok: false,

        message:
          "Owner ID is required.",
      });
    }

    /*
     * ----------------------------------------------------
     * Find files belonging to owner
     * ----------------------------------------------------
     */
    const files =
      await findFilesByOwner(
        ownerId
      );

    /*
     * ----------------------------------------------------
     * Return only non-sensitive file references
     * ----------------------------------------------------
     *
     * Plaintext metadata is deliberately excluded.
     */
    const result =
      files.map(
        (file) => ({
          id:
            file._id,

          gridFsFileId:
            file.gridFsFileId,

          keyVersion:
            file.keyVersion,

          createdAt:
            file.createdAt,
        })
      );

    return res.status(200).json({
      ok: true,

      files:
        result,
    });
  } catch (error) {
    console.error(
      "Encrypted file listing error:",
      error
    );

    return res.status(500).json({
      ok: false,

      message:
        "Unable to retrieve encrypted file list.",
    });
  }
}

/**
 * Retrieve an encrypted file.
 *
 * IMPORTANT:
 * The server performs NO decryption.
 *
 * It:
 * 1. verifies that the requested file belongs
 *    to the supplied ownerId
 * 2. retrieves the ciphertext from GridFS
 * 3. returns the ciphertext and protected
 *    cryptographic material to the browser
 *
 * TEMPORARY V1:
 * ownerId currently comes from the request.
 *
 * This MUST be replaced with authenticated
 * server-side identity before production use.
 */
export async function downloadFile(
  req,
  res
) {
  try {
    const {
      fileId,
    } = req.params;

    const {
      ownerId,
    } = req.query;

    /*
     * ----------------------------------------------------
     * Validate request
     * ----------------------------------------------------
     */
    if (
      typeof fileId !== "string" ||
      fileId.length === 0
    ) {
      return res.status(400).json({
        ok: false,

        message:
          "File ID is required.",
      });
    }

    if (
      typeof ownerId !== "string" ||
      ownerId.length === 0
    ) {
      return res.status(400).json({
        ok: false,

        message:
          "Owner ID is required.",
      });
    }

    /*
     * ----------------------------------------------------
     * Find file owned by requester
     * ----------------------------------------------------
     */
    const file =
      await findFileByIdForOwner(
        fileId,
        ownerId
      );

    if (!file) {
      return res.status(404).json({
        ok: false,

        message:
          "File not found.",
      });
    }

    /*
     * ----------------------------------------------------
     * Validate GridFS ID
     * ----------------------------------------------------
     */
    if (
      !file.gridFsFileId
    ) {
      return res.status(500).json({
        ok: false,

        message:
          "Stored GridFS file reference is missing.",
      });
    }

    /*
     * ----------------------------------------------------
     * Read encrypted bytes from GridFS
     * ----------------------------------------------------
     *
     * These bytes are ciphertext.
     *
     * The backend does NOT possess the FEK needed
     * to decrypt them.
     */
    const bucket =
      getGridFSBucket();

    const downloadStream =
      bucket.openDownloadStream(
        file.gridFsFileId
      );

    const chunks = [];

    let totalSize = 0;

    await new Promise(
      (resolve, reject) => {
        downloadStream.on(
          "data",
          (chunk) => {
            totalSize +=
              chunk.length;

            /*
             * Defensive size check.
             */
            if (
              totalSize >
              MAX_FILE_SIZE + 16
            ) {
              downloadStream.destroy(
                new Error(
                  "Stored encrypted file exceeds the V1 size limit."
                )
              );

              return;
            }

            chunks.push(chunk);
          }
        );

        downloadStream.on(
          "end",
          resolve
        );

        downloadStream.on(
          "error",
          reject
        );
      }
    );

    if (
      totalSize < 16
    ) {
      return res.status(500).json({
        ok: false,

        message:
          "Stored encrypted file is invalid.",
      });
    }

    const encryptedBuffer =
      Buffer.concat(
        chunks
      );

    /*
     * ----------------------------------------------------
     * Convert ciphertext to Base64
     * ----------------------------------------------------
     *
     * This is V1's simple JSON transport format.
     *
     * No plaintext is generated here.
     */
    const encryptedData =
      encryptedBuffer.toString(
        "base64"
      );

    /*
     * ----------------------------------------------------
     * Return encrypted file package
     * ----------------------------------------------------
     */
    return res.status(200).json({
      ok: true,

      message:
        "Encrypted file retrieved successfully.",

      file: {
        id:
          file._id,

        gridFsFileId:
          file.gridFsFileId,

        encryptedData,

        fileIV:
          file.fileIV,

        encryptedMetadata:
          file.encryptedMetadata,

        metadataIV:
          file.metadataIV,

        wrappedMetadataKey:
          file.wrappedMetadataKey,

        metadataKeyIV:
          file.metadataKeyIV,

        wrappedOwnerFEK:
          file.wrappedOwnerFEK,

        ownerFEKIV:
          file.ownerFEKIV,

        keyVersion:
          file.keyVersion,

        createdAt:
          file.createdAt,
      },
    });
  } catch (error) {
    console.error(
      "Encrypted file retrieval error:",
      error
    );

    return res.status(500).json({
      ok: false,

      message:
        "Encrypted file retrieval failed.",
    });
  }
}
