import { ObjectId } from "mongodb";

import { getDatabase } from "../config/db.js";

const FILES_COLLECTION = "files";

/**
 * Get the application's file metadata collection.
 *
 * IMPORTANT:
 * This collection does NOT contain plaintext file data.
 *
 * Actual encrypted file bytes are stored in GridFS.
 */
export function getFilesCollection() {
  return getDatabase().collection(
    FILES_COLLECTION
  );
}

/**
 * Create indexes required for file ownership
 * and retrieval.
 */
export async function ensureFileIndexes() {
  const files = getFilesCollection();

  await files.createIndex(
    { ownerId: 1, createdAt: -1 },
    {
      name: "owner_createdAt",
    }
  );

  await files.createIndex(
    { gridFsFileId: 1 },
    {
      unique: true,
      name: "gridFsFileId_unique",
    }
  );
}

/**
 * Create a file metadata document.
 *
 * The document contains ONLY protected cryptographic
 * material and operational metadata.
 *
 * The plaintext file itself is stored separately
 * in GridFS as ciphertext.
 */
export function createFileDocument({
  ownerId,

  // GridFS identifier for the encrypted file.
  gridFsFileId,

  // AES-256-GCM IV used for file encryption.
  // The IV is not secret, but is required for decryption.
  fileIV,

  // Encrypted metadata.
  encryptedMetadata,

  // IV used to encrypt the metadata itself.
  metadataIV,

  // Metadata key protected by the Master Key.
  wrappedMetadataKey,

  // IV used to wrap the metadata key.
  metadataKeyIV,

  // Owner's protected FEK.
  wrappedOwnerFEK,
  ownerFEKIV,

  // Cryptographic version.
  keyVersion,
}) {
  if (!ownerId) {
    throw new Error(
      "Owner ID is required."
    );
  }

  if (!gridFsFileId) {
    throw new Error(
      "GridFS file ID is required."
    );
  }

  if (
    typeof fileIV !== "string" ||
    fileIV.length === 0
  ) {
    throw new Error(
      "File IV is required."
    );
  }

  if (
    typeof encryptedMetadata !== "string" ||
    encryptedMetadata.length === 0
  ) {
    throw new Error(
      "Encrypted metadata is required."
    );
  }

  if (
    typeof metadataIV !== "string" ||
    metadataIV.length === 0
  ) {
    throw new Error(
      "Metadata IV is required."
    );
  }

  if (
    typeof wrappedMetadataKey !== "string" ||
    wrappedMetadataKey.length === 0
  ) {
    throw new Error(
      "Wrapped metadata key is required."
    );
  }

  if (
    typeof metadataKeyIV !== "string" ||
    metadataKeyIV.length === 0
  ) {
    throw new Error(
      "Metadata key IV is required."
    );
  }

  if (
    typeof wrappedOwnerFEK !== "string" ||
    wrappedOwnerFEK.length === 0
  ) {
    throw new Error(
      "Wrapped owner FEK is required."
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

  return {
    ownerId:
      new ObjectId(ownerId),

    gridFsFileId:
      new ObjectId(gridFsFileId),

    /*
     * AES-GCM file encryption IV.
     */
    fileIV,

    /*
     * Encrypted sensitive file metadata.
     */
    encryptedMetadata,

    /*
     * AES-GCM IV used for metadata encryption.
     */
    metadataIV,

    /*
     * Metadata Key encrypted using the
     * Master-Key-derived wrapping key.
     */
    wrappedMetadataKey,

    /*
     * AES-GCM IV used when wrapping
     * the Metadata Key.
     */
    metadataKeyIV,

    /*
     * The FEK itself is NEVER stored.
     *
     * Only the Master-Key-protected FEK is stored.
     */
    wrappedOwnerFEK,
    ownerFEKIV,

    keyVersion:
      Number.isInteger(keyVersion)
        ? keyVersion
        : 1,

    createdAt:
      new Date(),
  };
}

/**
 * Insert a new file record.
 */
export async function insertFile(
  fileDocument
) {
  const files =
    getFilesCollection();

  return files.insertOne(
    fileDocument
  );
}

/**
 * Find a file belonging to a specific owner.
 *
 * Ownership is checked directly in the database query
 * rather than trusting only the client.
 */
export async function findFileByIdForOwner(
  fileId,
  ownerId
) {
  let fileObjectId;
  let ownerObjectId;

  try {
    fileObjectId =
      new ObjectId(fileId);

    ownerObjectId =
      new ObjectId(ownerId);
  } catch {
    return null;
  }

  return getFilesCollection().findOne({
    _id: fileObjectId,
    ownerId: ownerObjectId,
  });
}

/**
 * Find a file by its MongoDB ID.
 *
 * Used later for access checks involving
 * shared files.
 */
export async function findFileById(
  fileId
) {
  let objectId;

  try {
    objectId =
      new ObjectId(fileId);
  } catch {
    return null;
  }

  return getFilesCollection().findOne({
    _id: objectId,
  });
}

/**
 * List files belonging to an owner.
 *
 * This returns encrypted/protected metadata only.
 */
export async function findFilesByOwner(
  ownerId
) {
  let ownerObjectId;

  try {
    ownerObjectId =
      new ObjectId(ownerId);
  } catch {
    return [];
  }

  return getFilesCollection()
    .find({
      ownerId: ownerObjectId,
    })
    .sort({
      createdAt: -1,
    })
    .toArray();
}

/**
 * Find the protected key material required by the owner
 * to create a share. No ciphertext or plaintext metadata
 * is returned by this helper.
 */
export async function findFileKeyMaterialForOwner(
  fileId,
  ownerId
) {
  const file = await findFileByIdForOwner(fileId, ownerId);

  if (!file) {
    return null;
  }

  return {
    id: file._id,
    wrappedOwnerFEK: file.wrappedOwnerFEK,
    ownerFEKIV: file.ownerFEKIV,
    wrappedMetadataKey: file.wrappedMetadataKey,
    metadataKeyIV: file.metadataKeyIV,
    keyVersion: file.keyVersion,
  };
}


/**
 * Delete a file metadata record.
 */
export async function deleteFileByIdForOwner(
  fileId,
  ownerId
) {
  let fileObjectId;
  let ownerObjectId;

  try {
    fileObjectId =
      new ObjectId(fileId);

    ownerObjectId =
      new ObjectId(ownerId);
  } catch {
    return {
      deletedCount: 0,
    };
  }

  return getFilesCollection().deleteOne({
    _id: fileObjectId,
    ownerId: ownerObjectId,
  });
}
