import { GridFSBucket } from "mongodb";

import { getDatabase } from "./db.js";

const GRIDFS_BUCKET_NAME = "files";

let bucket;

/**
 * Get the application's GridFS bucket.
 *
 * IMPORTANT:
 * GridFS stores the encrypted file bytes received
 * from the browser.
 *
 * The backend must NEVER receive plaintext file data.
 */
export function getGridFSBucket() {
  if (bucket) {
    return bucket;
  }

  const database = getDatabase();

  bucket = new GridFSBucket(database, {
    bucketName: GRIDFS_BUCKET_NAME,
  });

  return bucket;
}

/**
 * Reset the cached GridFS bucket.
 *
 * Primarily useful when reconnecting or testing.
 */
export function resetGridFSBucket() {
  bucket = undefined;
}

export {
  GRIDFS_BUCKET_NAME,
};
