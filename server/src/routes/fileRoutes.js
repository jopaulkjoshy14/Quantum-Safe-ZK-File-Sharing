import express from "express";

import {
  uploadFile,
  listFiles,
  downloadFile,
} from "../controllers/fileController.js";

const router =
  express.Router();

/*
 * Upload encrypted file.
 */
router.post(
  "/upload",
  uploadFile
);

/*
 * List encrypted files belonging to
 * the requested owner.
 *
 * TEMPORARY V1:
 * ownerId comes from the query string.
 */
router.get(
  "/",
  listFiles
);

/*
 * Retrieve encrypted file ciphertext
 * and protected cryptographic material.
 *
 * TEMPORARY V1:
 * ownerId comes from the query string.
 */
router.get(
  "/:fileId/download",
  downloadFile
);

export default router;
