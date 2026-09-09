import express from "express";

import {
  uploadFile,
} from "../controllers/fileController.js";

const router = express.Router();

/**
 * Upload an already-encrypted file.
 *
 * The frontend encrypts the file before
 * sending it to this endpoint.
 */
router.post(
  "/upload",
  uploadFile
);

export default router;
