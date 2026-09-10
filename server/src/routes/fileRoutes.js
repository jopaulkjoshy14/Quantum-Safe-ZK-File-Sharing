import express from "express";

import { requireAuth } from "../middleware/authMiddleware.js";

import {
  uploadFile,
  listFiles,
  downloadFile,
  getFileKeyMaterial,
} from "../controllers/fileController.js";

const router = express.Router();

router.use(requireAuth);

router.post("/upload", uploadFile);

router.get("/", listFiles);

router.get("/:fileId/key-material", getFileKeyMaterial);

router.get("/:fileId/download", downloadFile);

export default router;
