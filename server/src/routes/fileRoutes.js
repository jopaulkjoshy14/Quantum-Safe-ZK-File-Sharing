import express from "express";

import {
  uploadFile,
  downloadFile,
} from "../controllers/fileController.js";

const router = express.Router();

router.post(
  "/upload",
  uploadFile
);

router.get(
  "/:fileId/download",
  downloadFile
);

export default router;
