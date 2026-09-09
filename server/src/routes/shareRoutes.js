import express from "express";

import { requireAuth } from "../middleware/authMiddleware.js";

import {
  getRecipientPublicKey,
  createShare,
  listReceivedShares,
  listSentShares,
  downloadSharedFile,
  revokeShare,
} from "../controllers/shareController.js";

const router = express.Router();

router.use(requireAuth);

router.get("/received", listReceivedShares);
router.get("/sent", listSentShares);

router.get("/recipient/:username/public-key", getRecipientPublicKey);

router.post("/files/:fileId", createShare);

router.get("/:shareId/download", downloadSharedFile);

router.delete("/:shareId", revokeShare);

export default router;
