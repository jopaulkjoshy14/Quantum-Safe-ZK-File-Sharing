import { Readable } from "node:stream";

import { getGridFSBucket } from "../config/gridfs.js";

import {
  findUserByUsername,
  findUserById,
} from "../models/user.js";

import {
  findFileByIdForOwner,
  findFileById,
} from "../models/file.js";

import {
  createShareDocument,
  insertShare,
  findActiveShareForFileRecipient,
  findActiveSharesByRecipient,
  findActiveSharesBySender,
  findShareById,
  revokeShareForSender,
} from "../models/share.js";

const MAX_FILE_SIZE = 100 * 1024 * 1024;
const MAX_KEM_CIPHERTEXT_BYTES = 1200;
const MAX_WRAPPED_KEY_BYTES = 128;
const IV_LENGTH = 12;

function validateBase64(value, fieldName, maxBytes = null) {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    !/^[A-Za-z0-9+/]*={0,2}$/.test(value)
  ) {
    throw new Error(`${fieldName} contains invalid Base64 data.`);
  }

  const bytes = Buffer.from(value, "base64");

  if (bytes.length === 0) {
    throw new Error(`${fieldName} contains no data.`);
  }

  if (maxBytes !== null && bytes.length > maxBytes) {
    throw new Error(`${fieldName} is too large.`);
  }

  return bytes;
}

function validateIV(value, fieldName) {
  const bytes = validateBase64(value, fieldName, IV_LENGTH);

  if (bytes.length !== IV_LENGTH) {
    throw new Error(`${fieldName} must contain exactly 12 bytes.`);
  }
}

function normalizeUsername(username) {
  return username.trim().toLowerCase();
}

/**
 * Return an account's ML-KEM-768 public key.
 *
 * The public key is intentionally public cryptographic material.
 */
export async function getRecipientPublicKey(req, res) {
  try {
    const rawUsername = req.params.username;

    if (
      typeof rawUsername !== "string" ||
      rawUsername.length < 3 ||
      rawUsername.length > 50
    ) {
      return res.status(400).json({
        ok: false,
        message: "Invalid username.",
      });
    }

    const username = normalizeUsername(rawUsername);

    if (!/^[a-z0-9._-]+$/.test(username)) {
      return res.status(400).json({
        ok: false,
        message: "Invalid username.",
      });
    }

    const user = await findUserByUsername(username);

    if (!user || !user.mlKemPublicKey) {
      return res.status(404).json({
        ok: false,
        message: "Recipient account not found.",
      });
    }

    return res.status(200).json({
      ok: true,
      user: {
        id: user._id,
        username: user.username,
        mlKemPublicKey: user.mlKemPublicKey,
      },
    });
  } catch (error) {
    console.error("Recipient public-key lookup error:", error);

    return res.status(500).json({
      ok: false,
      message: "Unable to retrieve recipient public key.",
    });
  }
}

/**
 * Create a share record.
 *
 * The browser performs ML-KEM encapsulation and FEK/metadata-key
 * wrapping. The backend only validates and stores the resulting
 * protected package.
 */
export async function createShare(req, res) {
  try {
    const { fileId } = req.params;
    const senderId = req.user.id;

    const {
      recipientId,
      kemAlgorithm,
      kemCiphertext,
      wrappedFEK,
      wrapIV,
      wrappedMetadataKey,
      metadataKeyIV,
      keyVersion,
    } = req.body;

    if (
      typeof recipientId !== "string" ||
      recipientId.length === 0
    ) {
      return res.status(400).json({
        ok: false,
        message: "Recipient ID is required.",
      });
    }

    const recipient = await findUserById(recipientId);

    if (!recipient) {
      return res.status(404).json({
        ok: false,
        message: "Recipient account not found.",
      });
    }

    if (recipient._id.toString() === senderId) {
      return res.status(400).json({
        ok: false,
        message: "You cannot share a file with yourself.",
      });
    }

    const file = await findFileByIdForOwner(fileId, senderId);

    if (!file) {
      return res.status(404).json({
        ok: false,
        message: "File not found.",
      });
    }

    const existingShare =
      await findActiveShareForFileRecipient(
        fileId,
        recipientId
      );

    if (existingShare) {
      return res.status(409).json({
        ok: false,
        message: "This file is already shared with that user.",
      });
    }

    validateBase64(
      kemCiphertext,
      "ML-KEM ciphertext",
      MAX_KEM_CIPHERTEXT_BYTES
    );

    validateBase64(
      wrappedFEK,
      "Wrapped FEK",
      MAX_WRAPPED_KEY_BYTES
    );

    validateIV(wrapIV, "FEK wrapping IV");

    validateBase64(
      wrappedMetadataKey,
      "Wrapped metadata key",
      MAX_WRAPPED_KEY_BYTES
    );

    validateIV(
      metadataKeyIV,
      "Metadata key wrapping IV"
    );

    if (!Number.isInteger(keyVersion) || keyVersion < 1) {
      throw new Error("Invalid cryptographic key version.");
    }

    const shareDocument = createShareDocument({
      fileId,
      senderId,
      recipientId,
      kemAlgorithm,
      kemCiphertext,
      wrappedFEK,
      wrapIV,
      wrappedMetadataKey,
      metadataKeyIV,
      keyVersion,
    });

    const result = await insertShare(shareDocument);

    return res.status(201).json({
      ok: true,
      message: "File shared successfully.",
      share: {
        id: result.insertedId,
        fileId: shareDocument.fileId,
        recipientId: shareDocument.recipientId,
        keyVersion: shareDocument.keyVersion,
        status: shareDocument.status,
        createdAt: shareDocument.createdAt,
      },
    });
  } catch (error) {
    console.error("Create share error:", error);

    if (error?.code === 11000) {
      return res.status(409).json({
        ok: false,
        message: "This file is already shared with that user.",
      });
    }

    return res.status(400).json({
      ok: false,
      message: error.message || "Unable to create file share.",
    });
  }
}

async function enrichShareList(shares, viewerField) {
  return Promise.all(
    shares.map(async (share) => {
      const otherUserId =
        viewerField === "recipient"
          ? share.senderId
          : share.recipientId;

      const otherUser = await findUserById(otherUserId);
      const file = await findFileById(share.fileId);

      return {
        id: share._id,
        fileId: share.fileId,
        otherUser: {
          id: otherUserId,
          username: otherUser?.username || "Unknown user",
        },
        keyVersion: share.keyVersion,
        status: share.status,
        createdAt: share.createdAt,
        revokedAt: share.revokedAt,
        fileAvailable: Boolean(file),
      };
    })
  );
}

/**
 * List active shares received by the authenticated user.
 */
export async function listReceivedShares(req, res) {
  try {
    const shares = await findActiveSharesByRecipient(req.user.id);

    return res.status(200).json({
      ok: true,
      shares: await enrichShareList(shares, "recipient"),
    });
  } catch (error) {
    console.error("Received shares listing error:", error);

    return res.status(500).json({
      ok: false,
      message: "Unable to retrieve received shares.",
    });
  }
}

/**
 * List active shares created by the authenticated owner.
 */
export async function listSentShares(req, res) {
  try {
    const shares = await findActiveSharesBySender(req.user.id);

    return res.status(200).json({
      ok: true,
      shares: await enrichShareList(shares, "sender"),
    });
  } catch (error) {
    console.error("Sent shares listing error:", error);

    return res.status(500).json({
      ok: false,
      message: "Unable to retrieve sent shares.",
    });
  }
}

/**
 * Retrieve ciphertext and the recipient's protected key package.
 *
 * Only an active recipient can use this endpoint.
 * The server never decapsulates ML-KEM or unwraps any key.
 */
export async function downloadSharedFile(req, res) {
  try {
    const { shareId } = req.params;

    const share = await findShareById(shareId);

    if (
      !share ||
      share.status !== "active" ||
      share.recipientId.toString() !== req.user.id
    ) {
      return res.status(404).json({
        ok: false,
        message: "Shared file not found.",
      });
    }

    const file = await findFileById(share.fileId);

    if (!file) {
      return res.status(404).json({
        ok: false,
        message: "Shared file no longer exists.",
      });
    }

    const bucket = getGridFSBucket();
    const downloadStream = bucket.openDownloadStream(
      file.gridFsFileId
    );

    const chunks = [];
    let totalSize = 0;

    await new Promise((resolve, reject) => {
      downloadStream.on("data", (chunk) => {
        totalSize += chunk.length;

        if (totalSize > MAX_FILE_SIZE + 16) {
          downloadStream.destroy(
            new Error(
              "Stored encrypted file exceeds the V1 size limit."
            )
          );
          return;
        }

        chunks.push(chunk);
      });

      downloadStream.on("end", resolve);
      downloadStream.on("error", reject);
    });

    if (totalSize < 16) {
      return res.status(500).json({
        ok: false,
        message: "Stored encrypted file is invalid.",
      });
    }

    return res.status(200).json({
      ok: true,
      message: "Shared encrypted file retrieved successfully.",
      file: {
        id: file._id,
        encryptedData: Buffer.concat(chunks).toString("base64"),
        fileIV: file.fileIV,
        encryptedMetadata: file.encryptedMetadata,
        metadataIV: file.metadataIV,
        keyVersion: file.keyVersion,

        senderId: share.senderId,
        recipientId: share.recipientId,
        kemAlgorithm: share.kemAlgorithm,
        kemCiphertext: share.kemCiphertext,
        wrappedFEK: share.wrappedFEK,
        wrapIV: share.wrapIV,
        wrappedMetadataKey: share.wrappedMetadataKey,
        metadataKeyIV: share.metadataKeyIV,
      },
    });
  } catch (error) {
    console.error("Shared file retrieval error:", error);

    return res.status(500).json({
      ok: false,
      message: "Shared file retrieval failed.",
    });
  }
}

/**
 * Revoke a share.
 *
 * Revocation blocks future access through this share record.
 * It cannot erase plaintext already downloaded by the recipient.
 */
export async function revokeShare(req, res) {
  try {
    const { shareId } = req.params;

    const result = await revokeShareForSender(
      shareId,
      req.user.id
    );

    if (result.matchedCount === 0) {
      return res.status(404).json({
        ok: false,
        message: "Active share not found.",
      });
    }

    return res.status(200).json({
      ok: true,
      message:
        "Share revoked. Future access through this share has been disabled.",
    });
  } catch (error) {
    console.error("Share revocation error:", error);

    return res.status(500).json({
      ok: false,
      message: "Unable to revoke share.",
    });
  }
}
