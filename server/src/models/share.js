import { ObjectId } from "mongodb";

import { getDatabase } from "../config/db.js";

const SHARES_COLLECTION = "shares";

export function getSharesCollection() {
  return getDatabase().collection(SHARES_COLLECTION);
}

export async function ensureShareIndexes() {
  const shares = getSharesCollection();

  await shares.createIndex(
    { recipientId: 1, status: 1, createdAt: -1 },
    { name: "recipient_status_createdAt" }
  );

  await shares.createIndex(
    { senderId: 1, status: 1, createdAt: -1 },
    { name: "sender_status_createdAt" }
  );

  await shares.createIndex(
    { fileId: 1, recipientId: 1 },
    {
      unique: true,
      name: "file_recipient_unique_active",
      partialFilterExpression: {
        status: "active",
      },
    }
  );
}

function toObjectId(value, fieldName) {
  try {
    return new ObjectId(value);
  } catch {
    throw new Error(`${fieldName} is invalid.`);
  }
}

export function createShareDocument({
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
}) {
  if (!fileId || !senderId || !recipientId) {
    throw new Error("Share participants and file are required.");
  }

  if (kemAlgorithm !== "ML-KEM-768") {
    throw new Error("Unsupported key encapsulation algorithm.");
  }

  if (
    typeof kemCiphertext !== "string" ||
    kemCiphertext.length === 0 ||
    typeof wrappedFEK !== "string" ||
    wrappedFEK.length === 0 ||
    typeof wrapIV !== "string" ||
    wrapIV.length === 0
  ) {
    throw new Error("Protected sharing key material is incomplete.");
  }

  if (
    typeof wrappedMetadataKey !== "string" ||
    wrappedMetadataKey.length === 0 ||
    typeof metadataKeyIV !== "string" ||
    metadataKeyIV.length === 0
  ) {
    throw new Error("Protected metadata sharing key material is incomplete.");
  }

  if (!Number.isInteger(keyVersion) || keyVersion < 1) {
    throw new Error("Invalid cryptographic key version.");
  }

  return {
    fileId: toObjectId(fileId, "File ID"),
    senderId: toObjectId(senderId, "Sender ID"),
    recipientId: toObjectId(recipientId),

    kemAlgorithm,
    kemCiphertext,

    wrappedFEK,
    wrapIV,

    wrappedMetadataKey,
    metadataKeyIV,

    keyVersion,

    status: "active",
    createdAt: new Date(),
    revokedAt: null,
  };
}

export async function insertShare(document) {
  return getSharesCollection().insertOne(document);
}

export async function findActiveShareForFileRecipient(
  fileId,
  recipientId
) {
  let fileObjectId;
  let recipientObjectId;

  try {
    fileObjectId = new ObjectId(fileId);
    recipientObjectId = new ObjectId(recipientId);
  } catch {
    return null;
  }

  return getSharesCollection().findOne({
    fileId: fileObjectId,
    recipientId: recipientObjectId,
    status: "active",
  });
}

export async function findActiveSharesByRecipient(recipientId) {
  let recipientObjectId;

  try {
    recipientObjectId = new ObjectId(recipientId);
  } catch {
    return [];
  }

  return getSharesCollection()
    .find({
      recipientId: recipientObjectId,
      status: "active",
    })
    .sort({ createdAt: -1 })
    .toArray();
}

export async function findActiveSharesBySender(senderId) {
  let senderObjectId;

  try {
    senderObjectId = new ObjectId(senderId);
  } catch {
    return [];
  }

  return getSharesCollection()
    .find({
      senderId: senderObjectId,
      status: "active",
    })
    .sort({ createdAt: -1 })
    .toArray();
}

export async function findShareById(shareId) {
  try {
    return await getSharesCollection().findOne({
      _id: new ObjectId(shareId),
    });
  } catch {
    return null;
  }
}

export async function revokeShareForSender(shareId, senderId) {
  let shareObjectId;
  let senderObjectId;

  try {
    shareObjectId = new ObjectId(shareId);
    senderObjectId = new ObjectId(senderId);
  } catch {
    return { matchedCount: 0, modifiedCount: 0 };
  }

  return getSharesCollection().updateOne(
    {
      _id: shareObjectId,
      senderId: senderObjectId,
      status: "active",
    },
    {
      $set: {
        status: "revoked",
        revokedAt: new Date(),
      },
    }
  );
}
