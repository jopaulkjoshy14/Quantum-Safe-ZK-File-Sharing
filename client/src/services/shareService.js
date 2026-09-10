import { base64ToBytes, bytesToBase64 } from "../crypto/crypto.js";

import {
  encapsulateSharedSecret,
  decapsulateSharedSecret,
} from "../crypto/mlKem.js";

import {
  deriveShareWrappingKey,
  wrapSharedFEK,
  unwrapSharedFEK,
  wrapSharedMetadataKey,
  unwrapSharedMetadataKey,
} from "../crypto/shareWrapping.js";

import { unwrapOwnerFEK } from "../crypto/keyWrapping.js";
import {
  unwrapMetadataKey,
} from "../crypto/metadataCrypto.js";
import { decryptFile } from "../crypto/fileCrypto.js";
import { decryptMetadata } from "../crypto/metadataCrypto.js";

async function parseResponse(response, fallbackMessage) {
  let data;

  try {
    data = await response.json();
  } catch {
    throw new Error(
      "The server returned an invalid response."
    );
  }

  if (!response.ok) {
    throw new Error(
      data.message || fallbackMessage
    );
  }

  return data;
}

function validateMasterKey(masterKey) {
  if (!(masterKey instanceof Uint8Array) || masterKey.length !== 32) {
    throw new Error("Master Key must be exactly 32 bytes.");
  }
}

export async function lookupRecipient({
  username,
  authToken,
  apiBaseUrl,
}) {
  if (
    typeof username !== "string" ||
    username.trim().length === 0
  ) {
    throw new Error("Recipient username is required.");
  }

  const response = await fetch(
    `${apiBaseUrl}/shares/recipient/${encodeURIComponent(
      username.trim().toLowerCase()
    )}/public-key`,
    {
      headers: {
        Authorization: `Bearer ${authToken}`,
      },
    }
  );

  const data = await parseResponse(
    response,
    "Unable to find recipient."
  );

  if (
    !data.user ||
    typeof data.user.id !== "string" ||
    typeof data.user.mlKemPublicKey !== "string"
  ) {
    throw new Error("Recipient public-key data is invalid.");
  }

  return data.user;
}

/**
 * Retrieve only the owner's protected key material.
 * The ciphertext itself is not downloaded.
 */
async function getOwnerKeyMaterial({
  fileId,
  authToken,
  apiBaseUrl,
}) {
  const response = await fetch(
    `${apiBaseUrl}/files/${encodeURIComponent(fileId)}/key-material`,
    {
      headers: {
        Authorization: `Bearer ${authToken}`,
      },
    }
  );

  const data = await parseResponse(
    response,
    "Unable to retrieve protected file key material."
  );

  if (!data.file) {
    throw new Error("Protected file key material is missing.");
  }

  return data.file;
}

export async function createFileShare({
  fileId,
  recipient,
  authToken,
  masterKey,
  apiBaseUrl,
  senderId,
  onProgress,
}) {
  validateMasterKey(masterKey);

  if (
    typeof fileId !== "string" ||
    fileId.length === 0
  ) {
    throw new Error("File ID is required.");
  }

  if (
    !recipient ||
    typeof recipient.id !== "string" ||
    typeof recipient.mlKemPublicKey !== "string"
  ) {
    throw new Error("Recipient public-key data is invalid.");
  }

  onProgress?.({ id: "lookup" });
  const keyMaterial = await getOwnerKeyMaterial({
    fileId,
    authToken,
    apiBaseUrl,
  });

  const fek = await unwrapOwnerFEK(
    masterKey,
    keyMaterial.wrappedOwnerFEK,
    keyMaterial.ownerFEKIV
  );

  const metadataKey = await unwrapMetadataKey(
    masterKey,
    keyMaterial.wrappedMetadataKey,
    keyMaterial.metadataKeyIV
  );

  onProgress?.({ id: "kem" });
  const recipientPublicKey =
    base64ToBytes(recipient.mlKemPublicKey);

  const { cipherText, sharedSecret } =
    encapsulateSharedSecret(
      recipientPublicKey
    );

  onProgress?.({ id: "secret" });
  const wrappingKey =
    await deriveShareWrappingKey(
      sharedSecret,
      fileId,
      senderId,
      recipient.id
    );

  onProgress?.({ id: "derive" });
  const {
    ciphertext: wrappedFEK,
    iv: wrapIV,
  } = await wrapSharedFEK(
    wrappingKey,
    fek
  );

  const {
    ciphertext: wrappedMetadataKey,
    iv: metadataKeyIV,
  } = await wrapSharedMetadataKey(
    wrappingKey,
    metadataKey
  );

  onProgress?.({ id: "wrap" });
  const response = await fetch(
    `${apiBaseUrl}/shares/files/${encodeURIComponent(fileId)}`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${authToken}`,
      },
      body: JSON.stringify({
        recipientId: recipient.id,
        kemAlgorithm: "ML-KEM-768",
        kemCiphertext: bytesToBase64(cipherText),
        wrappedFEK,
        wrapIV,
        wrappedMetadataKey,
        metadataKeyIV,
        keyVersion: Number(keyMaterial.keyVersion) || 1,
      }),
    }
  );

  onProgress?.({ id: "send" });
  const parsed = await parseResponse(
    response,
    "Unable to create file share."
  );
  onProgress?.({ id: "record" });
  return parsed;
}

export async function listReceivedShares({
  authToken,
  apiBaseUrl,
}) {
  const response = await fetch(
    `${apiBaseUrl}/shares/received`,
    {
      headers: {
        Authorization: `Bearer ${authToken}`,
      },
    }
  );

  return parseResponse(
    response,
    "Unable to retrieve received shares."
  );
}

export async function listSentShares({
  authToken,
  apiBaseUrl,
}) {
  const response = await fetch(
    `${apiBaseUrl}/shares/sent`,
    {
      headers: {
        Authorization: `Bearer ${authToken}`,
      },
    }
  );

  return parseResponse(
    response,
    "Unable to retrieve sent shares."
  );
}

export async function revokeFileShare({
  shareId,
  authToken,
  apiBaseUrl,
}) {
  const response = await fetch(
    `${apiBaseUrl}/shares/${encodeURIComponent(shareId)}`,
    {
      method: "DELETE",
      headers: {
        Authorization: `Bearer ${authToken}`,
      },
    }
  );

  return parseResponse(
    response,
    "Unable to revoke file share."
  );
}

/**
 * Retrieve, decapsulate, decrypt and download a shared file.
 * All cryptographic operations remain in the browser.
 */
export async function downloadAndDecryptSharedFile({
  shareId,
  authToken,
  masterKey,
  mlKemPrivateKey,
  apiBaseUrl,
  onProgress,
}) {
  validateMasterKey(masterKey);

  if (
    !(mlKemPrivateKey instanceof Uint8Array) ||
    mlKemPrivateKey.length === 0
  ) {
    throw new Error("ML-KEM private key is unavailable.");
  }

  onProgress?.({ id: "retrieve" });
  const response = await fetch(
    `${apiBaseUrl}/shares/${encodeURIComponent(shareId)}/download`,
    {
      headers: {
        Authorization: `Bearer ${authToken}`,
      },
    }
  );

  const data = await parseResponse(
    response,
    "Unable to retrieve shared file."
  );

  if (!data.file) {
    throw new Error("Shared file package is missing.");
  }

  const file = data.file;

  if (file.kemAlgorithm !== "ML-KEM-768") {
    throw new Error("Unsupported sharing algorithm.");
  }

  const kemCiphertext =
    base64ToBytes(file.kemCiphertext);

  onProgress?.({ id: "decap" });
  const sharedSecret =
    decapsulateSharedSecret(
      kemCiphertext,
      mlKemPrivateKey
    );

  onProgress?.({ id: "derive" });
  const wrappingKey =
    await deriveShareWrappingKey(
      sharedSecret,
      String(file.id),
      // The endpoint intentionally returns the share participants.
      String(file.senderId),
      String(file.recipientId)
    );

  onProgress?.({ id: "unwrap" });
  const fek = await unwrapSharedFEK(
    wrappingKey,
    file.wrappedFEK,
    file.wrapIV
  );

  const metadataKey =
    await unwrapSharedMetadataKey(
      wrappingKey,
      file.wrappedMetadataKey,
      file.metadataKeyIV
    );

  onProgress?.({ id: "decrypt" });
  const plaintext = await decryptFile(
    base64ToBytes(file.encryptedData),
    fek,
    base64ToBytes(file.fileIV)
  );

  onProgress?.({ id: "metadata" });
  const metadata = await decryptMetadata(
    file.encryptedMetadata,
    metadataKey,
    file.metadataIV
  );

  if (
    !metadata ||
    typeof metadata.name !== "string" ||
    metadata.name.length === 0 ||
    typeof metadata.type !== "string" ||
    !Number.isInteger(metadata.size) ||
    metadata.size < 0
  ) {
    throw new Error("Recovered shared-file metadata is invalid.");
  }

  if (plaintext.length !== metadata.size) {
    throw new Error(
      "Recovered file size does not match its protected metadata."
    );
  }

  onProgress?.({ id: "reconstruct" });

  return {
    plaintext,
    metadata,
    shareId,
    keyVersion: file.keyVersion,
  };
}
