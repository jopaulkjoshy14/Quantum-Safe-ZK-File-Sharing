import { useEffect, useState } from "react";

import {
  lookupRecipient,
  createFileShare,
  listReceivedShares,
  listSentShares,
  revokeFileShare,
  downloadAndDecryptSharedFile,
} from "../services/shareService.js";

function formatDate(value) {
  if (!value) return "Unknown";
  return new Date(value).toLocaleString();
}

export default function SharingPanel({
  fileList,
  authToken,
  currentUser,
  runtimeKeys,
  apiBaseUrl,
}) {
  const [recipientUsername, setRecipientUsername] = useState("");
  const [selectedFileId, setSelectedFileId] = useState("");

  const [shareStatus, setShareStatus] = useState("");
  const [shareError, setShareError] = useState("");
  const [isSharing, setIsSharing] = useState(false);

  const [receivedShares, setReceivedShares] = useState([]);
  const [sentShares, setSentShares] = useState([]);
  const [shareListError, setShareListError] = useState("");
  const [isLoadingShares, setIsLoadingShares] = useState(false);

  const [downloadingShareId, setDownloadingShareId] = useState(null);
  const [sharedDownloadStatus, setSharedDownloadStatus] = useState("");
  const [sharedDownloadError, setSharedDownloadError] = useState("");

  const [revokingShareId, setRevokingShareId] = useState(null);

  async function refreshShares() {
    if (!authToken) return;

    setIsLoadingShares(true);
    setShareListError("");

    try {
      const [received, sent] = await Promise.all([
        listReceivedShares({
          authToken,
          apiBaseUrl,
        }),
        listSentShares({
          authToken,
          apiBaseUrl,
        }),
      ]);

      setReceivedShares(
        Array.isArray(received.shares)
          ? received.shares
          : []
      );

      setSentShares(
        Array.isArray(sent.shares)
          ? sent.shares
          : []
      );
    } catch (error) {
      console.error("Failed to load shares:", error);
      setShareListError(
        error.message || "Unable to load file shares."
      );
    } finally {
      setIsLoadingShares(false);
    }
  }

  useEffect(() => {
    refreshShares();
  }, [authToken, apiBaseUrl]);

  async function handleShare(event) {
    event.preventDefault();

    setShareStatus("");
    setShareError("");

    if (!selectedFileId) {
      setShareError("Select an encrypted file first.");
      return;
    }

    if (!recipientUsername.trim()) {
      setShareError("Enter the recipient username.");
      return;
    }

    if (
      !runtimeKeys?.masterKey ||
      !(runtimeKeys.masterKey instanceof Uint8Array)
    ) {
      setShareError("Master Key is unavailable.");
      return;
    }

    if (
      typeof currentUser?.id !== "string" ||
      currentUser.id.length === 0
    ) {
      setShareError("Authenticated user identity is unavailable.");
      return;
    }

    setIsSharing(true);

    try {
      setShareStatus("Looking up recipient public key...");

      const recipient = await lookupRecipient({
        username: recipientUsername,
        authToken,
        apiBaseUrl,
      });

      setShareStatus(
        "Creating ML-KEM-768 key encapsulation and protected share..."
      );

      await createFileShare({
        fileId: selectedFileId,
        recipient,
        authToken,
        masterKey: runtimeKeys.masterKey,
        apiBaseUrl,
        senderId: currentUser.id,
      });

      setRecipientUsername("");
      setSelectedFileId("");

      setShareStatus(
        `File ${selectedFileId} was shared securely with ${recipient.username}.`
      );

      await refreshShares();
    } catch (error) {
      console.error("File sharing failed:", error);
      setShareError(
        error.message || "Unable to share file."
      );
    } finally {
      setIsSharing(false);
    }
  }

  async function handleSharedDownload(shareId) {
    setSharedDownloadStatus("");
    setSharedDownloadError("");

    if (
      !runtimeKeys?.masterKey ||
      !runtimeKeys?.mlKemPrivateKey
    ) {
      setSharedDownloadError(
        "Required cryptographic keys are unavailable."
      );
      return;
    }

    setDownloadingShareId(String(shareId));

    try {
      setSharedDownloadStatus(
        "Retrieving encrypted shared file..."
      );

      const result =
        await downloadAndDecryptSharedFile({
          shareId: String(shareId),
          authToken,
          masterKey: runtimeKeys.masterKey,
          mlKemPrivateKey: runtimeKeys.mlKemPrivateKey,
          apiBaseUrl,
        });

      const blob = new Blob(
        [result.plaintext],
        {
          type:
            result.metadata.type ||
            "application/octet-stream",
        }
      );

      const objectUrl = URL.createObjectURL(blob);

      const anchor = document.createElement("a");
      anchor.href = objectUrl;
      anchor.download = result.metadata.name;

      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();

      setTimeout(() => {
        URL.revokeObjectURL(objectUrl);
      }, 1000);

      setSharedDownloadStatus(
        `"${result.metadata.name}" decrypted and downloaded locally.`
      );
    } catch (error) {
      console.error(
        "Shared file download failed:",
        error
      );

      setSharedDownloadError(
        error.message ||
          "Unable to decrypt shared file."
      );
    } finally {
      setDownloadingShareId(null);
    }
  }

  async function handleRevoke(shareId, username) {
    const confirmed = window.confirm(
      `Revoke this file share for ${username}?`
    );

    if (!confirmed) return;

    setRevokingShareId(String(shareId));
    setShareListError("");

    try {
      await revokeFileShare({
        shareId: String(shareId),
        authToken,
        apiBaseUrl,
      });

      await refreshShares();
    } catch (error) {
      console.error("Share revocation failed:", error);
      setShareListError(
        error.message || "Unable to revoke share."
      );
    } finally {
      setRevokingShareId(null);
    }
  }

  if (!currentUser) {
    return null;
  }

  return (
    <div className="card border-warning mb-4">
      <div className="card-body">
        <div className="d-flex justify-content-between align-items-center mb-3">
          <div>
            <h2 className="h5 mb-1">Secure File Sharing</h2>
            <p className="text-secondary small mb-0">
              Files are shared by encapsulating protected keys
              with the recipient's ML-KEM-768 public key.
            </p>
          </div>

          <button
            type="button"
            className="btn btn-outline-secondary btn-sm"
            onClick={refreshShares}
            disabled={isLoadingShares}
          >
            {isLoadingShares ? "Refreshing..." : "Refresh Shares"}
          </button>
        </div>

        <div className="alert alert-info small">
          <strong>Key-only sharing:</strong>{" "}
          The server stores the ML-KEM ciphertext and
          recipient-specific wrapped keys. The plaintext file
          and unwrapped FEK remain client-side.
        </div>

        <form onSubmit={handleShare}>
          <div className="row g-3">
            <div className="col-md-6">
              <label
                htmlFor="shareFile"
                className="form-label"
              >
                Encrypted file
              </label>

              <select
                id="shareFile"
                className="form-select"
                value={selectedFileId}
                onChange={(event) =>
                  setSelectedFileId(event.target.value)
                }
                disabled={isSharing || fileList.length === 0}
              >
                <option value="">
                  Select a file
                </option>

                {fileList.map((file) => (
                  <option
                    key={String(file.id)}
                    value={String(file.id)}
                  >
                    Encrypted File —{" "}
                    {String(file.id)}
                  </option>
                ))}
              </select>
            </div>

            <div className="col-md-6">
              <label
                htmlFor="shareRecipient"
                className="form-label"
              >
                Recipient username
              </label>

              <input
                id="shareRecipient"
                type="text"
                className="form-control"
                value={recipientUsername}
                onChange={(event) =>
                  setRecipientUsername(event.target.value)
                }
                placeholder="e.g. bob"
                minLength={3}
                maxLength={50}
                autoComplete="off"
                disabled={isSharing}
                required
              />
            </div>
          </div>

          {shareError && (
            <div className="alert alert-danger mt-3 mb-2">
              {shareError}
            </div>
          )}

          {shareStatus && (
            <div className="alert alert-success mt-3 mb-2">
              {shareStatus}
            </div>
          )}

          <button
            type="submit"
            className="btn btn-warning mt-3"
            disabled={
              isSharing ||
              fileList.length === 0 ||
              !selectedFileId
            }
          >
            {isSharing
              ? "Creating Secure Share..."
              : "Share File"}
          </button>
        </form>

        <hr className="my-4" />

        {shareListError && (
          <div className="alert alert-danger small">
            {shareListError}
          </div>
        )}

        {sharedDownloadError && (
          <div className="alert alert-danger small">
            {sharedDownloadError}
          </div>
        )}

        {sharedDownloadStatus && (
          <div className="alert alert-success small">
            {sharedDownloadStatus}
          </div>
        )}

        <div className="row g-4">
          <div className="col-lg-6">
            <h3 className="h6">Files Shared With You</h3>

            {receivedShares.length === 0 ? (
              <p className="small text-secondary">
                No active incoming shares.
              </p>
            ) : (
              <div className="list-group">
                {receivedShares.map((share) => {
                  const shareId = String(share.id);
                  const isDownloading =
                    downloadingShareId === shareId;

                  return (
                    <div
                      key={shareId}
                      className="list-group-item"
                    >
                      <div className="fw-semibold">
                        Encrypted shared file
                      </div>

                      <div className="small text-secondary">
                        File ID:{" "}
                        <code>
                          {String(share.fileId)}
                        </code>
                      </div>

                      <div className="small text-secondary">
                        From:{" "}
                        {share.otherUser?.username ||
                          "Unknown user"}
                      </div>

                      <div className="small text-secondary">
                        Shared: {formatDate(share.createdAt)}
                      </div>

                      <button
                        type="button"
                        className="btn btn-primary btn-sm mt-2"
                        onClick={() =>
                          handleSharedDownload(shareId)
                        }
                        disabled={
                          downloadingShareId !== null
                        }
                      >
                        {isDownloading
                          ? "Decapsulating & Decrypting..."
                          : "Decrypt & Download"}
                      </button>
                    </div>
                  );
                })}
              </div>
            )}
          </div>

          <div className="col-lg-6">
            <h3 className="h6">Your Active Shares</h3>

            {sentShares.length === 0 ? (
              <p className="small text-secondary">
                No active outgoing shares.
              </p>
            ) : (
              <div className="list-group">
                {sentShares.map((share) => {
                  const shareId = String(share.id);
                  const isRevoking =
                    revokingShareId === shareId;

                  return (
                    <div
                      key={shareId}
                      className="list-group-item"
                    >
                      <div className="fw-semibold">
                        Encrypted shared file
                      </div>

                      <div className="small text-secondary">
                        File ID:{" "}
                        <code>
                          {String(share.fileId)}
                        </code>
                      </div>

                      <div className="small text-secondary">
                        Recipient:{" "}
                        {share.otherUser?.username ||
                          "Unknown user"}
                      </div>

                      <div className="small text-secondary">
                        Shared: {formatDate(share.createdAt)}
                      </div>

                      <button
                        type="button"
                        className="btn btn-outline-danger btn-sm mt-2"
                        onClick={() =>
                          handleRevoke(
                            shareId,
                            share.otherUser?.username ||
                              "this user"
                          )
                        }
                        disabled={isRevoking}
                      >
                        {isRevoking
                          ? "Revoking..."
                          : "Revoke Access"}
                      </button>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </div>

        <div className="alert alert-secondary small mt-4 mb-0">
          <strong>Revocation:</strong>{" "}
          revoking a share blocks future downloads through
          that share record. It cannot erase a plaintext file
          that the recipient already downloaded.
        </div>
      </div>
    </div>
  );
}
