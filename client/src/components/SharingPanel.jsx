import { useEffect, useRef, useState } from "react";
import OperationPanel from "./OperationPanel.jsx";
import Icon from "./Icon.jsx";
import {
  lookupRecipient,
  createFileShare,
  listReceivedShares,
  listSentShares,
  revokeFileShare,
  downloadAndDecryptSharedFile,
} from "../services/shareService.js";

function formatDate(value) {
  return value ? new Date(value).toLocaleDateString(undefined, { day: "numeric", month: "short", year: "numeric" }) : "Unknown date";
}

const SHARE_STAGES = [
  ["lookup", "Find their account"],
  ["kem", "Prepare secure sharing"],
  ["secret", "Establish a shared key"],
  ["derive", "Prepare the file key"],
  ["wrap", "Protect the file key"],
  ["send", "Send the share"],
  ["record", "Save access"],
];
const RECEIVE_STAGES = [
  ["retrieve", "Get the shared file"],
  ["decap", "Unlock shared access"],
  ["derive", "Prepare the shared key"],
  ["unwrap", "Unlock the file key"],
  ["decrypt", "Decrypt the file"],
  ["metadata", "Read file details"],
  ["reconstruct", "Prepare download"],
];

export default function SharingPanel({ section = "sharing", fileList, authToken, currentUser, runtimeKeys, apiBaseUrl, onActivity }) {
  const showingShare = section === "sharing";
  const [recipientUsername, setRecipientUsername] = useState("");
  const [selectedFileId, setSelectedFileId] = useState("");
  const [shareStatus, setShareStatus] = useState("");
  const [shareError, setShareError] = useState("");
  const [isSharing, setIsSharing] = useState(false);
  const [shareSteps, setShareSteps] = useState([]);
  const [receivedShares, setReceivedShares] = useState([]);
  const [sentShares, setSentShares] = useState([]);
  const [shareListError, setShareListError] = useState("");
  const [isLoadingShares, setIsLoadingShares] = useState(true);
  const [downloadingShareId, setDownloadingShareId] = useState(null);
  const [receiveSteps, setReceiveSteps] = useState([]);
  const [sharedDownloadError, setSharedDownloadError] = useState("");
  const [revokingShareId, setRevokingShareId] = useState(null);
  const [pendingRevokeId, setPendingRevokeId] = useState(null);
  const focusTarget = useRef(null);

  function restoreFocus(button, target) {
    if (button && !button.disabled && focusTarget.current === target) {
      button.focus();
      focusTarget.current = null;
    }
  }

  async function refreshShares() {
    if (!authToken) return;
    setIsLoadingShares(true);
    setShareListError("");
    try {
      const result = await (showingShare ? listSentShares : listReceivedShares)({ authToken, apiBaseUrl });
      const shares = Array.isArray(result.shares) ? result.shares : [];
      if (showingShare) setSentShares(shares);
      else setReceivedShares(shares);
    } catch (error) {
      setShareListError(error.message || "Unable to load shares.");
    } finally {
      setIsLoadingShares(false);
    }
  }

  useEffect(() => {
    setPendingRevokeId(null);
    setSharedDownloadError("");
    refreshShares();
  }, [authToken, apiBaseUrl, section]);

  async function handleShare(event) {
    event.preventDefault();
    setShareError("");
    setShareStatus("");
    setShareSteps([]);
    if (!selectedFileId) return setShareError("Choose a file first.");
    if (!recipientUsername.trim()) return setShareError("Enter their username.");
    if (!(runtimeKeys?.masterKey instanceof Uint8Array)) return setShareError("Your session is unavailable. Sign in again.");
    setIsSharing(true);
    try {
      const recipient = await lookupRecipient({ username: recipientUsername, authToken, apiBaseUrl });
      const step = ({ id }) => setShareSteps((steps) => steps.some((item) => item.id === id) ? steps : [...steps, { id }]);
      await createFileShare({
        fileId: selectedFileId, recipient, authToken, masterKey: runtimeKeys.masterKey,
        apiBaseUrl, senderId: currentUser.id, onProgress: step,
      });
      setShareStatus(`Shared with ${recipient.username}.`);
      onActivity?.("SHARE", "File shared", `Shared with ${recipient.username}.`);
      setRecipientUsername("");
      setSelectedFileId("");
      await refreshShares();
    } catch (error) {
      setShareError(error.message || "Unable to share file.");
      onActivity?.("SHARE", "Sharing couldn’t finish", error.message || "Try sharing the file again.", "failed");
    } finally {
      setIsSharing(false);
    }
  }

  async function handleSharedDownload(shareId, sender) {
    setSharedDownloadError("");
    setReceiveSteps([]);
    setDownloadingShareId(String(shareId));
    try {
      const step = ({ id }) => setReceiveSteps((steps) => steps.some((item) => item.id === id) ? steps : [...steps, { id }]);
      const result = await downloadAndDecryptSharedFile({
        shareId: String(shareId), authToken, masterKey: runtimeKeys.masterKey,
        mlKemPrivateKey: runtimeKeys.mlKemPrivateKey, apiBaseUrl, onProgress: step,
      });
      const blob = new Blob([result.plaintext], { type: result.metadata.type || "application/octet-stream" });
      const objectUrl = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = objectUrl;
      anchor.download = result.metadata.name;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      setTimeout(() => URL.revokeObjectURL(objectUrl), 1000);
      onActivity?.("DOWNLOAD", "Shared file downloaded", `${result.metadata.name} · From ${sender || "another user"}`);
    } catch (error) {
      setSharedDownloadError(error.message || "Unable to download the shared file.");
      onActivity?.("DOWNLOAD", "Download couldn’t finish", error.message || "Try downloading the file again.", "failed");
    } finally {
      setDownloadingShareId(null);
    }
  }

  async function handleRevoke(shareId, username) {
    setRevokingShareId(String(shareId));
    setShareListError("");
    try {
      await revokeFileShare({ shareId: String(shareId), authToken, apiBaseUrl });
      focusTarget.current = "refresh";
      setPendingRevokeId(null);
      onActivity?.("REVOKE", "Access removed", `Removed access for ${username}.`);
      await refreshShares();
    } catch (error) {
      setShareListError(error.message || "Unable to remove access.");
      onActivity?.("REVOKE", "Access couldn’t be removed", error.message || "Try removing access again.", "failed");
    } finally {
      setRevokingShareId(null);
    }
  }

  return (
    <div className="page-body sharing-page">
      <div className="page-intro">
        <span className="section-kicker"><Icon name={showingShare ? "share" : "download"} />{showingShare ? "Better together" : "From your people"}</span>
        <h2>{showingShare ? "A file worth sharing." : "Shared with you."}</h2>
        <p>{showingShare ? "Choose a file and enter their username." : "Files people have shared with your account."}</p>
      </div>
      {showingShare ? (
        <>
          <section className="share-layout">
            <section className="section-card share-form-card">
              <div className="card-heading">
                <h3>Send a file</h3>
                <span className="mini-badge"><Icon name="shield" /> Encrypted</span>
              </div>
              <form onSubmit={handleShare} className="modern-form sharing-form">
                <label>
                  Choose a file
                  <select value={selectedFileId} onChange={(event) => { setSelectedFileId(event.target.value); setShareError(""); setShareStatus(""); setShareSteps([]); }} disabled={isSharing || fileList.length === 0} required>
                    <option value="">{fileList.length ? "Select a file" : "Upload a file first"}</option>
                    {fileList.map((file) => <option key={String(file.id)} value={String(file.id)}>Private file · {String(file.id).slice(-8)}</option>)}
                  </select>
                </label>
                <label>
                  Their username
                  <input value={recipientUsername} onChange={(event) => { setRecipientUsername(event.target.value); setShareError(""); setShareStatus(""); setShareSteps([]); }} placeholder="e.g. bob" minLength={3} maxLength={50} autoComplete="off" disabled={isSharing} required />
                </label>
                {shareError && <div className="form-alert danger" role="alert">{shareError}</div>}
                {shareStatus && <div className="form-alert success" role="status">{shareStatus}</div>}
                <button className="primary-btn" disabled={isSharing || fileList.length === 0}>
                  <Icon name="share" />{isSharing ? "Sharing your file…" : "Share file"}
                </button>
              </form>
            </section>
            {!shareStatus && <OperationPanel title="Share progress" subtitle={recipientUsername} stages={SHARE_STAGES} steps={shareSteps} active={isSharing} />}
          </section>
          <section className="section-card share-list-card">
            <div className="card-heading">
              <h3>Shared by you</h3>
              <button className="outline-btn" ref={(button) => restoreFocus(button, "refresh")} onClick={refreshShares} disabled={isLoadingShares}><Icon name="refresh" />{isLoadingShares ? "Refreshing…" : "Refresh"}</button>
            </div>
            {shareListError && <div className="form-alert danger" role="alert">{shareListError}</div>}
            {sentShares.length === 0 ? (
              !shareListError && <EmptyShare text="No files shared yet." loading={isLoadingShares} />
            ) : (
              <div className="share-list">
                {sentShares.map((share) => {
                  const id = String(share.id);
                  const username = share.otherUser?.username || "Unknown user";
                  const confirming = pendingRevokeId === id;
                  return (
                    <div className="share-row" key={id}>
                      <span className="share-avatar" aria-hidden="true">{username.slice(0, 1).toUpperCase()}</span>
                      <div className="share-copy"><strong>Private file</strong><small>To {username} · {formatDate(share.createdAt)}</small></div>
                      <span className="share-status"><Icon name="check" /> Active</span>
                      {!confirming && <button className="danger-btn" ref={(button) => restoreFocus(button, id)} onClick={() => setPendingRevokeId(id)} disabled={revokingShareId !== null}>Remove access</button>}
                      {confirming && (
                        <div className="revoke-confirmation" role="group" aria-label={`Remove access for ${username}`}>
                          <p>Remove access for <strong>{username}</strong>?</p>
                          <div className="confirmation-actions">
                            <button className="outline-btn" autoFocus onClick={() => { focusTarget.current = id; setPendingRevokeId(null); }} disabled={revokingShareId !== null}>Cancel</button>
                            <button className="danger-btn" onClick={() => handleRevoke(id, username)} disabled={revokingShareId !== null}>{revokingShareId === id ? "Removing…" : "Remove access"}</button>
                          </div>
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
            <div className="revocation-note"><Icon name="info" /><span>Removing access stops future downloads, but can’t erase saved copies.</span></div>
          </section>
        </>
      ) : (
        <>
          {shareListError && <div className="form-alert danger" role="alert">{shareListError}</div>}
          {sharedDownloadError && <div className="form-alert danger" role="alert">{sharedDownloadError}</div>}
          <section className="received-layout">
            <section className="section-card received-list-card">
              <div className="card-heading">
                <h3>Files from others</h3>
                <button className="outline-btn" onClick={refreshShares} disabled={isLoadingShares}><Icon name="refresh" />{isLoadingShares ? "Refreshing…" : "Refresh"}</button>
              </div>
              {receivedShares.length === 0 ? (
                !shareListError && <EmptyShare text="Nothing shared with you yet." loading={isLoadingShares} />
              ) : (
                <div className="share-list">
                  {receivedShares.map((share) => {
                    const id = String(share.id);
                    const sender = share.otherUser?.username || "Unknown user";
                    return (
                      <div className="received-row" key={id}>
                        <span className="share-avatar" aria-hidden="true">{sender.slice(0, 1).toUpperCase()}</span>
                        <div className="share-copy"><strong>Private file</strong><small>From {sender} · {formatDate(share.createdAt)}</small></div>
                        <span className="share-status"><Icon name="check" /> Available</span>
                        <button className="primary-mini" onClick={() => handleSharedDownload(id, sender)} disabled={downloadingShareId !== null}><Icon name="download" />{downloadingShareId === id ? "Preparing…" : "Download"}</button>
                      </div>
                    );
                  })}
                </div>
              )}
            </section>
            <OperationPanel title="Download progress" stages={RECEIVE_STAGES} steps={receiveSteps} active={downloadingShareId !== null} />
          </section>
        </>
      )}
    </div>
  );
}

function EmptyShare({ text, loading }) {
  return (
    <div className="empty-state" role={loading ? "status" : undefined}>
      {loading ? <><div className="loader" /><p>Getting shared files…</p></> : <><div className="empty-icon"><Icon name="share" /></div><strong>{text}</strong></>}
    </div>
  );
}
