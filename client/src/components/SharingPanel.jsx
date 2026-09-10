import { useEffect, useState } from "react";
import {
  lookupRecipient,
  createFileShare,
  listReceivedShares,
  listSentShares,
  revokeFileShare,
  downloadAndDecryptSharedFile,
} from "../services/shareService.js";

function formatDate(value) { return value ? new Date(value).toLocaleString() : "Unknown"; }

const SHARE_STAGES = [
  ["lookup", "Recipient public key retrieved"],
  ["kem", "ML-KEM-768 encapsulation performed"],
  ["secret", "Shared secret established"],
  ["derive", "FEK wrapping key derived"],
  ["wrap", "FEK protected for recipient"],
  ["send", "Protected share sent to server"],
  ["record", "Share record created"],
];
const RECEIVE_STAGES = [
  ["retrieve", "Authenticated shared package retrieved"],
  ["decap", "ML-KEM-768 decapsulation performed"],
  ["derive", "Share wrapping key derived"],
  ["unwrap", "Recipient FEK recovered locally"],
  ["metadata", "Encrypted metadata decrypted locally"],
  ["decrypt", "File decrypted with AES-256-GCM"],
  ["reconstruct", "Original file reconstructed"],
];

export default function SharingPanel({ section = "sharing", fileList, authToken, currentUser, runtimeKeys, apiBaseUrl, onActivity }) {
  const [recipientUsername, setRecipientUsername] = useState("");
  const [selectedFileId, setSelectedFileId] = useState("");
  const [shareStatus, setShareStatus] = useState("");
  const [shareError, setShareError] = useState("");
  const [isSharing, setIsSharing] = useState(false);
  const [shareSteps, setShareSteps] = useState([]);
  const [receivedShares, setReceivedShares] = useState([]);
  const [sentShares, setSentShares] = useState([]);
  const [shareListError, setShareListError] = useState("");
  const [isLoadingShares, setIsLoadingShares] = useState(false);
  const [downloadingShareId, setDownloadingShareId] = useState(null);
  const [receiveSteps, setReceiveSteps] = useState([]);
  const [sharedDownloadError, setSharedDownloadError] = useState("");
  const [revokingShareId, setRevokingShareId] = useState(null);

  async function refreshShares() {
    if (!authToken) return;
    setIsLoadingShares(true); setShareListError("");
    try {
      const [received, sent] = await Promise.all([
        listReceivedShares({ authToken, apiBaseUrl }),
        listSentShares({ authToken, apiBaseUrl }),
      ]);
      setReceivedShares(Array.isArray(received.shares) ? received.shares : []);
      setSentShares(Array.isArray(sent.shares) ? sent.shares : []);
    } catch (error) { setShareListError(error.message || "Unable to load shares."); }
    finally { setIsLoadingShares(false); }
  }
  useEffect(() => { refreshShares(); }, [authToken, apiBaseUrl]);

  async function handleShare(event) {
    event.preventDefault(); setShareError(""); setShareStatus(""); setShareSteps([]);
    if (!selectedFileId) return setShareError("Select an encrypted file first.");
    if (!recipientUsername.trim()) return setShareError("Enter the recipient username.");
    if (!(runtimeKeys?.masterKey instanceof Uint8Array)) return setShareError("Master Key is unavailable.");
    setIsSharing(true);
    try {
      const recipient = await lookupRecipient({ username: recipientUsername, authToken, apiBaseUrl });
      setShareSteps((s) => [...s, { id: "lookup" }]);
      const step = (id) => setShareSteps((s) => s.some((x) => x.id === id) ? s : [...s, { id }]);
      await createFileShare({ fileId: selectedFileId, recipient, authToken, masterKey: runtimeKeys.masterKey, apiBaseUrl, senderId: currentUser.id, onProgress: step });
      ["kem", "secret", "derive", "wrap", "send", "record"].forEach((id) => step(id));
      setShareStatus(`File shared securely with ${recipient.username}.`);
      onActivity?.("SHARE", "File shared securely", `Encrypted file → ${recipient.username} · ML-KEM-768 protected key sharing`);
      setRecipientUsername(""); setSelectedFileId(""); await refreshShares();
    } catch (error) {
      setShareError(error.message || "Unable to share file.");
      onActivity?.("SHARE", "Secure sharing failed", error.message || "The sharing operation failed.", "failed");
    } finally { setIsSharing(false); }
  }

  async function handleSharedDownload(shareId, sender) {
    setSharedDownloadError(""); setReceiveSteps([]); setDownloadingShareId(String(shareId));
    try {
      const step = (id) => setReceiveSteps((s) => s.some((x) => x.id === id) ? s : [...s, { id }]);
      const result = await downloadAndDecryptSharedFile({ shareId: String(shareId), authToken, masterKey: runtimeKeys.masterKey, mlKemPrivateKey: runtimeKeys.mlKemPrivateKey, apiBaseUrl, onProgress: step });
      const blob = new Blob([result.plaintext], { type: result.metadata.type || "application/octet-stream" });
      const objectUrl = URL.createObjectURL(blob); const anchor = document.createElement("a"); anchor.href = objectUrl; anchor.download = result.metadata.name; document.body.appendChild(anchor); anchor.click(); anchor.remove(); setTimeout(() => URL.revokeObjectURL(objectUrl), 1000);
      onActivity?.("DOWNLOAD", "Shared file decrypted locally", `${result.metadata.name} · received from ${sender || "another user"}`);
    } catch (error) {
      setSharedDownloadError(error.message || "Unable to decrypt shared file.");
      onActivity?.("DOWNLOAD", "Shared download failed", error.message || "The shared-file operation failed.", "failed");
    } finally { setDownloadingShareId(null); }
  }

  async function handleRevoke(shareId, username) {
    if (!window.confirm(`Revoke this file share for ${username}?`)) return;
    setRevokingShareId(String(shareId)); setShareListError("");
    try { await revokeFileShare({ shareId: String(shareId), authToken, apiBaseUrl }); onActivity?.("REVOKE", "File access revoked", `Future access blocked for ${username}.`); await refreshShares(); }
    catch (error) { setShareListError(error.message || "Unable to revoke share."); onActivity?.("REVOKE", "Revocation failed", error.message || "The revocation operation failed.", "failed"); }
    finally { setRevokingShareId(null); }
  }

  const showingShare = section === "sharing";
  return <div className="page-body sharing-page">
    <div className="page-intro"><span className="section-kicker">{showingShare ? "Protected key distribution" : "Incoming access"}</span><h2>{showingShare ? "Share securely." : "Shared with me."}</h2><p>{showingShare ? "Give another user access by protecting the file's encryption key with their ML-KEM-768 public key." : "Files shared with your account can be recovered and decrypted locally using your protected ML-KEM private key."}</p></div>
    {showingShare ? <>
      <section className="share-layout"><section className="section-card share-form-card"><div className="card-heading"><div><span className="section-kicker">New share</span><h3>Protect a file for a recipient.</h3></div><span className="mini-badge">ML-KEM-768</span></div><form onSubmit={handleShare} className="modern-form"><label>Encrypted file<select value={selectedFileId} onChange={(e) => setSelectedFileId(e.target.value)} disabled={isSharing || fileList.length === 0} required><option value="">Select a file</option>{fileList.map((file) => <option key={String(file.id)} value={String(file.id)}>Encrypted file · {String(file.id).slice(0, 12)}…</option>)}</select></label><label>Recipient username<input value={recipientUsername} onChange={(e) => setRecipientUsername(e.target.value)} placeholder="e.g. bob" minLength={3} maxLength={50} autoComplete="off" disabled={isSharing} required /></label>{shareError && <div className="form-alert danger">{shareError}</div>}{shareStatus && <div className="form-alert success">✓ {shareStatus}</div>}<button className="primary-btn wide" disabled={isSharing || fileList.length === 0}>{isSharing ? "Creating protected share…" : "Share file securely →"}</button></form></section><OperationCard title="Secure File Sharing" subtitle={recipientUsername || "Key distribution pipeline"} stages={SHARE_STAGES} steps={shareSteps} active={isSharing} /></section>
      <section className="section-card share-list-card"><div className="card-heading"><div><span className="section-kicker">Outgoing access</span><h3>Your active shares</h3></div><button className="outline-btn" onClick={refreshShares} disabled={isLoadingShares}>{isLoadingShares ? "Refreshing…" : "Refresh"}</button></div>{shareListError && <div className="form-alert danger">{shareListError}</div>}{sentShares.length === 0 ? <EmptyShare text="No active outgoing shares." /> : <div className="share-list">{sentShares.map((share) => { const id = String(share.id); const user = share.otherUser?.username || "Unknown user"; return <div className="share-row" key={id}><span className="share-avatar">{user.slice(0,1).toUpperCase()}</span><div><strong>Encrypted file</strong><small>To {user} · {formatDate(share.createdAt)}</small></div><span className="share-status"><i /> Active</span><button className="danger-btn" onClick={() => handleRevoke(id, user)} disabled={revokingShareId === id}>{revokingShareId === id ? "Revoking…" : "Revoke"}</button></div>; })}</div>}<div className="revocation-note"><strong>Revocation boundary</strong><span>Revocation blocks future access through the share record. It cannot erase plaintext already downloaded by a recipient.</span></div></section>
    </> : <>
      {shareListError && <div className="form-alert danger">{shareListError}</div>}{sharedDownloadError && <div className="form-alert danger">{sharedDownloadError}</div>}<section className="received-layout"><section className="section-card received-list-card"><div className="card-heading"><div><span className="section-kicker">Incoming shares</span><h3>Files available to you</h3></div><button className="outline-btn" onClick={refreshShares} disabled={isLoadingShares}>{isLoadingShares ? "Refreshing…" : "Refresh"}</button></div>{receivedShares.length === 0 ? <EmptyShare text="No active incoming shares." /> : <div className="share-list">{receivedShares.map((share) => { const id = String(share.id); const sender = share.otherUser?.username || "Unknown user"; return <div className="received-row" key={id}><span className="share-avatar">{sender.slice(0,1).toUpperCase()}</span><div><strong>Encrypted shared file</strong><small>From {sender} · {formatDate(share.createdAt)}</small></div><span className="share-status"><i /> Available</span><button className="primary-mini" onClick={() => handleSharedDownload(id, sender)} disabled={downloadingShareId !== null}>{downloadingShareId === id ? "Decrypting…" : "Decrypt & download"}</button></div>; })}</div>}</section><OperationCard title="Secure Download" subtitle="Recipient-side decryption" stages={RECEIVE_STAGES} steps={receiveSteps} active={downloadingShareId !== null} /></section>
      <div className="page-note"><span>◇</span><p><strong>Local decryption:</strong> the recipient's browser decapsulates the ML-KEM ciphertext, recovers the protected FEK and decrypts the file. The backend never receives the plaintext file.</p></div>
    </>}
  </div>;
}

function OperationCard({ title, subtitle, stages, steps, active }) { const done = new Set(steps.map((s) => s.id)); return <section className="operation-card"><div className="operation-head"><span className="operation-live"><i className={active ? "pulse" : ""} /> {active ? "Processing" : "Secure Activity"}</span><strong>{title}</strong><small>{subtitle}</small></div><div className="pipeline">{stages.map(([id, label], i) => <div className={`pipeline-step ${done.has(id) ? "done" : ""}`} key={id}><span>{done.has(id) ? "✓" : String(i+1).padStart(2,"0")}</span><div><strong>{label}</strong><small>{done.has(id) ? "Completed" : active ? "Waiting for this stage" : "Ready"}</small></div>{i < stages.length-1 && <i className={`connector ${done.has(id) ? "done" : ""}`} />}</div>)}</div><div className="operation-foot">◇ <span>Protected key material is processed in browser memory.</span></div></section>; }
function EmptyShare({ text }) { return <div className="empty-state"><div className="empty-icon">↗</div><strong>{text}</strong><p>Active access records will appear here.</p></div>; }
