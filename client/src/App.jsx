import { useEffect, useState } from "react";

import { prepareRegistrationCrypto } from "./crypto/registrationCrypto.js";
import { recoverLoginKeys } from "./crypto/loginCrypto.js";
import { uploadEncryptedFile } from "./services/fileUploadService.js";
import { downloadAndDecryptFile } from "./services/fileDownloadService.js";
import SharingPanel from "./components/SharingPanel.jsx";

function formatBytes(bytes) {
  if (!Number.isFinite(bytes) || bytes < 0) return "—";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

function App() {
  const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || "http://localhost:5000/api";
  const MAX_FILE_SIZE = 100 * 1024 * 1024;

  const [status, setStatus] = useState("Checking backend...");
  const [error, setError] = useState("");

  const [registerUsername, setRegisterUsername] = useState("");
  const [registerPassword, setRegisterPassword] = useState("");
  const [registerStatus, setRegisterStatus] = useState("");
  const [registerError, setRegisterError] = useState("");
  const [isRegistering, setIsRegistering] = useState(false);

  const [loginUsername, setLoginUsername] = useState("");
  const [loginPassword, setLoginPassword] = useState("");
  const [loginStatus, setLoginStatus] = useState("");
  const [loginError, setLoginError] = useState("");
  const [isLoggingIn, setIsLoggingIn] = useState(false);

  const [authToken, setAuthToken] = useState(null);
  const [currentUser, setCurrentUser] = useState(null);
  const [runtimeKeys, setRuntimeKeys] = useState(null);

  const [selectedFile, setSelectedFile] = useState(null);
  const [uploadStatus, setUploadStatus] = useState("");
  const [uploadError, setUploadError] = useState("");
  const [isUploading, setIsUploading] = useState(false);
  const [uploadResult, setUploadResult] = useState(null);

  const [fileList, setFileList] = useState([]);
  const [fileListStatus, setFileListStatus] = useState("");
  const [fileListError, setFileListError] = useState("");
  const [isLoadingFiles, setIsLoadingFiles] = useState(false);

  const [downloadingFileId, setDownloadingFileId] = useState(null);
  const [downloadStatus, setDownloadStatus] = useState("");
  const [downloadError, setDownloadError] = useState("");

  useEffect(() => {
    fetch(`${API_BASE_URL}/health`)
      .then(async (response) => {
        if (!response.ok) throw new Error("Backend returned an error.");
        return response.json();
      })
      .then((data) => {
        setStatus(data.message || "Backend online");
        setError("");
      })
      .catch((err) => {
        setError(err.message);
        setStatus("Backend unavailable");
      });
  }, [API_BASE_URL]);

  async function handleRegister(event) {
    event.preventDefault();
    setRegisterStatus("");
    setRegisterError("");
    setIsRegistering(true);

    try {
      const cryptoMaterial = await prepareRegistrationCrypto(registerPassword);
      const response = await fetch(`${API_BASE_URL}/auth/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: registerUsername, password: registerPassword, ...cryptoMaterial }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.message || "Registration failed.");
      setRegisterStatus(`Registration successful for "${data.user.username}".`);
      setRegisterUsername("");
      setRegisterPassword("");
    } catch (err) {
      console.error("Registration failed:", err);
      setRegisterError(err.message || "Registration failed.");
    } finally {
      setIsRegistering(false);
    }
  }

  async function loadFileList(tokenOverride = null) {
    const token = tokenOverride || authToken;
    if (!token) return;
    setFileListStatus("Loading encrypted files...");
    setFileListError("");
    setIsLoadingFiles(true);
    try {
      const response = await fetch(`${API_BASE_URL}/files`, { headers: { Authorization: `Bearer ${token}` } });
      const data = await response.json();
      if (!response.ok) throw new Error(data.message || "Unable to load encrypted files.");
      const files = Array.isArray(data.files) ? data.files : [];
      setFileList(files);
      setFileListStatus(files.length ? `${files.length} encrypted file${files.length === 1 ? "" : "s"} available.` : "No encrypted files found.");
    } catch (err) {
      console.error("Failed to load encrypted files:", err);
      setFileList([]);
      setFileListStatus("");
      setFileListError(err.message || "Unable to load encrypted files.");
    } finally {
      setIsLoadingFiles(false);
    }
  }

  async function handleLogin(event) {
    event.preventDefault();
    setLoginStatus("");
    setLoginError("");
    setIsLoggingIn(true);
    setAuthToken(null);
    setRuntimeKeys(null);
    setCurrentUser(null);
    setFileList([]);
    setFileListStatus("");
    setFileListError("");

    try {
      const response = await fetch(`${API_BASE_URL}/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: loginUsername, password: loginPassword }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.message || "Login failed.");
      if (typeof data.authToken !== "string" || !data.authToken) throw new Error("Authentication token was not returned by the server.");
      if (!data.user || typeof data.user !== "object") throw new Error("User authentication data was not returned by the server.");

      const recoveredKeys = await recoverLoginKeys({
        password: loginPassword,
        passwordKdfSalt: data.user.passwordKdfSalt,
        passwordKdfParams: data.user.passwordKdfParams,
        wrappedMasterKey: data.user.wrappedMasterKey,
        masterKeyIV: data.user.masterKeyIV,
        wrappedMlKemPrivateKey: data.user.wrappedMlKemPrivateKey,
        privateKeyIV: data.user.privateKeyIV,
      });

      const authenticatedToken = data.authToken;
      setAuthToken(authenticatedToken);
      setRuntimeKeys(recoveredKeys);
      setCurrentUser({ id: data.user.id, username: data.user.username, mlKemPublicKey: data.user.mlKemPublicKey });
      setLoginStatus("Secure session established.");
      setLoginPassword("");
      await loadFileList(authenticatedToken);
    } catch (err) {
      console.error("Login failed:", err);
      setAuthToken(null);
      setRuntimeKeys(null);
      setCurrentUser(null);
      setLoginError(err.message || "Login failed.");
    } finally {
      setIsLoggingIn(false);
    }
  }

  function handleFileSelect(event) {
    const file = event.target.files?.[0];
    setUploadStatus("");
    setUploadError("");
    setUploadResult(null);
    if (!file) {
      setSelectedFile(null);
      return;
    }
    if (file.size > MAX_FILE_SIZE) {
      setSelectedFile(null);
      setUploadError("File exceeds the V1 maximum size of 100 MB.");
      event.target.value = "";
      return;
    }
    setSelectedFile(file);
  }

  async function handleFileUpload(event) {
    event.preventDefault();
    setUploadStatus("");
    setUploadError("");
    setUploadResult(null);
    if (!selectedFile) return setUploadError("Please select a file first.");
    if (!currentUser) return setUploadError("You must be logged in to upload a file.");
    if (!authToken) return setUploadError("Authenticated session is unavailable.");
    if (!(runtimeKeys?.masterKey instanceof Uint8Array)) return setUploadError("Master Key is unavailable.");

    setIsUploading(true);
    try {
      setUploadStatus("Encrypting file and metadata locally...");
      const result = await uploadEncryptedFile({ file: selectedFile, masterKey: runtimeKeys.masterKey, authToken, apiBaseUrl: API_BASE_URL });
      setUploadResult(result);
      setUploadStatus("File encrypted in the browser and uploaded successfully.");
      setSelectedFile(null);
      const input = document.getElementById("fileUpload");
      if (input) input.value = "";
      await loadFileList();
    } catch (err) {
      console.error("Encrypted file upload failed:", err);
      setUploadError(err.message || "Encrypted file upload failed.");
    } finally {
      setIsUploading(false);
    }
  }

  async function handleFileDownload(fileId) {
    setDownloadStatus("");
    setDownloadError("");
    if (!authToken) return setDownloadError("Authenticated session is unavailable.");
    if (!(runtimeKeys?.masterKey instanceof Uint8Array)) return setDownloadError("Master Key is unavailable.");
    setDownloadingFileId(fileId);
    try {
      setDownloadStatus("Retrieving encrypted file...");
      const result = await downloadAndDecryptFile({ fileId, authToken, masterKey: runtimeKeys.masterKey, apiBaseUrl: API_BASE_URL });
      if (result.plaintext.length !== result.metadata.size) throw new Error("Recovered file size does not match its protected metadata.");
      const blob = new Blob([result.plaintext], { type: result.metadata.type || "application/octet-stream" });
      const objectUrl = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = objectUrl;
      anchor.download = result.metadata.name;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      setTimeout(() => URL.revokeObjectURL(objectUrl), 1000);
      setDownloadStatus(`"${result.metadata.name}" decrypted and downloaded locally.`);
    } catch (err) {
      console.error("File download/decryption failed:", err);
      setDownloadError(err.message || "File download and decryption failed.");
    } finally {
      setDownloadingFileId(null);
    }
  }

  function handleLogout() {
    setAuthToken(null);
    setRuntimeKeys(null);
    setCurrentUser(null);
    setLoginUsername("");
    setLoginPassword("");
    setSelectedFile(null);
    setFileList([]);
    setFileListStatus("");
    setFileListError("");
    setUploadStatus("");
    setUploadError("");
    setUploadResult(null);
    setDownloadStatus("");
    setDownloadError("");
    setDownloadingFileId(null);
    const input = document.getElementById("fileUpload");
    if (input) input.value = "";
    setLoginStatus("Session cleared. Runtime keys removed.");
    setLoginError("");
  }

  const loggedIn = Boolean(currentUser);
  const backendOnline = !error;
  const totalFiles = fileList.length;

  return (
    <div className="app-shell">
      <header className="topbar">
        <div className="container-fluid app-container topbar-inner">
          <a className="brand" href="#top" aria-label="QSZKFSS home">
            <span className="brand-mark"><span /></span>
            <span><strong>QSZKFSS</strong><small>Quantum Safe File Sharing</small></span>
          </a>
          <div className="topbar-actions">
            <span className={`system-pill ${backendOnline ? "online" : "offline"}`}><i />{backendOnline ? "System operational" : "Backend offline"}</span>
            {loggedIn && <span className="user-chip"><span>{currentUser.username.slice(0, 1).toUpperCase()}</span>{currentUser.username}</span>}
            {loggedIn && <button className="ghost-btn" onClick={handleLogout}>Sign out</button>}
          </div>
        </div>
      </header>

      <main id="top">
        {!loggedIn ? (
          <>
            <section className="hero-section">
              <div className="container-fluid app-container">
                <div className="hero-grid">
                  <div className="hero-copy">
                    <div className="eyebrow"><span className="eyebrow-dot" /> Client-side security architecture</div>
                    <h1>Your files.<br /><em>Your keys.</em><br />Your privacy.</h1>
                    <p className="hero-lead">A privacy-first file sharing system where encryption happens in your browser before your data reaches the cloud.</p>
                    <div className="hero-proof">
                      <div><strong>AES-256-GCM</strong><span>File encryption</span></div>
                      <div><strong>ML-KEM-768</strong><span>Secure key establishment</span></div>
                      <div><strong>0</strong><span>Plaintext sent to server</span></div>
                    </div>
                  </div>
                  <div className="auth-card">
                    <div className="auth-tabs"><a href="#login" className="active">Sign in</a><a href="#register">Create account</a></div>
                    <div id="login" className="auth-pane">
                      <div className="section-kicker">Welcome back</div>
                      <h2>Open your secure vault</h2>
                      <p>Recover your cryptographic keys locally and continue securely.</p>
                      <form onSubmit={handleLogin}>
                        <label>Username<input value={loginUsername} onChange={(e) => setLoginUsername(e.target.value)} placeholder="alice" autoComplete="username" required minLength={3} maxLength={50} /></label>
                        <label>Password<input type="password" value={loginPassword} onChange={(e) => setLoginPassword(e.target.value)} placeholder="Your password" autoComplete="current-password" required minLength={8} maxLength={128} /></label>
                        {loginError && <div className="form-alert danger">{loginError}</div>}
                        {loginStatus && <div className="form-alert success">✓ {loginStatus}</div>}
                        <button className="primary-btn" disabled={isLoggingIn}>{isLoggingIn ? "Recovering secure keys…" : "Sign in securely →"}</button>
                      </form>
                    </div>
                    <div id="register" className="auth-pane register-pane">
                      <div className="section-kicker">New here?</div>
                      <h2>Create a private account</h2>
                      <p>Your Master Key and ML-KEM private key are generated and protected in the browser.</p>
                      <form onSubmit={handleRegister}>
                        <label>Username<input value={registerUsername} onChange={(e) => setRegisterUsername(e.target.value)} placeholder="Choose a username" autoComplete="username" required minLength={3} maxLength={50} /></label>
                        <label>Password<input type="password" value={registerPassword} onChange={(e) => setRegisterPassword(e.target.value)} placeholder="At least 8 characters" autoComplete="new-password" required minLength={8} maxLength={128} /></label>
                        {registerError && <div className="form-alert danger">{registerError}</div>}
                        {registerStatus && <div className="form-alert success">✓ {registerStatus}</div>}
                        <button className="secondary-btn" disabled={isRegistering}>{isRegistering ? "Creating protected account…" : "Create account"}</button>
                      </form>
                    </div>
                  </div>
                </div>
              </div>
            </section>
            <section className="trust-strip"><div className="container-fluid app-container trust-grid"><div><span>01</span><strong>Encrypt locally</strong><p>Plaintext is processed in your browser.</p></div><div><span>02</span><strong>Protect the keys</strong><p>Master and private keys stay out of storage.</p></div><div><span>03</span><strong>Share securely</strong><p>ML-KEM-768 protects recipient key material.</p></div><div><span>04</span><strong>Decrypt locally</strong><p>Only the recipient's browser recovers plaintext.</p></div></div></section>
          </>
        ) : (
          <div className="dashboard-wrap">
            <div className="container-fluid app-container">
              <section className="dashboard-heading">
                <div><div className="eyebrow"><span className="eyebrow-dot" /> Secure session active</div><h1>Good to see you, <span>{currentUser.username}</span>.</h1><p>Your encrypted workspace is ready. Sensitive cryptographic material exists only in this browser session.</p></div>
                <div className="security-badge"><div className="shield-icon">✓</div><div><strong>Protected session</strong><span>AES-GCM · ML-KEM-768</span></div></div>
              </section>

              <section className="metric-grid">
                <div className="metric-card"><span className="metric-icon">◈</span><div><strong>{totalFiles}</strong><span>Encrypted files</span></div></div>
                <div className="metric-card"><span className="metric-icon">↗</span><div><strong>ML-KEM</strong><span>768 key establishment</span></div></div>
                <div className="metric-card"><span className="metric-icon">⌁</span><div><strong>Runtime</strong><span>Keys not persisted</span></div></div>
                <div className="metric-card"><span className="metric-icon">✓</span><div><strong>Online</strong><span>Backend connection</span></div></div>
              </section>

              <section className="security-banner"><div className="security-banner-icon">⌁</div><div><strong>Zero-knowledge protection</strong><p>The server stores encrypted file data, encrypted metadata and protected key material. Plaintext files and unwrapped FEKs remain in the client.</p></div><div className="security-tags"><span>Client-side</span><span>Encrypted at rest</span><span>No browser persistence</span></div></section>

              <section className="workspace-grid">
                <div className="workspace-main">
                  <div className="panel-card upload-panel" id="upload">
                    <div className="panel-heading"><div><div className="section-kicker">Secure upload</div><h2>Protect a new file</h2><p>Encryption happens before the upload request is sent.</p></div><span className="panel-number">01</span></div>
                    <form onSubmit={handleFileUpload}>
                      <label htmlFor="fileUpload" className={`drop-zone ${selectedFile ? "has-file" : ""}`}>
                        <input id="fileUpload" type="file" onChange={handleFileSelect} disabled={isUploading} />
                        <span className="upload-icon">↑</span>
                        <strong>{selectedFile ? selectedFile.name : "Choose a file to encrypt"}</strong>
                        <span>{selectedFile ? `${formatBytes(selectedFile.size)} · ${selectedFile.type || "application/octet-stream"}` : "Click to browse · maximum 100 MB"}</span>
                      </label>
                      {uploadError && <div className="form-alert danger">{uploadError}</div>}
                      {uploadStatus && <div className="form-alert success">✓ {uploadStatus}</div>}
                      <div className="upload-actions"><div className="micro-copy"><span>🔒</span> AES-256-GCM + encrypted metadata</div><button className="primary-btn" disabled={isUploading || !selectedFile}>{isUploading ? "Encrypting & uploading…" : "Encrypt & upload"}</button></div>
                    </form>
                    {uploadResult && <div className="result-strip"><span>✓</span><div><strong>Ciphertext accepted by server</strong><small>GridFS object created · cryptographic version {uploadResult.file?.keyVersion ?? 1} · plaintext not transmitted</small></div></div>}
                  </div>

                  <div className="panel-card files-panel" id="files">
                    <div className="panel-heading"><div><div className="section-kicker">Private vault</div><h2>Your encrypted files</h2><p>File references are visible; sensitive metadata remains encrypted.</p></div><button className="outline-btn" onClick={loadFileList} disabled={isLoadingFiles}>{isLoadingFiles ? "Refreshing…" : "Refresh"}</button></div>
                    {fileListError && <div className="form-alert danger">{fileListError}</div>}
                    {downloadError && <div className="form-alert danger">{downloadError}</div>}
                    {downloadStatus && <div className="form-alert success">✓ {downloadStatus}</div>}
                    {isLoadingFiles && fileList.length === 0 && <div className="empty-state"><div className="loader" /><p>Loading encrypted files…</p></div>}
                    {!isLoadingFiles && fileList.length === 0 && !fileListError && <div className="empty-state"><div className="empty-icon">□</div><strong>Your vault is empty</strong><p>Upload your first file above. Its contents will be encrypted before leaving this device.</p></div>}
                    {fileList.length > 0 && <div className="file-table"><div className="file-row table-head"><span>Reference</span><span>Version</span><span>Uploaded</span><span>Status</span><span /></div>{fileList.map((file) => { const id = String(file.id); const busy = downloadingFileId === id; return <div className="file-row" key={id}><div className="file-ref"><span className="file-icon">□</span><div><strong>Encrypted file</strong><small>{id}</small></div></div><span>v{file.keyVersion}</span><span>{file.createdAt ? new Date(file.createdAt).toLocaleDateString() : "—"}</span><span><b className="status-dot" />Encrypted</span><button className="table-action" onClick={() => handleFileDownload(id)} disabled={downloadingFileId !== null || isUploading}>{busy ? "Decrypting…" : "Decrypt ↓"}</button></div>; })}</div>}
                    <div className="privacy-note"><span>⌁</span><div><strong>Metadata privacy</strong><p>Filenames, MIME types and original file contents are recovered only during browser-side decryption.</p></div></div>
                  </div>
                </div>

                <aside className="workspace-side">
                  <div className="panel-card crypto-panel" id="security"><div className="panel-heading"><div><div className="section-kicker">Security</div><h2>Session integrity</h2></div></div><div className="key-status"><div className="key-line"><span className="check">✓</span><div><strong>Master Key</strong><small>Recovered · 256-bit</small></div></div><div className="key-line"><span className="check">✓</span><div><strong>ML-KEM private key</strong><small>Recovered · 2400 bytes</small></div></div><div className="key-line"><span className="check">✓</span><div><strong>Browser persistence</strong><small>Disabled for cryptographic keys</small></div></div><div className="key-line"><span className="check">✓</span><div><strong>Authentication token</strong><small>Runtime memory only</small></div></div></div><div className="algorithm-box"><span>ACTIVE CRYPTOGRAPHY</span><strong>AES-256-GCM</strong><strong>ML-KEM-768</strong><small>PBKDF2-HMAC-SHA-256</small></div></div>
                  <div className="panel-card how-panel"><div className="section-kicker">How it works</div><h2>Privacy by design.</h2><div className="flow-step"><b>01</b><div><strong>Encrypt</strong><p>Browser creates a fresh file key and encrypts the file.</p></div></div><div className="flow-line" /><div className="flow-step"><b>02</b><div><strong>Store</strong><p>Cloud receives ciphertext and protected key material.</p></div></div><div className="flow-line" /><div className="flow-step"><b>03</b><div><strong>Decrypt</strong><p>Authorized browser recovers the plaintext locally.</p></div></div></div>
                </aside>
              </section>

              <section id="sharing" className="sharing-wrap"><SharingPanel fileList={fileList} authToken={authToken} currentUser={currentUser} runtimeKeys={runtimeKeys} apiBaseUrl={API_BASE_URL} /></section>
              <footer className="dashboard-footer"><span>QSZKFSS · Frozen V1</span><span>Client-side encryption · ML-KEM-768 · Browser-side decryption</span><span className="footer-live"><i /> Operational</span></footer>
            </div>
          </div>
        )}
      </main>
    </div>
  );
}

export default App;
