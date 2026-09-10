import { useEffect, useMemo, useState } from "react";
import { prepareRegistrationCrypto } from "./crypto/registrationCrypto.js";
import { recoverLoginKeys } from "./crypto/loginCrypto.js";
import { uploadEncryptedFile } from "./services/fileUploadService.js";
import { downloadAndDecryptFile } from "./services/fileDownloadService.js";
import SharingPanel from "./components/SharingPanel.jsx";

const MAX_FILE_SIZE = 100 * 1024 * 1024;
const NAV_ITEMS = [
  ["dashboard", "Dashboard", "⌂"],
  ["upload", "Upload", "↑"],
  ["files", "My Encrypted Files", "□"],
  ["sharing", "Sharing", "↗"],
  ["received", "Shared With Me", "⇩"],
  ["activity", "Activity Log", "◷"],
  ["security", "Security Center", "◇"],
  ["about", "About", "i"],
];

function formatBytes(bytes) {
  if (!Number.isFinite(bytes) || bytes < 0) return "—";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

function formatDate(value) {
  if (!value) return "—";
  return new Date(value).toLocaleString();
}

function App() {
  const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || "http://localhost:5000/api";
  const [backendOnline, setBackendOnline] = useState(false);
  const [backendMessage, setBackendMessage] = useState("Checking connection...");
  const [authView, setAuthView] = useState("login");
  const [page, setPage] = useState("dashboard");

  const [registerUsername, setRegisterUsername] = useState("");
  const [registerPassword, setRegisterPassword] = useState("");
  const [registerStatus, setRegisterStatus] = useState("");
  const [registerError, setRegisterError] = useState("");
  const [isRegistering, setIsRegistering] = useState(false);

  const [loginUsername, setLoginUsername] = useState("");
  const [loginPassword, setLoginPassword] = useState("");
  const [loginError, setLoginError] = useState("");
  const [isLoggingIn, setIsLoggingIn] = useState(false);

  const [authToken, setAuthToken] = useState(null);
  const [currentUser, setCurrentUser] = useState(null);
  const [runtimeKeys, setRuntimeKeys] = useState(null);

  const [selectedFile, setSelectedFile] = useState(null);
  const [uploadError, setUploadError] = useState("");
  const [uploadResult, setUploadResult] = useState(null);
  const [isUploading, setIsUploading] = useState(false);
  const [uploadSteps, setUploadSteps] = useState([]);

  const [fileList, setFileList] = useState([]);
  const [fileListError, setFileListError] = useState("");
  const [isLoadingFiles, setIsLoadingFiles] = useState(false);
  const [downloadingFileId, setDownloadingFileId] = useState(null);
  const [downloadError, setDownloadError] = useState("");
  const [downloadSteps, setDownloadSteps] = useState([]);

  const [activities, setActivities] = useState([]);

  const addActivity = (type, title, detail, status = "success") => {
    setActivities((current) => [
      {
        id: `${Date.now()}-${Math.random().toString(16).slice(2)}`,
        type,
        title,
        detail,
        status,
        createdAt: new Date().toISOString(),
      },
      ...current,
    ].slice(0, 100));
  };

  useEffect(() => {
    fetch(`${API_BASE_URL}/health`)
      .then(async (response) => {
        if (!response.ok) throw new Error("Backend returned an error.");
        return response.json();
      })
      .then((data) => {
        setBackendOnline(true);
        setBackendMessage(data.message || "Backend online");
      })
      .catch((err) => {
        setBackendOnline(false);
        setBackendMessage(err.message || "Backend unavailable");
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
      setRegisterStatus(`Account created for ${data.user.username}. Your protected key material was prepared in the browser.`);
      setRegisterUsername("");
      setRegisterPassword("");
      setAuthView("login");
      setLoginUsername(data.user.username);
    } catch (err) {
      setRegisterError(err.message || "Registration failed.");
    } finally {
      setIsRegistering(false);
    }
  }

  async function loadFileList(tokenOverride = null) {
    const token = tokenOverride || authToken;
    if (!token) return;
    setIsLoadingFiles(true);
    setFileListError("");
    try {
      const response = await fetch(`${API_BASE_URL}/files`, { headers: { Authorization: `Bearer ${token}` } });
      const data = await response.json();
      if (!response.ok) throw new Error(data.message || "Unable to load encrypted files.");
      setFileList(Array.isArray(data.files) ? data.files : []);
    } catch (err) {
      setFileList([]);
      setFileListError(err.message || "Unable to load encrypted files.");
    } finally {
      setIsLoadingFiles(false);
    }
  }

  async function handleLogin(event) {
    event.preventDefault();
    setLoginError("");
    setIsLoggingIn(true);
    try {
      const response = await fetch(`${API_BASE_URL}/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: loginUsername, password: loginPassword }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.message || "Login failed.");
      if (!data.authToken || !data.user) throw new Error("Authentication data was not returned by the server.");
      const recoveredKeys = await recoverLoginKeys({
        password: loginPassword,
        passwordKdfSalt: data.user.passwordKdfSalt,
        passwordKdfParams: data.user.passwordKdfParams,
        wrappedMasterKey: data.user.wrappedMasterKey,
        masterKeyIV: data.user.masterKeyIV,
        wrappedMlKemPrivateKey: data.user.wrappedMlKemPrivateKey,
        privateKeyIV: data.user.privateKeyIV,
      });
      setAuthToken(data.authToken);
      setRuntimeKeys(recoveredKeys);
      setCurrentUser({ id: data.user.id, username: data.user.username, mlKemPublicKey: data.user.mlKemPublicKey });
      setLoginPassword("");
      setPage("dashboard");
      setActivities([]);
      addActivity("AUTH", "Secure session established", "Master Key and ML-KEM private key recovered into browser memory.");
      await loadFileList(data.authToken);
    } catch (err) {
      setAuthToken(null);
      setRuntimeKeys(null);
      setCurrentUser(null);
      setLoginError(err.message || "Login failed.");
    } finally {
      setIsLoggingIn(false);
    }
  }

  function handleFileSelect(event) {
    const file = event.target.files?.[0] || null;
    setUploadError("");
    setUploadResult(null);
    setUploadSteps([]);
    if (file?.size > MAX_FILE_SIZE) {
      setSelectedFile(null);
      setUploadError("File exceeds the V1 maximum size of 100 MB.");
      event.target.value = "";
      return;
    }
    setSelectedFile(file);
  }

  async function handleFileUpload(event) {
    event.preventDefault();
    setUploadError("");
    setUploadResult(null);
    setUploadSteps([]);
    if (!selectedFile) return setUploadError("Please select a file first.");
    if (!authToken || !runtimeKeys?.masterKey) return setUploadError("Authenticated cryptographic session is unavailable.");
    setIsUploading(true);
    try {
      const result = await uploadEncryptedFile({
        file: selectedFile,
        masterKey: runtimeKeys.masterKey,
        authToken,
        apiBaseUrl: API_BASE_URL,
        onProgress: (step) => setUploadSteps((current) => [...current, step]),
      });
      setUploadResult(result);
      addActivity("UPLOAD", "Encrypted file uploaded", `${selectedFile.name} · ${formatBytes(selectedFile.size)} · ciphertext stored in GridFS`);
      setSelectedFile(null);
      const input = document.getElementById("fileUpload");
      if (input) input.value = "";
      await loadFileList();
    } catch (err) {
      setUploadError(err.message || "Encrypted file upload failed.");
      addActivity("UPLOAD", "Encrypted upload failed", err.message || "The secure upload operation failed.", "failed");
    } finally {
      setIsUploading(false);
    }
  }

  async function handleFileDownload(fileId) {
    setDownloadError("");
    setDownloadSteps([]);
    if (!authToken || !runtimeKeys?.masterKey) return setDownloadError("Authenticated cryptographic session is unavailable.");
    setDownloadingFileId(fileId);
    try {
      const result = await downloadAndDecryptFile({
        fileId,
        authToken,
        masterKey: runtimeKeys.masterKey,
        apiBaseUrl: API_BASE_URL,
        onProgress: (step) => setDownloadSteps((current) => [...current, step]),
      });
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
      addActivity("DOWNLOAD", "File decrypted locally", `${result.metadata.name} · plaintext reconstructed in the browser`);
    } catch (err) {
      setDownloadError(err.message || "File download and decryption failed.");
      addActivity("DOWNLOAD", "Secure download failed", err.message || "The secure download operation failed.", "failed");
    } finally {
      setDownloadingFileId(null);
    }
  }

  function handleLogout() {
    setAuthToken(null);
    setRuntimeKeys(null);
    setCurrentUser(null);
    setLoginPassword("");
    setSelectedFile(null);
    setFileList([]);
    setUploadSteps([]);
    setDownloadSteps([]);
    setPage("dashboard");
  }

  const loggedIn = Boolean(currentUser);
  const recentActivities = activities.slice(0, 5);
  const successCount = useMemo(() => activities.filter((item) => item.status === "success").length, [activities]);

  if (!loggedIn) {
    return (
      <div className="auth-shell">
        <div className="auth-noise" />
        <div className="auth-layout">
          <section className="auth-brand-panel">
            <div className="brand-lockup"><span className="brand-symbol"><span /></span><div><strong>QSZKFSS</strong><small>QUANTUM SAFE FILE SHARING</small></div></div>
            <div className="auth-hero">
              <span className="eyebrow"><i /> Browser-first security</span>
              <h1>Private files.<br /><em>Protected keys.</em></h1>
              <p>A quantum-safe file sharing workspace where files are encrypted before they leave your browser.</p>
            </div>
            <div className="auth-principles">
              <div><b>01</b><strong>AES-256-GCM</strong><span>Client-side file encryption</span></div>
              <div><b>02</b><strong>ML-KEM-768</strong><span>Post-quantum key establishment</span></div>
              <div><b>03</b><strong>Provider-blind</strong><span>Plaintext stays out of the cloud</span></div>
            </div>
            <div className="auth-footer"><span><i className={backendOnline ? "live" : ""} /> {backendOnline ? "Backend operational" : "Connecting to backend"}</span><span>QSZKFSS · V1</span></div>
          </section>
          <section className="auth-form-panel">
            <div className="mobile-brand"><span className="brand-symbol"><span /></span><strong>QSZKFSS</strong></div>
            {authView === "login" ? (
              <div className="auth-form-wrap">
                <div className="form-heading"><span className="section-kicker">Secure access</span><h2>Welcome back.</h2><p>Sign in to recover your protected cryptographic session.</p></div>
                <form onSubmit={handleLogin} className="modern-form">
                  <label>Username<input value={loginUsername} onChange={(e) => setLoginUsername(e.target.value)} placeholder="your username" autoComplete="username" required minLength={3} maxLength={50} /></label>
                  <label>Password<input type="password" value={loginPassword} onChange={(e) => setLoginPassword(e.target.value)} placeholder="Your account password" autoComplete="current-password" required minLength={8} maxLength={128} /></label>
                  {loginError && <div className="form-alert danger">{loginError}</div>}
                  {registerStatus && <div className="form-alert success">✓ {registerStatus}</div>}
                  <button className="primary-btn wide" disabled={isLoggingIn}>{isLoggingIn ? "Establishing secure session…" : "Sign in securely →"}</button>
                </form>
                <div className="auth-switch">Don't have an account? <button onClick={() => { setAuthView("register"); setRegisterStatus(""); setLoginError(""); }}>Create one</button></div>
                <div className="auth-assurance"><span>◇</span><div><strong>Your keys stay in runtime memory</strong><p>Cryptographic keys are not persisted in browser storage.</p></div></div>
              </div>
            ) : (
              <div className="auth-form-wrap">
                <div className="form-heading"><span className="section-kicker">New protected identity</span><h2>Create your account.</h2><p>Your Master Key and ML-KEM private key are generated and protected in the browser.</p></div>
                <form onSubmit={handleRegister} className="modern-form">
                  <label>Username<input value={registerUsername} onChange={(e) => setRegisterUsername(e.target.value)} placeholder="choose a username" autoComplete="username" required minLength={3} maxLength={50} /></label>
                  <label>Password<input type="password" value={registerPassword} onChange={(e) => setRegisterPassword(e.target.value)} placeholder="At least 8 characters" autoComplete="new-password" required minLength={8} maxLength={128} /></label>
                  {registerError && <div className="form-alert danger">{registerError}</div>}
                  <button className="primary-btn wide" disabled={isRegistering}>{isRegistering ? "Creating protected account…" : "Create account →"}</button>
                </form>
                <div className="auth-switch">Already registered? <button onClick={() => { setAuthView("login"); setRegisterError(""); }}>Sign in</button></div>
                <div className="auth-assurance"><span>✓</span><div><strong>Protection starts in the browser</strong><p>PBKDF2-HMAC-SHA-256, AES-GCM and ML-KEM-768 are used by V1.</p></div></div>
              </div>
            )}
          </section>
        </div>
      </div>
    );
  }

  const go = (next) => setPage(next);
  const pageTitle = NAV_ITEMS.find(([id]) => id === page)?.[1] || "Dashboard";

  return (
    <div className="product-shell">
      <aside className="sidebar">
        <div className="sidebar-brand"><span className="brand-symbol"><span /></span><div><strong>QSZKFSS</strong><small>QUANTUM SAFE</small></div></div>
        <div className="nav-caption">Workspace</div>
        <nav>{NAV_ITEMS.slice(0, 6).map(([id, label, icon]) => <button key={id} className={page === id ? "active" : ""} onClick={() => go(id)}><span>{icon}</span>{label}{id === "activity" && activities.length > 0 ? <b>{activities.length}</b> : null}</button>)}</nav>
        <div className="nav-caption lower">System</div>
        <nav>{NAV_ITEMS.slice(6).map(([id, label, icon]) => <button key={id} className={page === id ? "active" : ""} onClick={() => go(id)}><span>{icon}</span>{label}</button>)}</nav>
        <div className="sidebar-bottom"><div className="sidebar-status"><i className={backendOnline ? "live" : ""} /><div><strong>{backendOnline ? "System operational" : "Backend unavailable"}</strong><small>{backendOnline ? "Secure API connection" : backendMessage}</small></div></div><button className="sidebar-user" onClick={handleLogout}><span>{currentUser.username.slice(0, 1).toUpperCase()}</span><div><strong>{currentUser.username}</strong><small>Sign out</small></div><b>↪</b></button></div>
      </aside>

      <main className="main-content">
        <header className="content-topbar"><div><span className="breadcrumb">QSZKFSS <b>/</b> {pageTitle}</span><h1>{pageTitle}</h1></div><div className="topbar-security"><span className="secure-dot" /> Protected session <b>AES-256-GCM</b><b>ML-KEM-768</b></div></header>

        {page === "dashboard" && <Dashboard currentUser={currentUser} fileList={fileList} activities={recentActivities} successCount={successCount} backendOnline={backendOnline} onNavigate={go} />}
        {page === "upload" && <UploadPage selectedFile={selectedFile} handleFileSelect={handleFileSelect} handleFileUpload={handleFileUpload} isUploading={isUploading} uploadError={uploadError} uploadResult={uploadResult} steps={uploadSteps} />}
        {page === "files" && <FilesPage fileList={fileList} loadFileList={loadFileList} isLoadingFiles={isLoadingFiles} fileListError={fileListError} downloadError={downloadError} steps={downloadSteps} downloadingFileId={downloadingFileId} onDownload={handleFileDownload} onShare={() => go("sharing")} />}
        {page === "sharing" && <SharingPanel section="sharing" fileList={fileList} authToken={authToken} currentUser={currentUser} runtimeKeys={runtimeKeys} apiBaseUrl={API_BASE_URL} onActivity={addActivity} />}
        {page === "received" && <SharingPanel section="received" fileList={fileList} authToken={authToken} currentUser={currentUser} runtimeKeys={runtimeKeys} apiBaseUrl={API_BASE_URL} onActivity={addActivity} />}
        {page === "activity" && <ActivityPage activities={activities} />}
        {page === "security" && <SecurityPage currentUser={currentUser} runtimeKeys={runtimeKeys} backendOnline={backendOnline} />}
        {page === "about" && <AboutPage />}
      </main>
    </div>
  );
}

function Dashboard({ currentUser, fileList, activities, successCount, backendOnline, onNavigate }) {
  return <div className="page-body">
    <section className="welcome-row"><div><span className="eyebrow"><i /> Secure session active</span><h2>Good to see you, <em>{currentUser.username}</em>.</h2><p>Your encrypted workspace is ready. Sensitive cryptographic material exists only in this browser session.</p></div><div className="posture-card"><span>SECURITY POSTURE</span><strong><i /> Protected</strong><small>Browser-side cryptography active</small></div></section>
    <section className="stat-grid"><Stat icon="□" value={fileList.length} label="Encrypted files" /><Stat icon="◇" value="ML-KEM" label="Post-quantum sharing" /><Stat icon="⌁" value="Runtime" label="Keys not persisted" /><Stat icon="✓" value={backendOnline ? "Online" : "Offline"} label="Backend status" /></section>
    <section className="dashboard-grid">
      <div className="dashboard-main">
        <div className="feature-banner"><div className="feature-icon">◇</div><div><span>PROVIDER-BLIND PROTECTION</span><h3>Plaintext never needs to reach the cloud.</h3><p>Files are encrypted in the browser. The server receives ciphertext, encrypted metadata and protected key material.</p></div><button onClick={() => onNavigate("security")}>Security Center →</button></div>
        <div className="section-card"><div className="card-heading"><div><span className="section-kicker">Encrypted vault</span><h3>Recent files</h3></div><button className="text-btn" onClick={() => onNavigate("files")}>View all →</button></div>{fileList.length === 0 ? <Empty icon="□" title="Your encrypted vault is empty" text="Upload your first file to create a client-side encrypted object." action="Upload a file" onClick={() => onNavigate("upload")} /> : <div className="mini-file-list">{fileList.slice(0, 5).map((file) => <div className="mini-file" key={String(file.id)}><span className="file-tile">□</span><div><strong>Encrypted file</strong><small>{String(file.id)}</small></div><span>v{file.keyVersion || 1}</span><button onClick={() => onNavigate("files")}>Open</button></div>)}</div>}</div>
      </div>
      <aside className="dashboard-side"><div className="section-card activity-preview"><div className="card-heading"><div><span className="section-kicker">Audit view</span><h3>Recent activity</h3></div><button className="text-btn" onClick={() => onNavigate("activity")}>View all →</button></div>{activities.length === 0 ? <Empty icon="◷" title="No activity yet" text="Secure operations will appear here as you use the workspace." /> : activities.map((item) => <ActivityItem key={item.id} item={item} />)}</div><div className="section-card quick-card"><span className="section-kicker">Quick action</span><h3>Protect a new file.</h3><p>Encryption, metadata protection and upload happen as one secure operation.</p><button className="primary-btn" onClick={() => onNavigate("upload")}>Start secure upload →</button></div></aside>
    </section>
    <div className="page-note"><span>◇</span><p><strong>V1 security boundary:</strong> the system is provider-blind with respect to file plaintext and plaintext file-decryption keys; operational metadata such as IDs, authorization data and timestamps remains visible to the backend.</p></div>
  </div>;
}

function Stat({ icon, value, label }) { return <div className="stat-card"><span>{icon}</span><div><strong>{value}</strong><small>{label}</small></div></div>; }

function UploadPage({ selectedFile, handleFileSelect, handleFileUpload, isUploading, uploadError, uploadResult, steps }) {
  const stages = [
    ["key", "Generate fresh file encryption key"],
    ["encrypt", "Encrypt file with AES-256-GCM"],
    ["metadata", "Encrypt file metadata"],
    ["protect-meta", "Protect metadata key"],
    ["protect-fek", "Protect owner file key"],
    ["package", "Prepare encrypted package"],
    ["upload", "Upload ciphertext to server"],
    ["gridfs", "Store encrypted data in GridFS"],
  ];
  const completed = new Set(steps.map((step) => step.id));
  return <div className="page-body narrow-body"><div className="page-intro"><span className="section-kicker">Client-side protection</span><h2>Encrypt a new file.</h2><p>Choose a file and the browser will perform the cryptographic operations before the encrypted package is sent to the backend.</p></div><div className="operation-layout"><section className="section-card upload-card"><div className="drop-zone-large"><input id="fileUpload" type="file" onChange={handleFileSelect} disabled={isUploading} /><div className="upload-orb">↑</div><strong>{selectedFile ? selectedFile.name : "Choose a file"}</strong><span>{selectedFile ? `${formatBytes(selectedFile.size)} · ${selectedFile.type || "application/octet-stream"}` : "Click to browse · maximum 100 MB"}</span><label htmlFor="fileUpload">Browse files</label></div>{uploadError && <div className="form-alert danger">{uploadError}</div>}<div className="upload-submit"><div><strong>Ready for secure upload</strong><small>AES-256-GCM · encrypted metadata · protected FEK</small></div><button className="primary-btn" onClick={handleFileUpload} disabled={isUploading || !selectedFile}>{isUploading ? "Processing secure upload…" : "Encrypt & upload →"}</button></div>{uploadResult && <div className="success-card"><span>✓</span><div><strong>Secure upload complete</strong><p>Ciphertext accepted by the server and stored in MongoDB GridFS. Plaintext was not transmitted.</p></div></div>}</section><OperationPanel title="Secure Upload" subtitle={selectedFile ? selectedFile.name : "Operation pipeline"} stages={stages} completed={completed} active={isUploading} /></div></div>;
}

function OperationPanel({ title, subtitle, stages, completed, active }) { return <section className="operation-card"><div className="operation-head"><span className="operation-live"><i className={active ? "pulse" : ""} /> {active ? "Processing" : "Secure Activity"}</span><strong>{title}</strong><small>{subtitle}</small></div><div className="pipeline">{stages.map(([id, label], index) => { const done = completed.has(id); const last = index === stages.length - 1; return <div className={`pipeline-step ${done ? "done" : ""} ${!done && active ? "pending" : ""}`} key={id}><span>{done ? "✓" : String(index + 1).padStart(2, "0")}</span><div><strong>{label}</strong><small>{done ? "Completed" : active ? "Waiting for this stage" : "Ready"}</small></div>{!last && <i className={done ? "connector done" : "connector"} />}</div>; })}</div><div className="operation-foot">◇ <span>Cryptographic operations execute in the browser unless explicitly marked as server/storage activity.</span></div></section>; }

function FilesPage({ fileList, loadFileList, isLoadingFiles, fileListError, downloadError, steps, downloadingFileId, onDownload, onShare }) {
  return <div className="page-body"><div className="page-intro inline"><div><span className="section-kicker">Private vault</span><h2>My encrypted files.</h2><p>Cloud-visible references are separated from the protected file contents and metadata.</p></div><button className="outline-btn" onClick={() => loadFileList()} disabled={isLoadingFiles}>{isLoadingFiles ? "Refreshing…" : "Refresh vault"}</button></div>{fileListError && <div className="form-alert danger">{fileListError}</div>}{downloadError && <div className="form-alert danger">{downloadError}</div>}<section className="section-card vault-card">{isLoadingFiles && fileList.length === 0 ? <div className="empty-state"><div className="loader" /><p>Loading encrypted files…</p></div> : fileList.length === 0 ? <Empty icon="□" title="Your vault is empty" text="Upload a file to create your first encrypted object." /> : <div className="vault-list">{fileList.map((file) => { const id = String(file.id); const busy = downloadingFileId === id; return <div className="vault-row" key={id}><div className="vault-file-icon">□</div><div className="vault-file"><strong>Encrypted file</strong><small>{id}</small></div><div className="vault-meta"><span>KEY VERSION</span><strong>V{file.keyVersion || 1}</strong></div><div className="vault-meta"><span>CREATED</span><strong>{file.createdAt ? new Date(file.createdAt).toLocaleDateString() : "—"}</strong></div><div className="vault-status"><i /> Protected</div><div className="vault-actions"><button onClick={() => onShare()}>Share</button><button onClick={() => onDownload(id)} disabled={downloadingFileId !== null}>{busy ? "Decrypting…" : "Decrypt ↓"}</button></div></div>; })}</div>}<div className="vault-note"><span>◇</span><div><strong>Protected metadata</strong><p>Filenames, MIME types and original sizes are recovered through browser-side metadata decryption.</p></div></div></section>{(steps.length > 0 || downloadingFileId) && <section className="section-card compact-operation"><div className="compact-head"><span className="section-kicker">Secure Download</span><strong>{downloadingFileId ? "Decrypting encrypted package…" : "Last download operation"}</strong></div><div className="compact-steps">{["Authenticated access verified", "Encrypted file retrieved", "Protected FEK recovered", "Owner FEK unwrapped locally", "Encrypted metadata recovered", "Metadata decrypted locally", "File decrypted with AES-256-GCM", "Original file reconstructed"].map((label, i) => <span className={steps[i] ? "done" : ""} key={label}>{steps[i] ? "✓" : String(i + 1).padStart(2, "0")} {label}</span>)}</div></section>}</div>;
}

function ActivityPage({ activities }) { return <div className="page-body"><div className="page-intro"><span className="section-kicker">Session history</span><h2>Activity log.</h2><p>A local, in-session history of meaningful application and security operations. Sensitive cryptographic secrets are never recorded here.</p></div><section className="section-card activity-card">{activities.length === 0 ? <Empty icon="◷" title="No activity recorded" text="Upload, download, share or revoke a file to build the session activity history." /> : <div className="activity-list">{activities.map((item) => <ActivityItem key={item.id} item={item} expanded />)}</div>}<div className="activity-disclaimer"><strong>Privacy boundary</strong><span>This activity history lives in the current browser session. It does not store passwords, plaintext keys, FEKs, ML-KEM private keys or file contents.</span></div></section></div>; }

function ActivityItem({ item, expanded = false }) { return <div className={`activity-item ${item.status}`}><span className="activity-icon">{item.type === "UPLOAD" ? "↑" : item.type === "DOWNLOAD" ? "⇩" : item.type === "SHARE" ? "↗" : item.type === "REVOKE" ? "×" : "◇"}</span><div className="activity-copy"><strong>{item.title}</strong><span>{item.detail}</span>{expanded && <small>{formatDate(item.createdAt)}</small>}</div><time>{new Date(item.createdAt).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}</time></div>; }

function SecurityPage({ currentUser, runtimeKeys, backendOnline }) { return <div className="page-body"><div className="page-intro"><span className="section-kicker">Security Center</span><h2>Understand the protection.</h2><p>The current V1 security model, active runtime state and trust boundaries in one place.</p></div><div className="security-grid"><section className="section-card security-overview"><div className="security-score"><span>SESSION SECURITY</span><strong><i /> Protected</strong><small>{currentUser.username} · {backendOnline ? "Backend reachable" : "Backend unavailable"}</small></div><div className="security-lines"><SecurityLine title="Master Key" value={runtimeKeys?.masterKey instanceof Uint8Array ? "Recovered · 256-bit" : "Unavailable"} /><SecurityLine title="ML-KEM private key" value={runtimeKeys?.mlKemPrivateKey instanceof Uint8Array ? "Recovered · 2400 bytes" : "Unavailable"} /><SecurityLine title="Browser persistence" value="Cryptographic keys not persisted" /><SecurityLine title="Authentication token" value="Runtime memory only" /><SecurityLine title="Transport" value="HTTPS / TLS deployment" /></div></section><section className="section-card crypto-stack"><span className="section-kicker">Cryptographic stack</span><h3>V1 mechanisms</h3><div className="crypto-box"><b>AES-256-GCM</b><span>File encryption + metadata encryption</span></div><div className="crypto-box"><b>ML-KEM-768</b><span>Post-quantum key establishment for sharing</span></div><div className="crypto-box"><b>PBKDF2-HMAC-SHA-256</b><span>Password-based key derivation</span></div><div className="crypto-box"><b>HKDF-SHA-256</b><span>Key separation and sharing-key derivation</span></div></section></div><div className="security-grid lower-security"><section className="section-card"><span className="section-kicker">Key architecture</span><h3>Keys have separate jobs.</h3><div className="arch-flow"><div>Password</div><i>↓</i><div>PBKDF2 → KEK</div><i>↓</i><div>Wrapped Master Key</div><i>↓</i><div className="arch-split"><span>FEK protection</span><span>Metadata protection</span><span>ML-KEM private key</span></div></div></section><section className="section-card"><span className="section-kicker">Trust model</span><h3>What each layer can know.</h3><ul className="trust-list"><li><b>Browser</b><span>Plaintext files, passwords and runtime private keys.</span></li><li><b>Backend</b><span>Authentication, authorization and operational identifiers.</span></li><li><b>MongoDB Atlas</b><span>Encrypted files, encrypted metadata and protected key material.</span></li><li><b>Network</b><span>Protected by HTTPS/TLS transport.</span></li></ul></section></div><div className="limitation-banner"><strong>Important V1 boundary</strong><p>“Zero knowledge” here means provider-blind protection of file plaintext and plaintext file-decryption keys. It is not a claim of formal zero-knowledge proofs, complete metadata hiding or a malicious-server-resistant identity system.</p></div></div>; }
function SecurityLine({ title, value }) { return <div className="security-line"><span>✓</span><div><strong>{title}</strong><small>{value}</small></div></div>; }

function AboutPage() { return <div className="page-body about-page"><div className="about-hero"><span className="section-kicker">About QSZKFSS</span><h2>Quantum Safe Zero Knowledge<br /><em>File Sharing System.</em></h2><p>A browser-first secure file sharing application designed to keep file plaintext and plaintext file-decryption keys away from the storage provider while using post-quantum key establishment for recipient sharing.</p></div><div className="about-grid"><AboutSection title="Project objective"><p>QSZKFSS encrypts files before they leave the user's browser and stores only encrypted/protected material on the backend and MongoDB Atlas. Authorized recipients recover and decrypt files locally.</p></AboutSection><AboutSection title="How a file is protected"><p>Every file receives a fresh random 256-bit File Encryption Key (FEK). AES-256-GCM encrypts the file. Sensitive metadata receives a separate random metadata key and is encrypted independently.</p></AboutSection><AboutSection title="Master Key model"><p>A random 256-bit Master Key is generated in the browser. The password is processed with PBKDF2-HMAC-SHA-256 to derive a KEK, which protects the Master Key with AES-GCM. The Master Key then derives dedicated wrapping keys through HKDF-based key separation.</p></AboutSection><AboutSection title="Post-quantum sharing"><p>Sharing uses ML-KEM-768. The sender encapsulates to the recipient's public key, derives a wrapping key from the shared secret with HKDF-SHA-256 and uses it to protect the file key for that recipient. ML-KEM is used for key establishment, not for encrypting the file itself.</p></AboutSection><AboutSection title="Storage model"><p>MongoDB Atlas stores application records and MongoDB GridFS stores encrypted file ciphertext. The server does not receive the plaintext file or an unwrapped FEK during normal V1 operations.</p></AboutSection><AboutSection title="Revocation"><p>Revoking a share disables future access through that share record. It cannot erase plaintext that a recipient already downloaded.</p></AboutSection><AboutSection title="Technology stack"><div className="tech-grid"><span>React + Vite</span><span>Bootstrap 5</span><span>Node.js + Express</span><span>MongoDB Atlas</span><span>MongoDB GridFS</span><span>Web Crypto API</span><span>@noble/post-quantum</span><span>HTTPS / TLS</span></div></AboutSection><AboutSection title="V1 scope & limitations"><p>V1 intentionally does not include formal zero-knowledge proofs, searchable encryption, password recovery for encrypted data, multi-device key synchronization, complex key rotation, ML-DSA signatures, hybrid KEM schemes or protection against a compromised endpoint/browser.</p></AboutSection></div><div className="about-footer-card"><span>QSZKFSS · FROZEN V1</span><strong>Designed around browser-side cryptography and provider-blind file storage.</strong><small>Operational metadata such as account IDs, authorization information, recipient identifiers, file/access IDs and timestamps can remain visible to the backend.</small></div></div>; }
function AboutSection({ title, children }) { return <section className="section-card about-section"><span className="section-kicker">{title}</span><h3>{title}</h3>{children}</section>; }
function Empty({ icon, title, text, action, onClick }) { return <div className="empty-state"><div className="empty-icon">{icon}</div><strong>{title}</strong><p>{text}</p>{action && <button className="outline-btn" onClick={onClick}>{action}</button>}</div>; }

export default App;
