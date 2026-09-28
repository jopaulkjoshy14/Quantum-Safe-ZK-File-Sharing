import { useEffect, useState } from "react";
import { prepareRegistrationCrypto } from "./crypto/registrationCrypto.js";
import { recoverLoginKeys } from "./crypto/loginCrypto.js";
import { uploadEncryptedFile } from "./services/fileUploadService.js";
import { downloadAndDecryptFile } from "./services/fileDownloadService.js";
import SharingPanel from "./components/SharingPanel.jsx";
import OperationPanel from "./components/OperationPanel.jsx";
import Icon from "./components/Icon.jsx";
import VaultArtwork from "./components/VaultArtwork.jsx";

const MAX_FILE_SIZE = 100 * 1024 * 1024;
const NAV_ITEMS = [
  ["dashboard", "Overview", "home"],
  ["upload", "Upload", "upload"],
  ["files", "My files", "folder"],
  ["sharing", "Sharing", "share"],
  ["received", "Shared with me", "download"],
  ["activity", "Activity", "clock"],
  ["security", "Security", "shield"],
  ["about", "About", "info"],
];

function formatDisplayUsername(username) {
  if (!username) return "";
  return username.charAt(0).toUpperCase() + username.slice(1);
}

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
      setRegisterStatus(`Account created for ${data.user.username}. Sign in to continue.`);
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
    setRegisterStatus("");
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
      addActivity("AUTH", "Signed in", "Your workspace is ready.");
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
      setUploadError("Choose a file no larger than 100 MB.");
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
    if (!authToken || !runtimeKeys?.masterKey) return setUploadError("Your session is unavailable. Sign in again.");
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
      addActivity("UPLOAD", "File uploaded", `${selectedFile.name} · ${formatBytes(selectedFile.size)}`);
      setSelectedFile(null);
      const input = document.getElementById("fileUpload");
      if (input) input.value = "";
      await loadFileList();
    } catch (err) {
      setUploadError(err.message || "Unable to upload your file. Try again.");
      addActivity("UPLOAD", "Upload couldn't finish", err.message || "Try uploading the file again.", "failed");
    } finally {
      setIsUploading(false);
    }
  }

  async function handleFileDownload(fileId) {
    setDownloadError("");
    setDownloadSteps([]);
    if (!authToken || !runtimeKeys?.masterKey) return setDownloadError("Your session is unavailable. Sign in again.");
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
      addActivity("DOWNLOAD", "File downloaded", result.metadata.name);
    } catch (err) {
      setDownloadError(err.message || "Unable to download your file. Try again.");
      addActivity("DOWNLOAD", "Download couldn't finish", err.message || "Try downloading the file again.", "failed");
    } finally {
      setDownloadingFileId(null);
    }
  }

  function handleLogout() {
    setAuthToken(null);
    setRuntimeKeys(null);
    setCurrentUser(null);
    setLoginPassword("");
    setLoginError("");
    setRegisterError("");
    setRegisterStatus("");
    setSelectedFile(null);
    setUploadError("");
    setUploadResult(null);
    setFileList([]);
    setFileListError("");
    setDownloadError("");
    setUploadSteps([]);
    setDownloadSteps([]);
    setActivities([]);
    setAuthView("login");
    setPage("dashboard");
  }

  const loggedIn = Boolean(currentUser);
  const recentActivities = activities.slice(0, 5);

  if (!loggedIn) {
    const isLogin = authView === "login";
    const busy = isLogin ? isLoggingIn : isRegistering;
    return (
      <div className="auth-shell">
        <div className="auth-layout">
          <section className="auth-brand-panel">
            <Brand className="brand-lockup" />
            <div className="auth-hero">
              <span className="eyebrow">A little more peace of mind</span>
              <h1>Your files.<br />Your people.<br /><em>Your privacy.</em></h1>
              <p>Store securely. Share simply.</p>
              <VaultArtwork />
            </div>
            <div className="auth-principles">
              <span><Icon name="upload" /> Upload</span>
              <span><Icon name="share" /> Share</span>
              <span><Icon name="download" /> Download</span>
            </div>
            <div className="auth-footer"><span><i className={backendOnline ? "live" : ""} />{backendOnline ? "Connected" : backendMessage === "Checking connection..." ? "Connecting…" : "Connection unavailable"}</span><span>Made for your privacy</span></div>
          </section>
          <section className="auth-form-panel">
            <Brand className="mobile-brand" />
            <div className="auth-form-wrap">
              <span className="auth-greeting"><Icon name={isLogin ? "lock" : "plus"} /> Your private workspace</span>
              <div className="form-heading">
                <h2>{isLogin ? "Welcome back." : "Let's get you started."}</h2>
                <p>{isLogin ? "Sign in to get back to your files." : "Create an account to upload and share privately."}</p>
              </div>
              <form onSubmit={isLogin ? handleLogin : handleRegister} className="modern-form">
                <label>Username
                  <input value={isLogin ? loginUsername : registerUsername} onChange={(event) => {
                    if (isLogin) { setLoginUsername(event.target.value); setLoginError(""); setRegisterStatus(""); }
                    else { setRegisterUsername(event.target.value); setRegisterError(""); }
                  }} placeholder={isLogin ? "Enter your username" : "Choose a username"} autoComplete="username" required minLength={3} maxLength={50} disabled={busy} />
                </label>
                <label>Password
                  <input type="password" value={isLogin ? loginPassword : registerPassword} onChange={(event) => {
                    if (isLogin) { setLoginPassword(event.target.value); setLoginError(""); setRegisterStatus(""); }
                    else { setRegisterPassword(event.target.value); setRegisterError(""); }
                  }} placeholder={isLogin ? "Enter your password" : "At least 8 characters"} autoComplete={isLogin ? "current-password" : "new-password"} required minLength={8} maxLength={128} disabled={busy} />
                </label>
                {(isLogin ? loginError : registerError) && <div className="form-alert danger" role="alert">{isLogin ? loginError : registerError}</div>}
                {isLogin && registerStatus && <div className="form-alert success" role="status">{registerStatus}</div>}
                <button className="primary-btn wide" disabled={busy}>{busy ? isLogin ? "Signing in…" : "Creating your account…" : isLogin ? "Sign in" : "Create account"}<Icon name="arrow" /></button>
              </form>
              <div className="auth-switch">
                {isLogin ? "New here?" : "Already have an account?"}
                <button disabled={busy} onClick={() => { setAuthView(isLogin ? "register" : "login"); setRegisterStatus(""); setLoginError(""); setRegisterError(""); }}>{isLogin ? "Create an account" : "Sign in"}</button>
              </div>
              <div className="auth-assurance"><Icon name="shield" /><span>Your files are encrypted in your browser.</span></div>
            </div>
          </section>
        </div>
      </div>
    );
  }

  const go = (next) => setPage(next);
  const pageTitle = NAV_ITEMS.find(([id]) => id === page)?.[1] || "Overview";
  return (
    <div className="product-shell">
      <aside className="sidebar">
        <Brand className="sidebar-brand" />
        <div className="nav-caption">Your workspace</div>
        <nav aria-label="Workspace">{NAV_ITEMS.slice(0, 6).map(([id, label, icon]) => (
          <button key={id} className={page === id ? "active" : ""} aria-current={page === id ? "page" : undefined} onClick={() => go(id)}>
            <Icon name={icon} /><span>{label}</span>{id === "activity" && activities.length > 0 && <b>{activities.length}</b>}
          </button>
        ))}</nav>
        <div className="nav-caption lower">Good to know</div>
        <nav aria-label="System">{NAV_ITEMS.slice(6).map(([id, label, icon]) => (
          <button key={id} className={page === id ? "active" : ""} aria-current={page === id ? "page" : undefined} onClick={() => go(id)}><Icon name={icon} /><span>{label}</span></button>
        ))}</nav>
        <div className="sidebar-bottom">
          <div className="sidebar-status"><i className={backendOnline ? "live" : ""} /><span>{backendOnline ? "Connected to your workspace" : "Connection unavailable"}</span></div>
          <button className="sidebar-user" onClick={handleLogout}><span className="user-avatar">{currentUser.username.slice(0, 1).toUpperCase()}</span><div><strong>{formatDisplayUsername(currentUser.username)}</strong><small>Sign out</small></div><Icon name="logout" /></button>
        </div>
      </aside>
      <main className="main-content">
        <header className="content-topbar"><div><span className="breadcrumb">Workspace <span>/</span> {pageTitle}</span><h1>{pageTitle}</h1></div><div className="topbar-security"><Icon name="shield" /> Encrypted workspace</div></header>
        {page === "dashboard" && <Dashboard currentUser={currentUser} fileList={fileList} activities={recentActivities} backendOnline={backendOnline} onNavigate={go} />}
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

function Brand({ className }) {
  return <div className={className}><span className="brand-symbol"><Icon name="shield" /></span><div><strong>QSZKFSS</strong><small>Private file sharing</small></div></div>;
}

function Dashboard({ currentUser, fileList, activities, backendOnline, onNavigate }) {
  return (
    <div className="page-body">
      <section className="welcome-banner">
        <div className="welcome-copy">
          <span className="eyebrow"><Icon name="shield" /> Your private workspace</span>
          <h2>Hi, {formatDisplayUsername(currentUser.username)}.</h2>
          <p>A little space for the files that matter.</p>
          <div className="welcome-actions">
            <button className="primary-btn" onClick={() => onNavigate("upload")}><Icon name="plus" /> Upload a file</button>
            <button className="outline-btn" onClick={() => onNavigate("sharing")}><Icon name="share" /> Share a file</button>
          </div>
        </div>
        <VaultArtwork />
      </section>
      <section className="stat-grid">
        <Stat icon="folder" value={fileList.length} label="Files in your vault" tone="indigo" />
        <Stat icon="clock" value={activities.length} label="Recent actions" tone="amber" />
        <Stat icon="shield" value="Encrypted" label="File storage" tone="teal" />
        <Stat icon="cloud" value={backendOnline ? "Online" : "Offline"} label="Connection" tone="sky" />
      </section>
      <section className="dashboard-grid">
        <section className="section-card">
          <div className="card-heading"><h3>Recent files</h3><button className="text-btn" onClick={() => onNavigate("files")}>View all <Icon name="arrow" /></button></div>
          {fileList.length === 0 ? <Empty icon="folder" title="Your next file belongs here." text="Add your first file to get started." action="Upload a file" onClick={() => onNavigate("upload")} /> : (
            <div className="mini-file-list">{fileList.slice(0, 5).map((file) => (
              <div className="mini-file" key={String(file.id)}>
                <span className="file-tile"><Icon name="file" /></span>
                <div><strong>Private file</strong><small title={String(file.id)}>Reference · {String(file.id).slice(-8)}</small></div>
                <button className="outline-btn" onClick={() => onNavigate("files")}>Open <Icon name="arrow" /></button>
              </div>
            ))}</div>
          )}
        </section>
        <section className="section-card activity-preview">
          <div className="card-heading"><h3>Latest activity</h3><button className="text-btn" onClick={() => onNavigate("activity")}>View all <Icon name="arrow" /></button></div>
          {activities.length === 0 ? <Empty icon="clock" title="A fresh start." text="Your recent actions will appear here." /> : activities.map((item) => <ActivityItem key={item.id} item={item} />)}
        </section>
      </section>
    </div>
  );
}

function Stat({ icon, value, label, tone }) {
  return <div className={`stat-card ${tone}`}><span className="stat-icon"><Icon name={icon} /></span><div><strong>{value}</strong><small>{label}</small></div></div>;
}

const UPLOAD_STAGES = [
  ["key", "Prepare your file"], ["encrypt", "Encrypt the file"],
  ["metadata", "Protect file details"], ["protect-meta", "Secure file details"],
  ["protect-fek", "Protect the file key"], ["package", "Prepare upload"],
  ["upload", "Upload encrypted file"], ["gridfs", "Save to your vault"],
];
const DOWNLOAD_STAGES = [
  ["auth", "Check access"], ["retrieve", "Get encrypted file"],
  ["fek", "Get the protected key"], ["decrypt", "Unlock the file"],
  ["metadata", "Get file details"], ["metadata-decrypt", "Read file details"],
  ["reconstruct", "Prepare download"],
];

function UploadPage({ selectedFile, handleFileSelect, handleFileUpload, isUploading, uploadError, uploadResult, steps }) {
  return (
    <div className="page-body narrow-body">
      <div className="page-intro"><span className="section-kicker"><Icon name="upload" /> Add something new</span><h2>A safe place for your files.</h2><p>Choose a file. We’ll encrypt it before uploading.</p></div>
      <div className="operation-layout">
        <section className="section-card upload-card">
          <div className={`drop-zone-large ${selectedFile ? "has-file" : ""}`}>
            <input id="fileUpload" type="file" aria-label="Choose a file to upload" onChange={handleFileSelect} disabled={isUploading} />
            <div className="upload-orb"><Icon name={selectedFile ? "file" : "upload"} /></div>
            <strong>{selectedFile ? selectedFile.name : "What would you like to upload?"}</strong>
            <span>{selectedFile ? formatBytes(selectedFile.size) : "Any file type · Up to 100 MB"}</span>
            <label htmlFor="fileUpload">{selectedFile ? "Choose another file" : "Browse files"}<Icon name="plus" /></label>
          </div>
          {uploadError && <div className="form-alert danger" role="alert">{uploadError}</div>}
          <div className="upload-submit">
            <div className="upload-assurance"><Icon name="lock" /><span>Encrypted before upload.</span></div>
            <button className="primary-btn" onClick={handleFileUpload} disabled={isUploading || !selectedFile}>{isUploading ? "Uploading your file…" : "Upload file"}<Icon name="arrow" /></button>
          </div>
          {uploadResult && <div className="success-card" role="status"><Icon name="check" /><strong>All set! Your file is in your vault.</strong></div>}
        </section>
        {!uploadResult && <OperationPanel title="Upload progress" subtitle={selectedFile?.name} stages={UPLOAD_STAGES} steps={steps} active={isUploading} />}
      </div>
    </div>
  );
}

function FilesPage({ fileList, loadFileList, isLoadingFiles, fileListError, downloadError, steps, downloadingFileId, onDownload, onShare }) {
  return (
    <div className="page-body">
      <div className="page-intro inline">
        <div><span className="section-kicker"><Icon name="folder" /> Your private vault</span><h2>Your files, all here.</h2><p>Download a file or share access with someone.</p></div>
        <button className="outline-btn" onClick={() => loadFileList()} disabled={isLoadingFiles}><Icon name="refresh" />{isLoadingFiles ? "Refreshing…" : "Refresh"}</button>
      </div>
      {fileListError && <div className="form-alert danger" role="alert">{fileListError}</div>}
      {downloadError && <div className="form-alert danger" role="alert">{downloadError}</div>}
      <section className="section-card vault-card">
        {isLoadingFiles && fileList.length === 0 ? <div className="empty-state" role="status"><div className="loader" /><p>Getting your files…</p></div> : fileList.length === 0 ? !fileListError && <Empty icon="folder" title="Room for something new." text="Upload a file to start your collection." /> : (
          <div className="vault-table" role="table" aria-label="Your private files">
            <div className="vault-head" role="row"><span aria-hidden="true" /><span role="columnheader">File</span><span role="columnheader">Added</span><span role="columnheader">Status</span><span role="columnheader">Actions</span></div>
            <div className="vault-list" role="rowgroup">{fileList.map((file) => {
              const id = String(file.id);
              const busy = downloadingFileId === id;
              return (
                <div className="vault-row" role="row" key={id}>
                  <div className="vault-file-icon" role="cell" aria-hidden="true"><Icon name="file" /></div>
                  <div className="vault-file" role="cell"><strong>Private file</strong><small title={id}>Reference · {id.slice(-8)}</small></div>
                  <div className="vault-meta vault-created" role="cell"><span>Added</span><strong>{file.createdAt ? new Date(file.createdAt).toLocaleDateString(undefined, { day: "numeric", month: "short", year: "numeric" }) : "—"}</strong></div>
                  <div className="vault-status" role="cell"><Icon name="lock" /> Encrypted</div>
                  <div className="vault-actions" role="cell"><button className="outline-btn" aria-label={`Share private file ${id.slice(-8)}`} onClick={() => onShare()}><Icon name="share" /> Share</button><button className="primary-mini" aria-label={`Download private file ${id.slice(-8)}`} onClick={() => onDownload(id)} disabled={downloadingFileId !== null}><Icon name="download" />{busy ? "Preparing…" : "Download"}</button></div>
                </div>
              );
            })}</div>
          </div>
        )}
        <div className="vault-note"><Icon name="lock" /><span>File names stay encrypted until you download.</span></div>
      </section>
      <OperationPanel title="Download progress" stages={DOWNLOAD_STAGES} steps={steps} active={downloadingFileId !== null} />
    </div>
  );
}

function ActivityPage({ activities }) {
  return (
    <div className="page-body">
      <div className="page-intro"><span className="section-kicker"><Icon name="clock" /> This session</span><h2>Your recent activity.</h2><p>A quick look at what you’ve been up to.</p></div>
      <section className="section-card activity-card">
        {activities.length === 0 ? <Empty icon="clock" title="Nothing here just yet." text="Uploads, downloads, and shares will appear here." /> : <div className="activity-list">{activities.map((item) => <ActivityItem key={item.id} item={item} expanded />)}</div>}
        <div className="activity-disclaimer"><Icon name="info" /><span>This history clears when you sign out.</span></div>
      </section>
    </div>
  );
}

function ActivityItem({ item, expanded = false }) {
  const icon = { UPLOAD: "upload", DOWNLOAD: "download", SHARE: "share", REVOKE: "lock", AUTH: "shield" }[item.type] || "clock";
  return (
    <div className={`activity-item ${item.status}`}>
      <span className="activity-icon"><Icon name={icon} /></span>
      <div className="activity-copy"><strong>{item.title}</strong><span>{item.detail}</span><time dateTime={item.createdAt}>{expanded ? formatDate(item.createdAt) : new Date(item.createdAt).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}</time></div>
    </div>
  );
}

function SecurityPage({ currentUser, runtimeKeys, backendOnline }) {
  const keysReady = runtimeKeys?.masterKey instanceof Uint8Array && runtimeKeys?.mlKemPrivateKey instanceof Uint8Array;
  return (
    <div className="page-body">
      <div className="page-intro"><span className="section-kicker"><Icon name="shield" /> Peace of mind</span><h2>Your privacy, explained.</h2><p>A few things to know about your workspace.</p></div>
      <div className="security-grid">
        <section className="section-card security-overview">
          <div className="security-score"><span className="security-badge"><Icon name="shield" /></span><div><span>Your session</span><strong>{keysReady ? "Protected and ready" : "Session unavailable"}</strong><small>{formatDisplayUsername(currentUser.username)} · {backendOnline ? "Connected" : "Connection unavailable"}</small></div></div>
          <div className="security-lines">
            <SecurityLine icon="lock" title="Encrypted in your browser" value="Files are protected before they reach storage." />
            <SecurityLine icon="users" title="Sharing is your choice" value="Give access to another account, and remove it when needed." />
            <SecurityLine icon="shield" title="Keys stay in this tab" value="Your private keys aren’t saved in browser storage." />
          </div>
        </section>
        <section className="section-card good-to-know">
          <span className="section-kicker"><Icon name="info" /> Good to know</span><h3>A couple of useful reminders.</h3>
          <ul className="trust-list"><li><strong>Keep your password safe.</strong><span>Password recovery isn’t available in this version.</span></li><li><strong>Downloaded copies stay downloaded.</strong><span>Removing access stops future downloads, but can’t erase saved copies.</span></li></ul>
        </section>
      </div>
      <details className="technical-details section-card">
        <summary><Icon name="info" /> For the curious: technical details</summary>
        <div className="technical-content">
          <div className="crypto-box"><strong>AES-256-GCM</strong><span>Encrypts files and file details.</span></div>
          <div className="crypto-box"><strong>ML-KEM-768</strong><span>Establishes protected keys for sharing.</span></div>
          <div className="crypto-box"><strong>PBKDF2 + HKDF</strong><span>Derive and separate cryptographic keys.</span></div>
          <p>Encryption hides file contents. Account identifiers, sharing records, and timestamps remain visible to the service. This is provider-blind file storage, not a formal zero-knowledge proof system.</p>
        </div>
      </details>
    </div>
  );
}

function SecurityLine({ icon, title, value }) {
  return <div className="security-line"><span><Icon name={icon} /></span><div><strong>{title}</strong><small>{value}</small></div></div>;
}

function AboutPage() {
  return (
    <div className="page-body about-page">
      <section className="about-hero"><div><span className="eyebrow">Meet QSZKFSS</span><h2>Private files.<br /><em>Simple sharing.</em></h2><p>A workspace that puts your privacy first.</p></div><VaultArtwork /></section>
      <div className="about-grid">
        <AboutSection icon="upload" title="Make space." tone="indigo">Upload a file. It’s encrypted in your browser before it’s stored.</AboutSection>
        <AboutSection icon="share" title="Bring someone in." tone="teal">Share with another account using their username. You choose the access.</AboutSection>
        <AboutSection icon="download" title="Take it with you." tone="sky">Download your files, or the ones shared with you, and open them locally.</AboutSection>
      </div>
      <details className="technical-details section-card">
        <summary><Icon name="info" /> About the project</summary>
        <div className="technical-content"><p>Quantum Safe Zero Knowledge File Sharing System uses browser-side encryption and post-quantum key establishment for sharing.</p><div className="tech-grid"><span>React + Vite</span><span>Node.js + Express</span><span>MongoDB Atlas</span><span>Web Crypto API</span><span>AES-256-GCM</span><span>ML-KEM-768</span></div></div>
      </details>
    </div>
  );
}

function AboutSection({ icon, title, tone, children }) {
  return <section className={`section-card about-section ${tone}`}><span className="about-icon"><Icon name={icon} /></span><h3>{title}</h3><p>{children}</p></section>;
}

function Empty({ icon, title, text, action, onClick }) {
  return <div className="empty-state"><div className="empty-icon"><Icon name={icon} /></div><strong>{title}</strong><p>{text}</p>{action && <button className="primary-btn" onClick={onClick}><Icon name="plus" />{action}</button>}</div>;
}

export default App;
