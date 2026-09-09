import { useEffect, useState } from "react";

import { prepareRegistrationCrypto } from "./crypto/registrationCrypto.js";
import { recoverLoginKeys } from "./crypto/loginCrypto.js";

import { uploadEncryptedFile } from "./services/fileUploadService.js";

function App() {
  const API_BASE_URL =
    import.meta.env.VITE_API_BASE_URL ||
    "http://localhost:5000/api";

  const [status, setStatus] =
    useState("Checking backend...");

  const [error, setError] =
    useState("");

  /*
   * ----------------------------------------------------
   * Registration state
   * ----------------------------------------------------
   */
  const [
    registerUsername,
    setRegisterUsername,
  ] = useState("");

  const [
    registerPassword,
    setRegisterPassword,
  ] = useState("");

  const [
    registerStatus,
    setRegisterStatus,
  ] = useState("");

  const [
    registerError,
    setRegisterError,
  ] = useState("");

  const [
    isRegistering,
    setIsRegistering,
  ] = useState(false);

  /*
   * ----------------------------------------------------
   * Login state
   * ----------------------------------------------------
   */
  const [
    loginUsername,
    setLoginUsername,
  ] = useState("");

  const [
    loginPassword,
    setLoginPassword,
  ] = useState("");

  const [
    loginStatus,
    setLoginStatus,
  ] = useState("");

  const [
    loginError,
    setLoginError,
  ] = useState("");

  const [
    isLoggingIn,
    setIsLoggingIn,
  ] = useState(false);

  /*
   * ----------------------------------------------------
   * Runtime-only cryptographic state
   * ----------------------------------------------------
   *
   * These values are deliberately NOT stored in:
   * - localStorage
   * - sessionStorage
   * - cookies
   * - IndexedDB
   *
   * They exist only while this React application
   * is running.
   */
  const [
    currentUser,
    setCurrentUser,
  ] = useState(null);

  const [
    runtimeKeys,
    setRuntimeKeys,
  ] = useState(null);

  /*
   * ----------------------------------------------------
   * File upload state
   * ----------------------------------------------------
   */
  const [
    selectedFile,
    setSelectedFile,
  ] = useState(null);

  const [
    uploadStatus,
    setUploadStatus,
  ] = useState("");

  const [
    uploadError,
    setUploadError,
  ] = useState("");

  const [
    isUploading,
    setIsUploading,
  ] = useState(false);

  const [
    uploadResult,
    setUploadResult,
  ] = useState(null);

  /*
   * ----------------------------------------------------
   * Encrypted file listing state
   * ----------------------------------------------------
   */
  const [
    fileList,
    setFileList,
  ] = useState([]);

  const [
    fileListStatus,
    setFileListStatus,
  ] = useState("");

  const [
    fileListError,
    setFileListError,
  ] = useState("");

  const [
    isLoadingFiles,
    setIsLoadingFiles,
  ] = useState(false);

  /*
   * Maximum plaintext file size for V1.
   */
  const MAX_FILE_SIZE =
    100 * 1024 * 1024;

  /*
   * ----------------------------------------------------
   * Check backend availability
   * ----------------------------------------------------
   */
  useEffect(() => {
    fetch(
      `${API_BASE_URL}/health`
    )
      .then(async (response) => {
        if (!response.ok) {
          throw new Error(
            "Backend returned an error."
          );
        }

        return response.json();
      })
      .then((data) => {
        setStatus(data.message);
        setError("");
      })
      .catch((err) => {
        setError(err.message);
        setStatus(
          "Backend unavailable"
        );
      });
  }, [API_BASE_URL]);

  /*
   * ----------------------------------------------------
   * Registration
   * ----------------------------------------------------
   */
  async function handleRegister(event) {
    event.preventDefault();

    setRegisterStatus("");
    setRegisterError("");
    setIsRegistering(true);

    try {
      /*
       * Generate:
       * - Master Key
       * - PBKDF2 salt
       * - KEK
       * - wrapped Master Key
       * - ML-KEM-768 key pair
       * - protected ML-KEM private key
       */
      const cryptoMaterial =
        await prepareRegistrationCrypto(
          registerPassword
        );

      const response =
        await fetch(
          `${API_BASE_URL}/auth/register`,
          {
            method: "POST",

            headers: {
              "Content-Type":
                "application/json",
            },

            body: JSON.stringify({
              username:
                registerUsername,

              password:
                registerPassword,

              ...cryptoMaterial,
            }),
          }
        );

      const data =
        await response.json();

      if (!response.ok) {
        throw new Error(
          data.message ||
            "Registration failed."
        );
      }

      setRegisterStatus(
        `Registration successful for "${data.user.username}".`
      );

      setRegisterUsername("");
      setRegisterPassword("");
    } catch (err) {
      console.error(
        "Registration failed:",
        err
      );

      setRegisterError(
        err.message ||
          "Registration failed."
      );
    } finally {
      setIsRegistering(false);
    }
  }

  /*
   * ----------------------------------------------------
   * List encrypted files
   * ----------------------------------------------------
   *
   * IMPORTANT:
   *
   * The backend returns only file references.
   *
   * Plaintext filename, type and size remain
   * inside encryptedMetadata.
   *
   * Those values will be decrypted locally
   * in the next stage.
   */
  async function loadFileList(
    ownerId
  ) {
    if (
      typeof ownerId !== "string" ||
      ownerId.length === 0
    ) {
      return;
    }

    setFileListStatus(
      "Loading encrypted files..."
    );

    setFileListError("");
    setIsLoadingFiles(true);

    try {
      const response =
        await fetch(
          `${API_BASE_URL}/files?ownerId=${encodeURIComponent(
            ownerId
          )}`
        );

      let data;

      try {
        data =
          await response.json();
      } catch {
        throw new Error(
          "The server returned an invalid response."
        );
      }

      if (!response.ok) {
        throw new Error(
          data.message ||
            "Unable to load encrypted files."
        );
      }

      const files =
        Array.isArray(data.files)
          ? data.files
          : [];

      setFileList(files);

      setFileListStatus(
        files.length > 0
          ? `${files.length} encrypted file${
              files.length === 1
                ? ""
                : "s"
            } found.`
          : "No encrypted files found."
      );
    } catch (err) {
      console.error(
        "Failed to load encrypted files:",
        err
      );

      setFileList([]);

      setFileListStatus("");

      setFileListError(
        err.message ||
          "Unable to load encrypted files."
      );
    } finally {
      setIsLoadingFiles(false);
    }
  }

  /*
   * ----------------------------------------------------
   * Login
   * ----------------------------------------------------
   */
  async function handleLogin(event) {
    event.preventDefault();

    setLoginStatus("");
    setLoginError("");
    setIsLoggingIn(true);

    /*
     * Clear any previous runtime keys before
     * starting a new login attempt.
     */
    setRuntimeKeys(null);
    setCurrentUser(null);

    /*
     * Clear previous upload state.
     */
    setSelectedFile(null);
    setUploadStatus("");
    setUploadError("");
    setUploadResult(null);

    /*
     * Clear previous file listing.
     */
    setFileList([]);
    setFileListStatus("");
    setFileListError("");

    try {
      /*
       * Step 1:
       *
       * Authenticate with the backend.
       */
      const response =
        await fetch(
          `${API_BASE_URL}/auth/login`,
          {
            method: "POST",

            headers: {
              "Content-Type":
                "application/json",
            },

            body: JSON.stringify({
              username:
                loginUsername,

              password:
                loginPassword,
            }),
          }
        );

      const data =
        await response.json();

      if (!response.ok) {
        throw new Error(
          data.message ||
            "Login failed."
        );
      }

      /*
       * Step 2:
       *
       * Recover the Master Key and ML-KEM
       * private key entirely inside the browser.
       */
      const recoveredKeys =
        await recoverLoginKeys({
          password:
            loginPassword,

          passwordKdfSalt:
            data.user.passwordKdfSalt,

          passwordKdfParams:
            data.user.passwordKdfParams,

          wrappedMasterKey:
            data.user.wrappedMasterKey,

          masterKeyIV:
            data.user.masterKeyIV,

          wrappedMlKemPrivateKey:
            data.user
              .wrappedMlKemPrivateKey,

          privateKeyIV:
            data.user.privateKeyIV,
        });

      /*
       * Step 3:
       *
       * Keep recovered keys only in
       * React runtime memory.
       */
      setRuntimeKeys(
        recoveredKeys
      );

      const loggedInUser = {
        id: data.user.id,

        username:
          data.user.username,

        /*
         * Public key is not secret.
         *
         * It will be needed later for sharing.
         */
        mlKemPublicKey:
          data.user.mlKemPublicKey,
      };

      setCurrentUser(
        loggedInUser
      );

      setLoginStatus(
        "Login successful. Cryptographic keys recovered locally."
      );

      /*
       * Do not keep the plaintext password
       * in component state after successful
       * recovery.
       */
      setLoginPassword("");

      /*
       * Load Alice's encrypted file references.
       *
       * This does NOT decrypt anything.
       */
      await loadFileList(
        loggedInUser.id
      );
    } catch (err) {
      console.error(
        "Login failed:",
        err
      );

      setLoginError(
        err.message ||
          "Login failed."
      );
    } finally {
      setIsLoggingIn(false);
    }
  }

  /*
   * ----------------------------------------------------
   * File selection
   * ----------------------------------------------------
   */
  function handleFileSelect(event) {
    const file =
      event.target.files?.[0];

    /*
     * Clear previous upload state.
     */
    setUploadStatus("");
    setUploadError("");
    setUploadResult(null);

    if (!file) {
      setSelectedFile(null);
      return;
    }

    /*
     * Validate V1 size limit before
     * performing expensive browser-side
     * encryption.
     */
    if (
      file.size >
      MAX_FILE_SIZE
    ) {
      setSelectedFile(null);

      setUploadError(
        "File exceeds the V1 maximum size of 100 MB."
      );

      /*
       * Reset the input so the same file can
       * be selected again after correction.
       */
      event.target.value = "";

      return;
    }

    setSelectedFile(file);
  }

  /*
   * ----------------------------------------------------
   * Encrypted file upload
   * ----------------------------------------------------
   */
  async function handleFileUpload(event) {
    event.preventDefault();

    setUploadStatus("");
    setUploadError("");
    setUploadResult(null);

    if (!selectedFile) {
      setUploadError(
        "Please select a file first."
      );

      return;
    }

    if (!currentUser) {
      setUploadError(
        "You must be logged in to upload a file."
      );

      return;
    }

    if (!runtimeKeys) {
      setUploadError(
        "Cryptographic keys are not available."
      );

      return;
    }

    if (
      !(
        runtimeKeys.masterKey instanceof
        Uint8Array
      )
    ) {
      setUploadError(
        "Master Key is unavailable."
      );

      return;
    }

    setIsUploading(true);

    try {
      setUploadStatus(
        "Encrypting file and metadata locally..."
      );

      /*
       * IMPORTANT:
       *
       * This function performs:
       *
       * File
       *   ↓
       * AES-256-GCM
       *   ↓
       * ciphertext
       *
       * Metadata
       *   ↓
       * AES-256-GCM
       *   ↓
       * encrypted metadata
       *
       * Master Key
       *   ↓
       * HKDF
       *   ↓
       * wrapping keys
       *
       * Nothing plaintext is sent to the backend.
       */
      const result =
        await uploadEncryptedFile({
          file: selectedFile,

          ownerId:
            currentUser.id,

          masterKey:
            runtimeKeys.masterKey,

          apiBaseUrl:
            API_BASE_URL,
        });

      setUploadResult(result);

      setUploadStatus(
        "File encrypted in the browser and uploaded successfully."
      );

      /*
       * Keep the selected File object available
       * only for the current UI session.
       */
      setSelectedFile(null);

      /*
       * Reset the file input.
       */
      const input =
        document.getElementById(
          "fileUpload"
        );

      if (input) {
        input.value = "";
      }

      /*
       * Refresh encrypted file list.
       */
      await loadFileList(
        currentUser.id
      );
    } catch (err) {
      console.error(
        "Encrypted file upload failed:",
        err
      );

      setUploadError(
        err.message ||
          "Encrypted file upload failed."
      );
    } finally {
      setIsUploading(false);
    }
  }

  /*
   * ----------------------------------------------------
   * Logout
   * ----------------------------------------------------
   */
  function handleLogout() {
    /*
     * Remove cryptographic material from
     * React runtime state.
     */
    setRuntimeKeys(null);
    setCurrentUser(null);

    setLoginUsername("");
    setLoginPassword("");

    /*
     * Clear upload-related state.
     */
    setSelectedFile(null);
    setUploadStatus("");
    setUploadError("");
    setUploadResult(null);

    /*
     * Clear file listing.
     */
    setFileList([]);
    setFileListStatus("");
    setFileListError("");

    /*
     * Reset file input if present.
     */
    const input =
      document.getElementById(
        "fileUpload"
      );

    if (input) {
      input.value = "";
    }

    setLoginStatus(
      "Logged out. Runtime cryptographic keys cleared."
    );

    setLoginError("");
  }

  return (
    <main className="container py-5">
      <div className="row justify-content-center">
        <div className="col-lg-10">
          <div className="card shadow-sm">
            <div className="card-body p-4">

              <span className="badge text-bg-dark mb-3">
                Frozen V1 — Client-Side Encryption
              </span>

              <h1 className="h3">
                Quantum Safe Zero Knowledge
                File Sharing System
              </h1>

              <p className="text-secondary">
                Client-side encrypted file
                sharing with AES-256-GCM and
                ML-KEM-768 key establishment.
              </p>

              <hr />

              {/* Backend status */}
              <h2 className="h6">
                Backend status
              </h2>

              <div
                className={`alert ${
                  error
                    ? "alert-danger"
                    : "alert-success"
                }`}
              >
                {status}
              </div>

              <hr />

              <div className="row g-4">

                {/* Registration */}
                <div className="col-md-6">
                  <h2 className="h5 mb-3">
                    Create Account
                  </h2>

                  <form
                    onSubmit={
                      handleRegister
                    }
                  >
                    <div className="mb-3">
                      <label
                        htmlFor="registerUsername"
                        className="form-label"
                      >
                        Username
                      </label>

                      <input
                        id="registerUsername"
                        type="text"
                        className="form-control"
                        value={
                          registerUsername
                        }
                        onChange={(
                          event
                        ) =>
                          setRegisterUsername(
                            event.target
                              .value
                          )
                        }
                        placeholder="Enter username"
                        autoComplete="username"
                        required
                        minLength={3}
                        maxLength={50}
                      />
                    </div>

                    <div className="mb-3">
                      <label
                        htmlFor="registerPassword"
                        className="form-label"
                      >
                        Password
                      </label>

                      <input
                        id="registerPassword"
                        type="password"
                        className="form-control"
                        value={
                          registerPassword
                        }
                        onChange={(
                          event
                        ) =>
                          setRegisterPassword(
                            event.target
                              .value
                          )
                        }
                        placeholder="Enter password"
                        autoComplete="new-password"
                        required
                        minLength={8}
                        maxLength={128}
                      />
                    </div>

                    {registerError && (
                      <div className="alert alert-danger">
                        {registerError}
                      </div>
                    )}

                    {registerStatus && (
                      <div className="alert alert-success">
                        {registerStatus}
                      </div>
                    )}

                    <button
                      type="submit"
                      className="btn btn-dark w-100"
                      disabled={
                        isRegistering
                      }
                    >
                      {isRegistering
                        ? "Creating secure account..."
                        : "Create Account"}
                    </button>
                  </form>
                </div>

                {/* Login */}
                <div className="col-md-6">
                  <h2 className="h5 mb-3">
                    Login
                  </h2>

                  <form
                    onSubmit={
                      handleLogin
                    }
                  >
                    <div className="mb-3">
                      <label
                        htmlFor="loginUsername"
                        className="form-label"
                      >
                        Username
                      </label>

                      <input
                        id="loginUsername"
                        type="text"
                        className="form-control"
                        value={
                          loginUsername
                        }
                        onChange={(
                          event
                        ) =>
                          setLoginUsername(
                            event.target
                              .value
                          )
                        }
                        placeholder="Enter username"
                        autoComplete="username"
                        required
                        minLength={3}
                        maxLength={50}
                      />
                    </div>

                    <div className="mb-3">
                      <label
                        htmlFor="loginPassword"
                        className="form-label"
                      >
                        Password
                      </label>

                      <input
                        id="loginPassword"
                        type="password"
                        className="form-control"
                        value={
                          loginPassword
                        }
                        onChange={(
                          event
                        ) =>
                          setLoginPassword(
                            event.target
                              .value
                          )
                        }
                        placeholder="Enter password"
                        autoComplete="current-password"
                        required
                        minLength={8}
                        maxLength={128}
                      />
                    </div>

                    {loginError && (
                      <div className="alert alert-danger">
                        {loginError}
                      </div>
                    )}

                    {loginStatus && (
                      <div className="alert alert-success">
                        {loginStatus}
                      </div>
                    )}

                    <button
                      type="submit"
                      className="btn btn-primary w-100"
                      disabled={
                        isLoggingIn
                      }
                    >
                      {isLoggingIn
                        ? "Recovering secure keys..."
                        : "Login"}
                    </button>
                  </form>
                </div>
              </div>

              {/* Logged-in state */}
              {currentUser && (
                <>
                  <hr className="my-4" />

                  <div className="alert alert-success">
                    <h2 className="h6">
                      Secure session active
                    </h2>

                    <p className="mb-2">
                      Logged in as{" "}
                      <strong>
                        {
                          currentUser.username
                        }
                      </strong>
                      .
                    </p>

                    <p className="small mb-3">
                      Master Key and
                      ML-KEM-768 private key
                      have been recovered
                      inside the browser and
                      are currently held only
                      in runtime memory.
                    </p>

                    <button
                      type="button"
                      className="btn btn-outline-danger btn-sm"
                      onClick={
                        handleLogout
                      }
                    >
                      Logout & Clear Keys
                    </button>
                  </div>

                  {/* Cryptographic recovery */}
                  {runtimeKeys && (
                    <div className="card bg-light border-0 mb-4">
                      <div className="card-body">
                        <h2 className="h6">
                          Cryptographic Recovery
                        </h2>

                        <ul className="small mb-0">
                          <li>
                            Master Key recovered:{" "}
                            <strong>
                              Yes
                            </strong>
                          </li>

                          <li>
                            Master Key length:{" "}
                            <strong>
                              {
                                runtimeKeys
                                  .masterKey
                                  .length
                              }{" "}
                              bytes
                            </strong>
                          </li>

                          <li>
                            ML-KEM private key
                            recovered:{" "}
                            <strong>
                              Yes
                            </strong>
                          </li>

                          <li>
                            ML-KEM private key
                            length:{" "}
                            <strong>
                              {
                                runtimeKeys
                                  .mlKemPrivateKey
                                  .length
                              }{" "}
                              bytes
                            </strong>
                          </li>

                          <li>
                            Keys persisted to
                            browser storage:{" "}
                            <strong>
                              No
                            </strong>
                          </li>
                        </ul>
                      </div>
                    </div>
                  )}

                  {/* Encrypted File Upload */}
                  <div className="card border-primary mb-4">
                    <div className="card-body">
                      <h2 className="h5">
                        Secure File Upload
                      </h2>

                      <p className="text-secondary small">
                        Your file is encrypted
                        inside the browser before
                        any file data is sent to
                        the server.
                      </p>

                      <div className="alert alert-info small">
                        <strong>
                          Zero-Knowledge
                          Protection:
                        </strong>{" "}
                        The backend receives
                        ciphertext, encrypted
                        metadata, protected keys,
                        and non-secret IVs. It
                        does not receive the
                        plaintext file or FEK.
                      </div>

                      <form
                        onSubmit={
                          handleFileUpload
                        }
                      >
                        <div className="mb-3">
                          <label
                            htmlFor="fileUpload"
                            className="form-label"
                          >
                            Select file
                          </label>

                          <input
                            id="fileUpload"
                            type="file"
                            className="form-control"
                            onChange={
                              handleFileSelect
                            }
                            disabled={
                              isUploading
                            }
                          />

                          <div className="form-text">
                            Maximum V1 file
                            size: 100 MB.
                          </div>
                        </div>

                        {selectedFile && (
                          <div className="card bg-light border-0 mb-3">
                            <div className="card-body">
                              <h3 className="h6">
                                Selected file
                              </h3>

                              <div className="small">
                                <div>
                                  <strong>
                                    Name:
                                  </strong>{" "}
                                  {
                                    selectedFile.name
                                  }
                                </div>

                                <div>
                                  <strong>
                                    Type:
                                  </strong>{" "}
                                  {selectedFile.type ||
                                    "Unknown"}
                                </div>

                                <div>
                                  <strong>
                                    Size:
                                  </strong>{" "}
                                  {(
                                    selectedFile
                                      .size /
                                    (1024 * 1024)
                                  ).toFixed(
                                    2
                                  )}{" "}
                                  MB
                                </div>
                              </div>
                            </div>
                          </div>
                        )}

                        {uploadError && (
                          <div className="alert alert-danger">
                            {uploadError}
                          </div>
                        )}

                        {uploadStatus && (
                          <div className="alert alert-success">
                            {uploadStatus}
                          </div>
                        )}

                        <button
                          type="submit"
                          className="btn btn-primary w-100"
                          disabled={
                            isUploading ||
                            !selectedFile
                          }
                        >
                          {isUploading
                            ? "Encrypting & Uploading..."
                            : "Encrypt & Upload File"}
                        </button>
                      </form>

                      {uploadResult && (
                        <div className="card bg-light border-0 mt-4">
                          <div className="card-body">
                            <h3 className="h6">
                              Upload Result
                            </h3>

                            <ul className="small mb-0">
                              <li>
                                Server accepted
                                ciphertext:{" "}
                                <strong>
                                  Yes
                                </strong>
                              </li>

                              <li>
                                Cryptographic
                                version:{" "}
                                <strong>
                                  {
                                    uploadResult
                                      .file
                                      ?.keyVersion
                                  }
                                </strong>
                              </li>

                              <li>
                                GridFS object
                                created:{" "}
                                <strong>
                                  Yes
                                </strong>
                              </li>

                              <li>
                                Plaintext sent
                                to server:{" "}
                                <strong>
                                  No
                                </strong>
                              </li>
                            </ul>
                          </div>
                        </div>
                      )}
                    </div>
                  </div>

                  {/* Encrypted File List */}
                  <div className="card border-success">
                    <div className="card-body">
                      <div className="d-flex justify-content-between align-items-center mb-3">
                        <div>
                          <h2 className="h5 mb-1">
                            Your Encrypted Files
                          </h2>

                          <p className="text-secondary small mb-0">
                            File references are
                            retrieved from the
                            server. Sensitive
                            metadata remains
                            encrypted.
                          </p>
                        </div>

                        <button
                          type="button"
                          className="btn btn-outline-secondary btn-sm"
                          onClick={() =>
                            loadFileList(
                              currentUser.id
                            )
                          }
                          disabled={
                            isLoadingFiles
                          }
                        >
                          {isLoadingFiles
                            ? "Refreshing..."
                            : "Refresh"}
                        </button>
                      </div>

                      {fileListError && (
                        <div className="alert alert-danger small">
                          {fileListError}
                        </div>
                      )}

                      {fileListStatus && (
                        <div className="alert alert-info small">
                          {fileListStatus}
                        </div>
                      )}

                      {isLoadingFiles &&
                        fileList.length ===
                          0 && (
                          <div className="text-center py-3">
                            <div
                              className="spinner-border spinner-border-sm"
                              role="status"
                              aria-hidden="true"
                            />
                            <span className="ms-2 small">
                              Loading encrypted
                              files...
                            </span>
                          </div>
                        )}

                      {!isLoadingFiles &&
                        fileList.length ===
                          0 &&
                        !fileListError && (
                          <div className="text-center text-secondary py-4">
                            <p className="mb-1">
                              No encrypted files
                              found.
                            </p>

                            <p className="small mb-0">
                              Upload a file above
                              to create your first
                              encrypted file.
                            </p>
                          </div>
                        )}

                      {fileList.length > 0 && (
                        <div className="list-group">
                          {fileList.map(
                            (file) => (
                              <div
                                key={String(
                                  file.id
                                )}
                                className="list-group-item"
                              >
                                <div className="d-flex justify-content-between align-items-start">
                                  <div>
                                    <div className="fw-semibold">
                                      Encrypted
                                      File
                                    </div>

                                    <div className="small text-secondary">
                                      File ID:{" "}
                                      <code>
                                        {String(
                                          file.id
                                        )}
                                      </code>
                                    </div>

                                    <div className="small text-secondary">
                                      Version:{" "}
                                      {
                                        file.keyVersion
                                      }
                                    </div>

                                    {file.createdAt && (
                                      <div className="small text-secondary">
                                        Uploaded:{" "}
                                        {new Date(
                                          file.createdAt
                                        ).toLocaleString()}
                                      </div>
                                    )}
                                  </div>

                                  <span className="badge text-bg-success">
                                    Encrypted
                                  </span>
                                </div>
                              </div>
                            )
                          )}
                        </div>
                      )}

                      <div className="alert alert-secondary small mt-3 mb-0">
                        <strong>Privacy:</strong>{" "}
                        The server does not receive
                        the plaintext filename,
                        MIME type, or original file
                        contents. These will be
                        recovered from encrypted
                        metadata inside the browser.
                      </div>
                    </div>
                  </div>
                </>
              )}

              <hr />

              <p className="small text-secondary mb-0">
                Current stage: encrypted file
                listing and browser-side encrypted
                storage.
              </p>

            </div>
          </div>
        </div>
      </div>
    </main>
  );
}

export default App;
