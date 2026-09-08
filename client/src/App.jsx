import { useEffect, useState } from "react";

import { prepareRegistrationCrypto } from "./crypto/registrationCrypto.js";

import { recoverLoginKeys } from "./crypto/loginCrypto.js";

const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL ||
  "http://localhost:5000/api";

function App() {
  const [status, setStatus] =
    useState("Checking backend...");
  const [error, setError] = useState("");

  /*
   * Registration state
   */
  const [registerUsername, setRegisterUsername] =
    useState("");

  const [registerPassword, setRegisterPassword] =
    useState("");

  const [registerStatus, setRegisterStatus] =
    useState("");

  const [registerError, setRegisterError] =
    useState("");

  const [isRegistering, setIsRegistering] =
    useState(false);

  /*
   * Login state
   */
  const [loginUsername, setLoginUsername] =
    useState("");

  const [loginPassword, setLoginPassword] =
    useState("");

  const [loginStatus, setLoginStatus] =
    useState("");

  const [loginError, setLoginError] =
    useState("");

  const [isLoggingIn, setIsLoggingIn] =
    useState(false);

  /*
   * Runtime-only cryptographic state.
   *
   * IMPORTANT:
   * These values are deliberately NOT stored in:
   * - localStorage
   * - sessionStorage
   * - cookies
   * - IndexedDB
   *
   * They exist only while this React application is running.
   */
  const [currentUser, setCurrentUser] =
    useState(null);

  const [runtimeKeys, setRuntimeKeys] =
    useState(null);

  /*
   * Check backend availability.
   */
  useEffect(() => {
    fetch(`${API_BASE_URL}/health`)
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
      })
      .catch((err) => {
        setError(err.message);
        setStatus("Backend unavailable");
      });
  }, []);

  /*
   * Registration
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

      const response = await fetch(
        `${API_BASE_URL}/auth/register`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            username: registerUsername,
            password: registerPassword,

            ...cryptoMaterial,
          }),
        }
      );

      const data = await response.json();

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
   * Login
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

    try {
      /*
       * Step 1:
       * Authenticate with the backend.
       */
      const response = await fetch(
        `${API_BASE_URL}/auth/login`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            username: loginUsername,
            password: loginPassword,
          }),
        }
      );

      const data = await response.json();

      if (!response.ok) {
        throw new Error(
          data.message || "Login failed."
        );
      }

      /*
       * Step 2:
       *
       * The backend has authenticated the password.
       *
       * It has returned only protected cryptographic
       * material. The actual Master Key and ML-KEM
       * private key must be recovered locally.
       */
      const recoveredKeys =
        await recoverLoginKeys({
          password: loginPassword,

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
       * Keep recovered keys only in React runtime
       * memory.
       */
      setRuntimeKeys(recoveredKeys);

      setCurrentUser({
        id: data.user.id,
        username: data.user.username,

        /*
         * Public key is not secret.
         * It may be needed later for sharing.
         */
        mlKemPublicKey:
          data.user.mlKemPublicKey,
      });

      setLoginStatus(
        "Login successful. Cryptographic keys recovered locally."
      );

      /*
       * Do not keep the plaintext password in
       * component state after successful recovery.
       */
      setLoginPassword("");
    } catch (err) {
      console.error(
        "Login failed:",
        err
      );

      setLoginError(
        err.message || "Login failed."
      );
    } finally {
      setIsLoggingIn(false);
    }
  }

  /*
   * Logout
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

    setLoginStatus(
      "Logged out. Runtime cryptographic keys cleared."
    );

    setLoginError("");
  }

  return (
    <main className="container py-5">
      <div className="row justify-content-center">
        <div className="col-lg-9">
          <div className="card shadow-sm">
            <div className="card-body p-4">

              <span className="badge text-bg-dark mb-3">
                Frozen V1 — Authentication
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
                    onSubmit={handleRegister}
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
                        onChange={(event) =>
                          setRegisterUsername(
                            event.target.value
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
                        onChange={(event) =>
                          setRegisterPassword(
                            event.target.value
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
                    onSubmit={handleLogin}
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
                        onChange={(event) =>
                          setLoginUsername(
                            event.target.value
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
                        onChange={(event) =>
                          setLoginPassword(
                            event.target.value
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
                        {currentUser.username}
                      </strong>
                      .
                    </p>

                    <p className="small mb-3">
                      Master Key and ML-KEM-768
                      private key have been
                      recovered inside the browser
                      and are currently held only
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

                  {runtimeKeys && (
                    <div className="card bg-light border-0">
                      <div className="card-body">
                        <h2 className="h6">
                          Cryptographic Recovery
                        </h2>

                        <ul className="small mb-0">
                          <li>
                            Master Key recovered:
                            {" "}
                            <strong>
                              Yes
                            </strong>
                          </li>

                          <li>
                            Master Key length:
                            {" "}
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
                            recovered:
                            {" "}
                            <strong>
                              Yes
                            </strong>
                          </li>

                          <li>
                            ML-KEM private key
                            length:
                            {" "}
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
                            Keys persisted to browser
                            storage:
                            {" "}
                            <strong>
                              No
                            </strong>
                          </li>
                        </ul>
                      </div>
                    </div>
                  )}
                </>
              )}

              <hr />

              <p className="small text-secondary mb-0">
                Current stage: authentication and
                browser-side cryptographic key
                recovery.
              </p>

            </div>
          </div>
        </div>
      </div>
    </main>
  );
}

export default App;
