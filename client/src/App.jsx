import { useEffect, useState } from "react";
import { runMLKEMSelfTest } from "./crypto/testMlKem.js";

const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL || "http://localhost:5000/api";

function App() {
  const [status, setStatus] = useState("Checking backend...");
  const [error, setError] = useState("");

  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");

  const [registerStatus, setRegisterStatus] = useState("");
  const [registerError, setRegisterError] = useState("");
  const [isRegistering, setIsRegistering] = useState(false);

  useEffect(() => {
    fetch(`${API_BASE_URL}/health`)
      .then(async (response) => {
        if (!response.ok) {
          throw new Error("Backend returned an error.");
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

  useEffect(() => {
    try {
      const result = runMLKEMSelfTest();

      console.log("PQ crypto test result:", result);
    } catch (error) {
      console.error("PQ crypto test failed:", error);
    }
  }, []);

  async function handleRegister(event) {
    event.preventDefault();

    setRegisterStatus("");
    setRegisterError("");
    setIsRegistering(true);

    try {
      const response = await fetch(`${API_BASE_URL}/auth/register`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          username,
          password,

          // Temporary test values.
          // These will be replaced by real client-side cryptography.
          wrappedMasterKey: "TEST_WRAPPED_MASTER_KEY",
          masterKeyIV: "TEST_MASTER_KEY_IV",
          masterKeyVersion: 1,

          mlKemPublicKey: "TEST_PUBLIC_KEY",
          wrappedMlKemPrivateKey: "TEST_WRAPPED_PRIVATE_KEY",
          privateKeyIV: "TEST_PRIVATE_KEY_IV",
        }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.message || "Registration failed.");
      }

      setRegisterStatus(
        `Registration successful for "${data.user.username}".`
      );

      setUsername("");
      setPassword("");
    } catch (err) {
      setRegisterError(err.message);
    } finally {
      setIsRegistering(false);
    }
  }

  return (
    <main className="container py-5">
      <div className="row justify-content-center">
        <div className="col-lg-8">
          <div className="card shadow-sm">
            <div className="card-body p-4">
              <span className="badge text-bg-dark mb-3">
                Frozen V1 — Authentication
              </span>

              <h1 className="h3">
                Quantum Safe Zero Knowledge File Sharing System
              </h1>

              <p className="text-secondary">
                Client-side encrypted file sharing with AES-256-GCM and
                ML-KEM-768 key establishment.
              </p>

              <hr />

              <h2 className="h6">Backend status</h2>

              <div
                className={`alert ${
                  error ? "alert-danger" : "alert-success"
                }`}
              >
                {status}
              </div>

              <hr />

              <h2 className="h5 mb-3">Create Account</h2>

              <form onSubmit={handleRegister}>
                <div className="mb-3">
                  <label htmlFor="username" className="form-label">
                    Username
                  </label>

                  <input
                    id="username"
                    type="text"
                    className="form-control"
                    value={username}
                    onChange={(event) => setUsername(event.target.value)}
                    placeholder="Enter username"
                    autoComplete="username"
                    required
                    minLength={3}
                    maxLength={50}
                  />
                </div>

                <div className="mb-3">
                  <label htmlFor="password" className="form-label">
                    Password
                  </label>

                  <input
                    id="password"
                    type="password"
                    className="form-control"
                    value={password}
                    onChange={(event) => setPassword(event.target.value)}
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
                  disabled={isRegistering}
                >
                  {isRegistering ? "Creating account..." : "Create Account"}
                </button>
              </form>

              <p className="small text-secondary mt-3 mb-0">
                Development test only: cryptographic key material is currently
                represented by placeholders. Real browser-side cryptography
                will be implemented in the next phase.
              </p>

              <hr />

              <p className="small text-secondary mb-0">
                Current stage: authentication foundation. Cryptographic
                functionality will be implemented incrementally according to
                Frozen V1.
              </p>
            </div>
          </div>
        </div>
      </div>
    </main>
  );
}

export default App;
