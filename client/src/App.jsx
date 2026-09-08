import { useEffect, useState } from "react";

const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL || "http://localhost:5000/api";

function App() {
  const [status, setStatus] = useState("Checking backend...");
  const [error, setError] = useState("");

  useEffect(() => {
    fetch(`${API_BASE_URL}/health`)
      .then(async (response) => {
        if (!response.ok) {
          throw new Error("Backend returned an error.");
        }

        return response.json();
      })
      .then((data) => setStatus(data.message))
      .catch((err) => {
        setError(err.message);
        setStatus("Backend unavailable");
      });
  }, []);

  return (
    <main className="container py-5">
      <div className="row justify-content-center">
        <div className="col-lg-8">
          <div className="card shadow-sm">
            <div className="card-body p-4">
              <span className="badge text-bg-dark mb-3">
                Frozen V1 — Foundation
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

              <div className={`alert ${error ? "alert-danger" : "alert-success"}`}>
                {status}
              </div>

              <p className="small text-secondary mb-0">
                Current stage: project foundation. Cryptographic functionality
                will be implemented incrementally according to Frozen V1.
              </p>
            </div>
          </div>
        </div>
      </div>
    </main>
  );
}

export default App;
