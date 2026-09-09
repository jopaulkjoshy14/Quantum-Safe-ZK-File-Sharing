# Quantum Safe Zero Knowledge File Sharing System

A cloud-based, client-side encrypted file-sharing system using **AES-256-GCM** for file protection and **ML-KEM-768** for post-quantum secure key establishment during sharing.

> **Security terminology:** The system is *zero-knowledge/provider-blind with respect to file plaintext and plaintext file-decryption keys*. It is not a formal zero-knowledge proof system.

## Architecture

- **Frontend:** React + Vite + Bootstrap
- **Backend:** Node.js + Express
- **Database:** MongoDB Atlas
- **File storage:** MongoDB GridFS
- **File encryption:** AES-256-GCM
- **Metadata encryption:** AES-256-GCM
- **Password KDF:** PBKDF2-HMAC-SHA-256, 310,000 iterations
- **Post-quantum KEM:** ML-KEM-768 via `@noble/post-quantum`
- **Key derivation:** HKDF-SHA-256 with domain separation
- **Authentication:** HMAC-SHA-256 signed short-lived bearer token
- **Transport:** HTTPS/TLS
- **Deployment:** Render

## Implemented features

### Account and key protection
- Browser-generated random 256-bit Master Key
- Password-derived KEK protects the Master Key
- ML-KEM-768 key pair generated in the browser
- ML-KEM private key protected by the Master Key
- Authentication separated from cryptographic key material
- Authentication token and cryptographic keys kept in runtime memory only

### Encrypted file storage
- Fresh random FEK for every file
- AES-256-GCM file encryption before upload
- Separate random metadata encryption key
- Encrypted filename, MIME type, and size
- Dedicated Master-Key-derived wrapping keys
- Encrypted ciphertext stored in GridFS
- Authenticated owner-only file retrieval

### Secure sharing
1. Sender looks up the recipient's ML-KEM-768 public key.
2. Sender obtains only the protected owner key material.
3. Browser unwraps the FEK and metadata key locally.
4. Sender performs ML-KEM-768 encapsulation against the recipient public key.
5. Browser derives a dedicated sharing wrapping key using HKDF-SHA-256.
6. Browser wraps the FEK and metadata key for the recipient.
7. Backend stores the ML-KEM ciphertext and protected recipient key package.
8. Recipient decapsulates with their ML-KEM private key.
9. Recipient derives the same sharing wrapping key and unwraps the FEK.
10. File and metadata are decrypted entirely inside the recipient browser.

The server never performs ML-KEM decapsulation or file decryption.

### Access revocation
- Sender can revoke an active share.
- Revoked shares can no longer be used through the sharing endpoint.
- A recipient who already downloaded plaintext cannot be remotely forced to delete it.

## Data protection model

The backend may know operational information such as:

- account IDs/usernames
- recipient IDs
- file IDs
- share IDs
- authorization relationships
- timestamps
- public keys
- cryptographic algorithm/version identifiers

The backend does **not** receive:

- plaintext file contents
- plaintext FEKs
- plaintext metadata during upload
- the user's Master Key
- the user's ML-KEM private key in plaintext

## Project structure

```text
Quantum-Safe-ZK-File-Sharing/
├── client/
│   └── src/
│       ├── components/
│       │   └── SharingPanel.jsx
│       ├── crypto/
│       │   ├── crypto.js
│       │   ├── fileCrypto.js
│       │   ├── keyProtection.js
│       │   ├── keyWrapping.js
│       │   ├── loginCrypto.js
│       │   ├── metadataCrypto.js
│       │   ├── mlKem.js
│       │   ├── registrationCrypto.js
│       │   └── shareWrapping.js
│       ├── services/
│       │   ├── fileDownloadService.js
│       │   ├── fileUploadService.js
│       │   └── shareService.js
│       ├── App.jsx
│       └── main.jsx
├── server/
│   └── src/
│       ├── config/
│       ├── controllers/
│       │   ├── authController.js
│       │   ├── fileController.js
│       │   └── shareController.js
│       ├── middleware/
│       ├── models/
│       │   ├── file.js
│       │   ├── share.js
│       │   └── user.js
│       ├── routes/
│       │   ├── authRoutes.js
│       │   ├── fileRoutes.js
│       │   └── shareRoutes.js
│       ├── services/
│       │   └── authService.js
│       ├── app.js
│       └── server.js
└── render.yaml
```

## Render deployment

Current deployment:

- Frontend: `https://qszkfss-frontend.onrender.com`
- Backend: `https://qszkfss-backend.onrender.com`
- Backend health: `https://qszkfss-backend.onrender.com/api/health`

Backend environment variables:

```env
MONGODB_URI=<MongoDB Atlas connection string>
AUTH_TOKEN_SECRET=<long random secret>
CLIENT_ORIGIN=https://qszkfss-frontend.onrender.com
NODE_ENV=production
```

Frontend:

```env
VITE_API_BASE_URL=https://qszkfss-backend.onrender.com/api
```

Never commit secrets to GitHub.

## Security rules

- Never send plaintext files to the backend.
- Never store Master Keys, FEKs, ML-KEM private keys, or authentication tokens in `localStorage`, `sessionStorage`, or IndexedDB.
- Never derive FEKs from filenames or predictable metadata.
- Never use the Master Key directly for unrelated cryptographic purposes.
- Use fresh AES-GCM IVs for independent encryption operations.
- Do not implement cryptographic primitives manually.
- Treat the browser as the trusted cryptographic endpoint.
- Treat the backend as an authorization, storage, and transport service.

## V1 limitations

- Password recovery is intentionally not implemented.
- Search is browser-side after metadata decryption.
- ML-KEM provides key establishment, not identity authentication; account-to-public-key binding is currently trusted through the authenticated backend.
- Revocation prevents future server-authorized access but cannot recall plaintext already downloaded by a recipient.
- Multi-device cryptographic synchronization is not implemented.
