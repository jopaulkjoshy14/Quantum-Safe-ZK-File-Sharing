# Quantum Safe Zero Knowledge File Sharing System — Frozen V1

This repository is the initial implementation scaffold for the frozen V1 architecture.

## Stack

- Frontend: React + Vite + Bootstrap
- Backend: Node.js + Express
- Database: MongoDB Atlas
- File storage: MongoDB GridFS
- File encryption: AES-256-GCM
- Metadata encryption: AES-256-GCM
- Password KDF: PBKDF2-HMAC-SHA-256
- PQ KEM: ML-KEM-768 via `@noble/post-quantum`
- Browser crypto: Web Crypto API
- Deployment: Render

## Current scaffold

Phase 1 only:
- React/Vite frontend
- Express backend
- MongoDB connection layer
- Health endpoint
- Environment-variable templates
- Render configuration examples

Cryptographic and authentication implementation will be added incrementally in the frozen development order.

## Project structure

```text
quantum-safe-zk-file-sharing-v1/
├── client/
│   ├── src/
│   │   ├── App.jsx
│   │   ├── main.jsx
│   │   └── index.css
│   ├── .env.example
│   ├── index.html
│   ├── package.json
│   └── vite.config.js
├── server/
│   ├── src/
│   │   ├── config/env.js
│   │   ├── config/db.js
│   │   ├── app.js
│   │   └── server.js
│   ├── .env.example
│   └── package.json
├── .gitignore
└── README.md
```

## Local setup

### 1. Frontend

```bash
cd client
npm install
npm run dev
```

### 2. Backend

Open another terminal:

```bash
cd server
npm install
```

Copy `.env.example` to `.env` and fill in the MongoDB connection string.

Then:

```bash
npm run dev
```

Backend health check:

```text
http://localhost:5000/api/health
```

## MongoDB Atlas

Create an Atlas project and cluster, create a database user, and configure the network access list.

Then put the connection string in:

```text
server/.env
```

Example:

```env
PORT=5000
MONGODB_URI=mongodb+srv://<username>:<password>@<cluster>.mongodb.net/zk_file_sharing?retryWrites=true&w=majority
CLIENT_ORIGIN=http://localhost:5173
```

Never commit `.env`.

## Render deployment

Recommended order:

1. Create/prepare GitHub repository.
2. Create MongoDB Atlas cluster and credentials.
3. Push the project to GitHub.
4. Create the Render backend Web Service from the GitHub repository.
5. Add backend environment variables in Render.
6. Deploy the backend and verify `/api/health`.
7. Create the Render frontend Static Site from the same repository.
8. Set the frontend API URL to the deployed backend.
9. Update the backend `CLIENT_ORIGIN` to the deployed frontend URL.
10. Redeploy if necessary.

For a monorepo, configure Render's Root Directory separately:
- Backend: `server`
- Frontend: `client`

## Security rules

- Do not put MongoDB credentials in frontend code.
- Do not commit `.env`.
- Do not put plaintext cryptographic keys in localStorage/sessionStorage.
- Do not send plaintext files to the backend.
- Do not implement cryptographic primitives manually.
- Do not use the Master Key directly for unrelated purposes.
- Do not derive FEKs from filenames or predictable metadata.

## Important V1 terminology

Use:

> zero-knowledge/provider-blind with respect to file plaintext and plaintext file-decryption keys

Do not describe the application as a formal zero-knowledge proof system.
