import express from "express";
import cors from "cors";
import helmet from "helmet";

import { env } from "./config/env.js";

import authRoutes from "./routes/authRoutes.js";
import fileRoutes from "./routes/fileRoutes.js";
import shareRoutes from "./routes/shareRoutes.js";

const app = express();

app.disable("x-powered-by");

app.use(
  helmet({
    crossOriginResourcePolicy: {
      policy: "cross-origin",
    },
  })
);

app.use(
  cors({
    origin: env.clientOrigin,
  })
);

app.use(
  express.json({
    limit: "150mb",
  })
);

app.get("/api/health", (_req, res) => {
  res.json({
    ok: true,
    message: "Backend is running.",
  });
});

/*
 * Authentication routes
 *
 * POST /api/auth/register
 * POST /api/auth/login
 */
app.use(
  "/api/auth",
  authRoutes
);

/*
 * File routes
 *
 * POST /api/files/upload
 *
 * The frontend sends encrypted file data.
 * The backend stores the ciphertext in GridFS.
 */
app.use(
  "/api/files",
  fileRoutes
);

app.use(
  "/api/shares",
  shareRoutes
);

export default app;
