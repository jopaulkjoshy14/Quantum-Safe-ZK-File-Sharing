import express from "express";
import cors from "cors";
import helmet from "helmet";
import { env } from "./config/env.js";

const app = express();

app.disable("x-powered-by");

app.use(
  helmet({
    crossOriginResourcePolicy: { policy: "cross-origin" },
  })
);

app.use(
  cors({
    origin: env.clientOrigin,
  })
);

app.use(express.json({ limit: "1mb" }));

app.get("/api/health", (_req, res) => {
  res.json({
    ok: true,
    message: "Backend is running.",
  });
});

export default app;
