import crypto from "crypto";

import { env } from "../config/env.js";

export function requireAuth(req, res, next) {
  try {
    const authorization =
      req.headers.authorization;

    if (
      typeof authorization !== "string" ||
      !authorization.startsWith("Bearer ")
    ) {
      return res.status(401).json({
        message: "Authentication required.",
      });
    }

    const token =
      authorization.slice("Bearer ".length).trim();

    if (!token) {
      return res.status(401).json({
        message: "Authentication required.",
      });
    }

    const parts = token.split(".");

    if (parts.length !== 3) {
      return res.status(401).json({
        message: "Invalid authentication token.",
      });
    }

    const [encodedHeader, encodedPayload, encodedSignature] =
      parts;

    const signingInput =
      `${encodedHeader}.${encodedPayload}`;

    const expectedSignature =
      crypto
        .createHmac(
          "sha256",
          env.authTokenSecret
        )
        .update(signingInput)
        .digest("base64url");

    const expectedBuffer =
      Buffer.from(
        expectedSignature
      );

    const receivedBuffer =
      Buffer.from(
        encodedSignature
      );

    if (
      expectedBuffer.length !==
      receivedBuffer.length
    ) {
      return res.status(401).json({
        message: "Invalid authentication token.",
      });
    }

    if (
      !crypto.timingSafeEqual(
        expectedBuffer,
        receivedBuffer
      )
    ) {
      return res.status(401).json({
        message: "Invalid authentication token.",
      });
    }

    const payload =
      JSON.parse(
        Buffer.from(
          encodedPayload,
          "base64url"
        ).toString("utf8")
      );

    if (
      !payload ||
      typeof payload.userId !== "string" ||
      payload.userId.length === 0
    ) {
      return res.status(401).json({
        message: "Invalid authentication token.",
      });
    }

    if (
      typeof payload.exp !== "number" ||
      payload.exp <= Math.floor(Date.now() / 1000)
    ) {
      return res.status(401).json({
        message: "Authentication token has expired.",
      });
    }

    req.user = {
      id: payload.userId,
    };

    next();
  } catch {
    return res.status(401).json({
      message: "Invalid authentication token.",
    });
  }
}
