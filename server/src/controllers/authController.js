import {
  registerUser,
  loginUser,
} from "../services/authService.js";

export async function register(req, res) {
  try {
    const {
      username,
      password,

      // Client-side KDF parameters used to protect
      // the Master Key.
      passwordKdfSalt,
      passwordKdfParams,

      wrappedMasterKey,
      masterKeyIV,
      masterKeyVersion,

      mlKemPublicKey,
      wrappedMlKemPrivateKey,
      privateKeyIV,
    } = req.body;

    const result = await registerUser({
      username,
      password,

      // Preserve the exact KDF parameters generated
      // by the browser.
      passwordKdfSalt,
      passwordKdfParams,

      wrappedMasterKey,
      masterKeyIV,
      masterKeyVersion,

      mlKemPublicKey,
      wrappedMlKemPrivateKey,
      privateKeyIV,
    });

    return res.status(201).json({
      ok: true,
      message: "User registered successfully.",
      user: {
        id: result.userId,
        username: result.username,
      },
    });
  } catch (error) {
    console.error("Registration error:", error);

    return res.status(400).json({
      ok: false,
      message: error.message || "Registration failed.",
    });
  }
}

export async function login(req, res) {
  try {
    const {
      username,
      password,
    } = req.body;

    const result = await loginUser({
      username,
      password,
    });

    return res.status(200).json({
      ok: true,
      message: "Login successful.",

      /*
       * These values are protected cryptographic material.
       *
       * The browser will use them to recover the Master Key
       * locally. The server does not decrypt them.
       */
      user: {
        id: result.userId,
        username: result.username,

        passwordKdfSalt: result.passwordKdfSalt,
        passwordKdfParams: result.passwordKdfParams,

        wrappedMasterKey: result.wrappedMasterKey,
        masterKeyIV: result.masterKeyIV,
        masterKeyVersion: result.masterKeyVersion,

        mlKemPublicKey: result.mlKemPublicKey,
        wrappedMlKemPrivateKey:
          result.wrappedMlKemPrivateKey,
        privateKeyIV: result.privateKeyIV,
      },
    });
  } catch (error) {
    console.error("Login error:", error);

    return res.status(401).json({
      ok: false,
      message: error.message || "Login failed.",
    });
  }
}
