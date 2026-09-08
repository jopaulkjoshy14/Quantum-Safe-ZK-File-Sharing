import { registerUser } from "../services/authService.js";

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
