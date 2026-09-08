import { registerUser } from "../services/authService.js";

export async function register(req, res) {
  try {
    const {
      username,
      password,
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
