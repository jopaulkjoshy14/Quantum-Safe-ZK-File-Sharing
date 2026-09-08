import crypto from "node:crypto";
import {
  getUsersCollection,
  createUserDocument,
} from "../models/user.js";

const PASSWORD_HASH_ITERATIONS = 310000;
const PASSWORD_HASH_KEY_LENGTH = 32;
const PASSWORD_HASH_DIGEST = "sha256";
const PASSWORD_HASH_SALT_LENGTH = 16;

function normalizeUsername(username) {
  return username.trim().toLowerCase();
}

function validateUsername(username) {
  if (typeof username !== "string") {
    throw new Error("Username must be a string.");
  }

  const normalizedUsername = normalizeUsername(username);

  if (normalizedUsername.length < 3 || normalizedUsername.length > 50) {
    throw new Error("Username must be between 3 and 50 characters.");
  }

  if (!/^[a-z0-9._-]+$/.test(normalizedUsername)) {
    throw new Error(
      "Username may contain only letters, numbers, dots, underscores, and hyphens."
    );
  }

  return normalizedUsername;
}

function validatePassword(password) {
  if (typeof password !== "string") {
    throw new Error("Password must be a string.");
  }

  if (password.length < 8) {
    throw new Error("Password must be at least 8 characters long.");
  }

  if (password.length > 128) {
    throw new Error("Password must not exceed 128 characters.");
  }
}

function validateClientKdfParameters(
  passwordKdfSalt,
  passwordKdfParams
) {
  if (
    typeof passwordKdfSalt !== "string" ||
    passwordKdfSalt.length === 0
  ) {
    throw new Error("Client password KDF salt is required.");
  }

  if (
    !passwordKdfParams ||
    typeof passwordKdfParams !== "object"
  ) {
    throw new Error("Client password KDF parameters are required.");
  }

  if (
    passwordKdfParams.algorithm !==
    "PBKDF2-HMAC-SHA-256"
  ) {
    throw new Error("Unsupported client password KDF algorithm.");
  }

  if (passwordKdfParams.iterations !== 310000) {
    throw new Error(
      "Invalid client password KDF iteration count."
    );
  }

  if (passwordKdfParams.keyLength !== 256) {
    throw new Error(
      "Invalid client password KDF key length."
    );
  }
}

function hashPassword(password) {
  return new Promise((resolve, reject) => {
    const salt = crypto.randomBytes(
      PASSWORD_HASH_SALT_LENGTH
    );

    crypto.pbkdf2(
      password,
      salt,
      PASSWORD_HASH_ITERATIONS,
      PASSWORD_HASH_KEY_LENGTH,
      PASSWORD_HASH_DIGEST,
      (error, hash) => {
        if (error) {
          reject(error);
          return;
        }

        resolve({
          passwordHash: hash.toString("base64"),

          passwordHashSalt: salt.toString("base64"),

          passwordHashKdfParams: {
            algorithm: "PBKDF2-HMAC-SHA-256",
            iterations: PASSWORD_HASH_ITERATIONS,
            keyLength: PASSWORD_HASH_KEY_LENGTH,
          },
        });
      }
    );
  });
}

function verifyPassword(password, storedHash, storedSalt, params) {
  return new Promise((resolve, reject) => {
    if (
      params?.algorithm !== "PBKDF2-HMAC-SHA-256" ||
      params?.iterations !== PASSWORD_HASH_ITERATIONS ||
      params?.keyLength !== PASSWORD_HASH_KEY_LENGTH
    ) {
      reject(
        new Error(
          "Unsupported stored password hashing parameters."
        )
      );
      return;
    }

    let expectedHash;
    let salt;

    try {
      expectedHash = Buffer.from(storedHash, "base64");
      salt = Buffer.from(storedSalt, "base64");
    } catch {
      reject(new Error("Invalid stored password hash data."));
      return;
    }

    crypto.pbkdf2(
      password,
      salt,
      params.iterations,
      params.keyLength,
      PASSWORD_HASH_DIGEST,
      (error, derivedHash) => {
        if (error) {
          reject(error);
          return;
        }

        if (
          expectedHash.length !== derivedHash.length
        ) {
          resolve(false);
          return;
        }

        resolve(
          crypto.timingSafeEqual(
            expectedHash,
            derivedHash
          )
        );
      }
    );
  });
}

export async function registerUser({
  username,
  password,

  // Client-side KDF parameters.
  // These MUST be the exact parameters used by the browser
  // to derive the KEK that protects the Master Key.
  passwordKdfSalt,
  passwordKdfParams,

  wrappedMasterKey,
  masterKeyIV,
  masterKeyVersion,

  mlKemPublicKey,
  wrappedMlKemPrivateKey,
  privateKeyIV,
}) {
  const normalizedUsername =
    validateUsername(username);

  validatePassword(password);

  validateClientKdfParameters(
    passwordKdfSalt,
    passwordKdfParams
  );

  if (!wrappedMasterKey || !masterKeyIV) {
    throw new Error(
      "Protected Master Key data is required."
    );
  }

  if (
    !mlKemPublicKey ||
    !wrappedMlKemPrivateKey ||
    !privateKeyIV
  ) {
    throw new Error(
      "Protected ML-KEM key data is required."
    );
  }

  const users = getUsersCollection();

  const existingUser = await users.findOne({
    username: normalizedUsername,
  });

  if (existingUser) {
    throw new Error(
      "Username is already registered."
    );
  }

  /*
   * Generate a SEPARATE server-side password hash.
   *
   * This salt is unrelated to the client-side
   * passwordKdfSalt.
   */
  const {
    passwordHash,
    passwordHashSalt,
    passwordHashKdfParams,
  } = await hashPassword(password);

  const userDocument = createUserDocument({
    username: normalizedUsername,

    // Server authentication
    passwordHash,
    passwordHashSalt,
    passwordHashKdfParams,

    // Client-side Master Key protection
    passwordKdfSalt,
    passwordKdfParams,

    // Protected Master Key
    wrappedMasterKey,
    masterKeyIV,
    masterKeyVersion,

    // ML-KEM-768
    mlKemPublicKey,
    wrappedMlKemPrivateKey,
    privateKeyIV,
  });

  const result = await users.insertOne(
    userDocument
  );

  return {
    userId: result.insertedId,
    username: normalizedUsername,
  };
}

/**
 * Authenticate an existing user.
 *
 * IMPORTANT:
 * The server verifies the password but NEVER derives
 * or receives the user's Master Key.
 *
 * After successful authentication, the browser receives
 * the protected cryptographic material required to recover
 * the Master Key locally.
 */
export async function loginUser({
  username,
  password,
}) {
  const normalizedUsername =
    validateUsername(username);

  validatePassword(password);

  const users = getUsersCollection();

  const user = await users.findOne({
    username: normalizedUsername,
  });

  if (!user) {
    throw new Error("Invalid username or password.");
  }

  const passwordValid = await verifyPassword(
    password,
    user.passwordHash,
    user.passwordHashSalt,
    user.passwordHashKdfParams
  );

  if (!passwordValid) {
    throw new Error("Invalid username or password.");
  }

  /*
   * Return only information the browser needs.
   *
   * No plaintext password, Master Key, ML-KEM secret key,
   * or derived KEK is returned or generated by the server.
   */
  return {
    userId: user._id,
    username: user.username,

    // Browser uses these to derive the KEK.
    passwordKdfSalt: user.passwordKdfSalt,
    passwordKdfParams: user.passwordKdfParams,

    // Browser unwraps the Master Key locally.
    wrappedMasterKey: user.wrappedMasterKey,
    masterKeyIV: user.masterKeyIV,
    masterKeyVersion: user.masterKeyVersion,

    // Browser unwraps the ML-KEM secret key locally.
    mlKemPublicKey: user.mlKemPublicKey,
    wrappedMlKemPrivateKey:
      user.wrappedMlKemPrivateKey,
    privateKeyIV: user.privateKeyIV,
  };
}
