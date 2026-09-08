import crypto from "node:crypto";
import {
  getUsersCollection,
  createUserDocument,
} from "../models/user.js";

const PASSWORD_HASH_ITERATIONS = 310000;
const PASSWORD_HASH_KEY_LENGTH = 32;
const PASSWORD_HASH_DIGEST = "sha256";
const PASSWORD_SALT_LENGTH = 16;

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

function hashPassword(password) {
  return new Promise((resolve, reject) => {
    const salt = crypto.randomBytes(PASSWORD_SALT_LENGTH);

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
          passwordKdfSalt: salt.toString("base64"),
          passwordKdfParams: {
            algorithm: "PBKDF2-HMAC-SHA-256",
            iterations: PASSWORD_HASH_ITERATIONS,
            keyLength: PASSWORD_HASH_KEY_LENGTH,
          },
        });
      }
    );
  });
}

export async function registerUser({
  username,
  password,
  wrappedMasterKey,
  masterKeyIV,
  masterKeyVersion,
  mlKemPublicKey,
  wrappedMlKemPrivateKey,
  privateKeyIV,
}) {
  const normalizedUsername = validateUsername(username);

  validatePassword(password);

  if (!wrappedMasterKey || !masterKeyIV) {
    throw new Error("Protected Master Key data is required.");
  }

  if (!mlKemPublicKey || !wrappedMlKemPrivateKey || !privateKeyIV) {
    throw new Error("Protected ML-KEM key data is required.");
  }

  const users = getUsersCollection();

  const existingUser = await users.findOne({
    username: normalizedUsername,
  });

  if (existingUser) {
    throw new Error("Username is already registered.");
  }

  const {
    passwordHash,
    passwordKdfSalt,
    passwordKdfParams,
  } = await hashPassword(password);

  const userDocument = createUserDocument({
    username: normalizedUsername,

    passwordHash,
    passwordKdfSalt,
    passwordKdfParams,

    wrappedMasterKey,
    masterKeyIV,
    masterKeyVersion,

    mlKemPublicKey,
    wrappedMlKemPrivateKey,
    privateKeyIV,
  });

  const result = await users.insertOne(userDocument);

  return {
    userId: result.insertedId,
    username: normalizedUsername,
  };
}
