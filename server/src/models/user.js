import { ObjectId } from "mongodb";
import { getDatabase } from "../config/db.js";

const USERS_COLLECTION = "users";

export function getUsersCollection() {
  return getDatabase().collection(USERS_COLLECTION);
}

export async function ensureUserIndexes() {
  const users = getUsersCollection();

  await users.createIndex(
    { username: 1 },
    {
      unique: true,
      name: "username_unique",
    }
  );
}

export function createUserDocument({
  username,

  // Server-side password authentication data
  passwordHash,
  passwordHashSalt,
  passwordHashKdfParams,

  // Client-side Master Key protection data
  passwordKdfSalt,
  passwordKdfParams,

  // Protected Master Key
  wrappedMasterKey,
  masterKeyIV,
  masterKeyVersion,

  // ML-KEM-768 key material
  mlKemPublicKey,
  wrappedMlKemPrivateKey,
  privateKeyIV,
}) {
  return {
    username,

    // Used by the server to verify the user's password.
    passwordHash,
    passwordHashSalt,
    passwordHashKdfParams,

    // Used by the browser to derive the KEK
    // required to unwrap the Master Key.
    passwordKdfSalt,
    passwordKdfParams,

    wrappedMasterKey,
    masterKeyIV,
    masterKeyVersion,

    mlKemPublicKey,
    wrappedMlKemPrivateKey,
    privateKeyIV,

    createdAt: new Date(),
  };
}

export async function findUserByUsername(username) {
  return getUsersCollection().findOne({ username });
}

export async function findUserById(userId) {
  let objectId;

  try {
    objectId = new ObjectId(userId);
  } catch {
    return null;
  }

  return getUsersCollection().findOne({
    _id: objectId,
  });
}

export async function insertUser(userDocument) {
  return getUsersCollection().insertOne(userDocument);
}
