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
  passwordHash,
  passwordKdfSalt,
  passwordKdfParams,
  wrappedMasterKey,
  masterKeyIV,
  masterKeyVersion,
  mlKemPublicKey,
  wrappedMlKemPrivateKey,
  privateKeyIV,
}) {
  return {
    username,
    passwordHash,
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
  return getUsersCollection().findOne({ _id: userId });
}

export async function insertUser(userDocument) {
  return getUsersCollection().insertOne(userDocument);
}
