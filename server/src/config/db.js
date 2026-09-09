import { MongoClient } from "mongodb";
import { env } from "./env.js";

const client = new MongoClient(env.mongodbUri);

let database;

export async function connectDatabase() {
  if (database) {
    return database;
  }

  await client.connect();

  database = client.db();
  console.log(`MongoDB connected: ${database.databaseName}`);

  return database;
}

export function getDatabase() {
  if (!database) {
    throw new Error("Database has not been connected yet.");
  }

  return database;
}

export async function closeDatabase() {
  await client.close();
  database = undefined;
}
