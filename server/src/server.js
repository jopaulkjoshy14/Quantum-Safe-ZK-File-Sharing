import app from "./app.js";
import { env } from "./config/env.js";
import { connectDatabase } from "./config/db.js";
import { ensureUserIndexes } from "./models/user.js";

async function startServer() {
  try {
    await connectDatabase();

    await ensureUserIndexes();

    console.log("Database indexes verified.");

    app.listen(env.port, "0.0.0.0", () => {
      console.log(`Server listening on port ${env.port}`);
    });
  } catch (error) {
    console.error("Failed to start server:", error);
    process.exit(1);
  }
}

startServer();
