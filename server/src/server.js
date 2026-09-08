import app from "./app.js";
import { env } from "./config/env.js";
import { connectDatabase } from "./config/db.js";

async function startServer() {
  try {
    await connectDatabase();

    app.listen(env.port, "0.0.0.0", () => {
      console.log(`Server listening on port ${env.port}`);
    });
  } catch (error) {
    console.error("Failed to start server:", error);
    process.exit(1);
  }
}

startServer();
