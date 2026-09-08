import "dotenv/config";

const requiredVariables = ["MONGODB_URI"];

for (const variable of requiredVariables) {
  if (!process.env[variable]) {
    throw new Error(`Missing required environment variable: ${variable}`);
  }
}

export const env = {
  port: Number(process.env.PORT || 5000),
  mongodbUri: process.env.MONGODB_URI,
  clientOrigin: process.env.CLIENT_ORIGIN || "http://localhost:5173",
  nodeEnv: process.env.NODE_ENV || "development",
};
