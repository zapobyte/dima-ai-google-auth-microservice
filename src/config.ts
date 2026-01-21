import dotenv from "dotenv";

dotenv.config();

function requiredEnv(name: string): string {
  const v = process.env[name];
  if (!v || !String(v).trim()) throw new Error(`Missing required env var: ${name}`);
  return String(v).trim();
}

function optionalEnv(name: string, fallback: string | null = null): string | null {
  const v = process.env[name];
  if (!v || !String(v).trim()) return fallback;
  return String(v).trim();
}
const databasePath = optionalEnv("DATABASE_PATH", "./auth.db");
const port = optionalEnv("PORT", "5050");

const config = {
  port: port,
  baseUrl: requiredEnv("BASE_URL").replace(/\/$/, ""),
  googleClientId: requiredEnv("GOOGLE_CLIENT_ID"),
  googleClientSecret: requiredEnv("GOOGLE_CLIENT_SECRET"),
  jwtSecret: requiredEnv("JWT_SECRET"),
  jwtExpiresInSeconds: 15 * 60,
  allowedReturnOrigins: (optionalEnv("ALLOWED_RETURN_ORIGINS", "") || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean),
  databasePath: databasePath?.toString()!,
};

export default config;

