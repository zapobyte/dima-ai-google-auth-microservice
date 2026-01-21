type LogLevel = "debug" | "info" | "warn" | "error";

const SERVICE_NAME = "google-authentication-microservice";

const LEVEL_ORDER: Record<LogLevel, number> = {
  debug: 10,
  info: 20,
  warn: 30,
  error: 40,
};

function normalizeLevel(input: unknown): LogLevel {
  const v = String(input || "").trim().toLowerCase();
  if (v === "debug" || v === "info" || v === "warn" || v === "error") return v;
  return "info";
}

const MIN_LEVEL: LogLevel = normalizeLevel(process.env.LOG_LEVEL);

const SENSITIVE_KEYS = new Set([
  "authorization",
  "cookie",
  "set-cookie",
  "token",
  "tokens",
  "accessToken",
  "access_token",
  "refreshToken",
  "refresh_token",
  "jwt",
  "jwtSecret",
  "jwt_secret",
  "clientSecret",
  "client_secret",
  "googleClientSecret",
  "GOOGLE_CLIENT_SECRET",
  "JWT_SECRET",
  "code", // OAuth code
  "state", // OAuth state (can contain returnTo)
]);

function shouldRedactKey(key: string): boolean {
  const k = key.trim();
  if (!k) return false;
  if (SENSITIVE_KEYS.has(k)) return true;
  // common header casing / variants
  if (SENSITIVE_KEYS.has(k.toLowerCase())) return true;
  return false;
}

function redactValue(_value: unknown) {
  return "[REDACTED]";
}

function safeCloneAndRedact(input: unknown, depth = 0): unknown {
  if (depth > 12) return "[Truncated]";
  if (input === null || input === undefined) return input;
  if (typeof input === "string" || typeof input === "number" || typeof input === "boolean") return input;

  if (input instanceof Error) {
    return {
      name: input.name,
      message: input.message,
      stack: typeof input.stack === "string" ? input.stack.split("\n").slice(0, 25).join("\n") : undefined,
    };
  }

  if (Array.isArray(input)) {
    return input.slice(0, 200).map((v) => safeCloneAndRedact(v, depth + 1));
  }

  if (typeof input === "object") {
    const obj = input as Record<string, unknown>;
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(obj)) {
      if (shouldRedactKey(k)) {
        out[k] = redactValue(v);
      } else {
        out[k] = safeCloneAndRedact(v, depth + 1);
      }
    }
    return out;
  }

  // fallback for bigint/symbol/function etc.
  try {
    return String(input);
  } catch {
    return "[Unserializable]";
  }
}

function levelEnabled(level: LogLevel): boolean {
  return LEVEL_ORDER[level] >= LEVEL_ORDER[MIN_LEVEL];
}

export type LogFields = Record<string, unknown> & {
  event: string;
  message?: string;
  requestId?: string;
  traceparent?: string;
  method?: string;
  path?: string;
  route?: string;
  statusCode?: number;
  durationMs?: number;
  userId?: number;
  googleService?: string;
};

function emit(level: LogLevel, fields: LogFields) {
  if (!levelEnabled(level)) return;

  const base = {
    timestamp: new Date().toISOString(),
    level,
    service: SERVICE_NAME,
  };

  const payload = safeCloneAndRedact({ ...base, ...fields });
  // eslint-disable-next-line no-console
  console.log(JSON.stringify(payload));
}

export const logger = {
  debug: (fields: LogFields) => emit("debug", fields),
  info: (fields: LogFields) => emit("info", fields),
  warn: (fields: LogFields) => emit("warn", fields),
  error: (fields: LogFields) => emit("error", fields),
};

