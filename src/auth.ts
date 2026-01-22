import jwt from "jsonwebtoken";
import { google } from "googleapis";
import { createHash, randomBytes } from "crypto";
import  config  from "./config";
import { logger } from "./utils/logger";
import {
  createSession,
  findSessionByRefreshHash,
  getTokenRow,
  listGrantedServices,
  revokeSession,
  touchSession,
  upsertTokens,
  upsertUser,
  getUser,
} from "./database";
import type { GoogleService, JwtPayload } from "./types";

const SERVICE_SCOPES: Record<GoogleService, string[]> = {
  drive: [
    "https://www.googleapis.com/auth/drive"
  ],
  calendar: [
    "https://www.googleapis.com/auth/calendar",
    // "https://www.googleapis.com/auth/calendar.readonly",
    // "https://www.googleapis.com/auth/calendar.events",
  ],
  forms: [
      "https://www.googleapis.com/auth/forms",
    // "https://www.googleapis.com/auth/forms.body",
    // "https://www.googleapis.com/auth/forms.responses.readonly",
    // "https://www.googleapis.com/auth/drive.readonly",
  ],
  gmail: [
    "https://www.googleapis.com/auth/gmail",
    // "https://www.googleapis.com/auth/gmail.readonly"
  ],
  youtube: [
    "https://www.googleapis.com/auth/youtube",
    // "https://www.googleapis.com/auth/youtube.readonly"
  ],
  analytics: [
    "https://www.googleapis.com/auth/analytics",
    // "https://www.googleapis.com/auth/analytics.readonly"

  ],
};

export function getScopesForService(service: GoogleService): string[] {
  return SERVICE_SCOPES[service] || [];
}

export function createOAuthClient(redirectUri: string) {
  return new google.auth.OAuth2(config.googleClientId, config.googleClientSecret, redirectUri);
}

export function issueJwt(userId: number): string {
  const u = getUser(userId);
  const grantedServices = listGrantedServices(userId) as GoogleService[];
  const payload: JwtPayload = {
    userId,
    email: u?.email ?? null,
    grantedServices,
  };
  return jwt.sign(payload, config.jwtSecret, {
    expiresIn: config.jwtExpiresInSeconds,
  });
}

export function verifyJwt(token: string): JwtPayload {
  const decoded = jwt.verify(token, config.jwtSecret) as JwtPayload;
  return decoded;
}

function sha256Hex(input: string): string {
  return createHash("sha256").update(input, "utf8").digest("hex");
}

function newRefreshToken(): string {
  return randomBytes(48).toString("base64url");
}

export function validateReturnTo(returnTo: string | null): string | null {
  if (!returnTo) return null;
  let u: URL;
  try {
    u = new URL(returnTo);
  } catch {
    return null;
  }
  const origin = u.origin;
  if (config.allowedReturnOrigins.length === 0) return returnTo;
  if (!config.allowedReturnOrigins.includes(origin)) return null;
  return returnTo;
}

export function createRefreshSession(userId: number): { refreshToken: string; expiresAt: number } {
  const refreshToken = newRefreshToken();
  const refreshTokenHash = sha256Hex(refreshToken);
  const expiresAt = Date.now() + 30 * 24 * 60 * 60 * 1000; // 30 days
  createSession({ userId, refreshTokenHash, expiresAt });
  return { refreshToken, expiresAt };
}

export function rotateRefreshSession(refreshToken: string): { userId: number; refreshToken: string; expiresAt: number } | null {
  const now = Date.now();
  const hash = sha256Hex(refreshToken);
  const session = findSessionByRefreshHash(hash);
  if (!session) return null;
  if (session.revoked_at) return null;
  if (session.expires_at <= now) return null;

  // rotate: revoke current, create new
  touchSession(session.id, now);
  revokeSession(session.id, now);

  const next = createRefreshSession(session.user_id);
  return { userId: session.user_id, refreshToken: next.refreshToken, expiresAt: next.expiresAt };
}

export function revokeRefreshSession(refreshToken: string): boolean {
  const now = Date.now();
  const hash = sha256Hex(refreshToken);
  const session = findSessionByRefreshHash(hash);
  if (!session) return false;
  if (session.revoked_at) return true;
  revokeSession(session.id, now);
  return true;
}

export async function exchangeCodeAndStoreTokens(params: {
  userId: number;
  service: GoogleService;
  code: string;
  redirectUri: string;
}) {
  const oauth2Client = createOAuthClient(params.redirectUri);
  const { tokens } = await oauth2Client.getToken(params.code);

  oauth2Client.setCredentials(tokens);
  let email: string | null = null;
  let name: string | null = null;
  let picture: string | null = null;
  try {
    const oauth2 = google.oauth2({ version: "v2", auth: oauth2Client });
    const userinfo = await oauth2.userinfo.get();
    email = (userinfo.data.email as string) || null;
    name = (userinfo.data.name as string) || null;
    picture = (userinfo.data.picture as string) || null;
  } catch {
    // profile fetch is best-effort
  }

  upsertUser({ id: params.userId, email, name, picture });
  upsertTokens({
    userId: params.userId,
    service: params.service,
    accessToken: tokens.access_token || null,
    refreshToken: tokens.refresh_token || null,
    expiryDate: typeof tokens.expiry_date === "number" ? tokens.expiry_date : null,
    scopes: tokens.scope || getScopesForService(params.service).join(" "),
  });
}

export async function getValidAccessToken(params: {
  userId: number;
  service: GoogleService;
  redirectUri: string;
  requestId?: string;
  traceparent?: string;
}) {
  const row = getTokenRow(params.userId, params.service);
  if (!row?.refresh_token) return null;

  const now = Date.now();
  const expiresAt = row.expiry_date ?? 0;
  const isExpired = !expiresAt || expiresAt <= now + 30_000; // 30s skew

  if (!isExpired && row.access_token) {
    logger.info({
      event: "google_access_token_cache_hit",
      message: "Using cached Google access token",
      requestId: params.requestId,
      traceparent: params.traceparent,
      userId: params.userId,
      googleService: params.service,
    });
    return row.access_token;
  }

  logger.info({
    event: "google_access_token_refresh_attempt",
    message: "Refreshing Google access token",
    requestId: params.requestId,
    traceparent: params.traceparent,
    userId: params.userId,
    googleService: params.service,
    expiresAt,
  });

  const oauth2Client = createOAuthClient(params.redirectUri);
  oauth2Client.setCredentials({
    refresh_token: row.refresh_token,
    access_token: row.access_token || undefined,
    expiry_date: row.expiry_date || undefined,
  });

  let credentials;
  try {
    const refreshed = await oauth2Client.refreshAccessToken();
    credentials = refreshed.credentials;
  } catch (e) {
    logger.warn({
      event: "google_access_token_refresh_failed",
      message: "Google access token refresh failed",
      requestId: params.requestId,
      traceparent: params.traceparent,
      userId: params.userId,
      googleService: params.service,
      error: e,
    });
    throw e;
  }

  upsertTokens({
    userId: params.userId,
    service: params.service,
    accessToken: credentials.access_token || row.access_token || null,
    refreshToken: credentials.refresh_token || null,
    expiryDate: typeof credentials.expiry_date === "number" ? credentials.expiry_date : row.expiry_date,
    scopes: credentials.scope || row.scopes || null,
  });

  logger.info({
    event: "google_access_token_refresh_succeeded",
    message: "Google access token refreshed",
    requestId: params.requestId,
    traceparent: params.traceparent,
    userId: params.userId,
    googleService: params.service,
  });

  return credentials.access_token || row.access_token || null;
}

