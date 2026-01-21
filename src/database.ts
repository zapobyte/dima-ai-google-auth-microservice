import Database from "better-sqlite3";
import config from "./config";

export const db = new Database(config.databasePath);
let isDbClosed = false;

db.pragma("journal_mode = WAL");

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    email TEXT UNIQUE,
    name TEXT,
    picture TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    service TEXT NOT NULL,
    access_token TEXT,
    refresh_token TEXT,
    expiry_date INTEGER,
    scopes TEXT,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, service),
    FOREIGN KEY(user_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    refresh_token_hash TEXT NOT NULL UNIQUE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at INTEGER NOT NULL,
    revoked_at INTEGER,
    last_used_at INTEGER,
    FOREIGN KEY(user_id) REFERENCES users(id)
  );
`);

export function closeDatabase() {
  if (isDbClosed) return;
  isDbClosed = true;
  try {
    db.close();
  } catch {
    // Best-effort shutdown: ignore close errors.
  }
}

export function upsertUser(params: {
  id: number;
  email: string | null;
  name: string | null;
  picture: string | null;
}) {
  const stmt = db.prepare(`
    INSERT INTO users (id, email, name, picture)
    VALUES (@id, @email, @name, @picture)
    ON CONFLICT(id) DO UPDATE SET
      email=excluded.email,
      name=excluded.name,
      picture=excluded.picture
  `);
  stmt.run({
    id: params.id,
    email: params.email,
    name: params.name,
    picture: params.picture,
  });
}

export function upsertTokens(params: {
  userId: number;
  service: string;
  accessToken: string | null;
  refreshToken: string | null;
  expiryDate: number | null;
  scopes: string | null;
}) {
  const stmt = db.prepare(`
    INSERT INTO tokens (user_id, service, access_token, refresh_token, expiry_date, scopes, updated_at)
    VALUES (@userId, @service, @accessToken, @refreshToken, @expiryDate, @scopes, CURRENT_TIMESTAMP)
    ON CONFLICT(user_id, service) DO UPDATE SET
      access_token=excluded.access_token,
      refresh_token=COALESCE(excluded.refresh_token, tokens.refresh_token),
      expiry_date=excluded.expiry_date,
      scopes=excluded.scopes,
      updated_at=CURRENT_TIMESTAMP
  `);
  stmt.run({
    userId: params.userId,
    service: params.service,
    accessToken: params.accessToken,
    refreshToken: params.refreshToken,
    expiryDate: params.expiryDate,
    scopes: params.scopes,
  });
}

export function getUser(userId: number) {
  return db
    .prepare(`SELECT id, email, name, picture, created_at FROM users WHERE id=?`)
    .get(userId) as
    | {
        id: number;
        email: string | null;
        name: string | null;
        picture: string | null;
        created_at: string;
      }
    | undefined;
}

export function listGrantedServices(userId: number): string[] {
  const rows = db
    .prepare(`SELECT service FROM tokens WHERE user_id=? AND refresh_token IS NOT NULL AND refresh_token != ''`)
    .all(userId) as Array<{ service: string }>;
  return rows.map((r) => r.service);
}

export function getTokenRow(userId: number, service: string) {
  return db
    .prepare(
      `SELECT id, user_id, service, access_token, refresh_token, expiry_date, scopes, updated_at
       FROM tokens WHERE user_id=? AND service=?`
    )
    .get(userId, service) as
    | {
        id: number;
        user_id: number;
        service: string;
        access_token: string | null;
        refresh_token: string | null;
        expiry_date: number | null;
        scopes: string | null;
        updated_at: string;
      }
    | undefined;
}

export function deleteAllTokensForUser(userId: number) {
  db.prepare(`DELETE FROM tokens WHERE user_id=?`).run(userId);
}

export function createSession(params: { userId: number; refreshTokenHash: string; expiresAt: number }) {
  db.prepare(
    `INSERT INTO sessions (user_id, refresh_token_hash, expires_at) VALUES (?, ?, ?)`
  ).run(params.userId, params.refreshTokenHash, params.expiresAt);
}

export function findSessionByRefreshHash(refreshTokenHash: string) {
  return db
    .prepare(
      `SELECT id, user_id, refresh_token_hash, created_at, expires_at, revoked_at, last_used_at
       FROM sessions WHERE refresh_token_hash=?`
    )
    .get(refreshTokenHash) as
    | {
        id: number;
        user_id: number;
        refresh_token_hash: string;
        created_at: string;
        expires_at: number;
        revoked_at: number | null;
        last_used_at: number | null;
      }
    | undefined;
}

export function touchSession(id: number, nowMs: number) {
  db.prepare(`UPDATE sessions SET last_used_at=? WHERE id=?`).run(nowMs, id);
}

export function revokeSession(id: number, nowMs: number) {
  db.prepare(`UPDATE sessions SET revoked_at=?, last_used_at=? WHERE id=?`).run(nowMs, nowMs, id);
}

