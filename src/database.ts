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

function getUserVersion(): number {
  const row = db.prepare(`PRAGMA user_version`).get() as { user_version: number };
  return Number(row?.user_version ?? 0) || 0;
}

function setUserVersion(v: number) {
  db.exec(`PRAGMA user_version = ${Math.max(0, Math.trunc(v))}`);
}

function hasTokensTable(): boolean {
  const row = db
    .prepare(`SELECT name FROM sqlite_master WHERE type='table' AND name='tokens'`)
    .get() as { name?: string } | undefined;
  return !!row?.name;
}

function createTokensTableV1() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS tokens (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      workspace_id INTEGER NOT NULL,
      workspace_slug TEXT NOT NULL,
      agent_id TEXT NOT NULL,
      service TEXT NOT NULL,
      access_token TEXT,
      refresh_token TEXT,
      expiry_date INTEGER,
      scopes TEXT,
      connection_id TEXT,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(user_id, workspace_id, agent_id, service),
      FOREIGN KEY(user_id) REFERENCES users(id)
    );
    CREATE INDEX IF NOT EXISTS tokens_lookup ON tokens(user_id, workspace_id, agent_id, service);
  `);
}

function migrateTokensToV1() {
  const current = getUserVersion();
  if (current >= 1) return;

  if (!hasTokensTable()) {
    createTokensTableV1();
    setUserVersion(1);
    return;
  }

  db.exec(`
    CREATE TABLE IF NOT EXISTS tokens_new (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      workspace_id INTEGER NOT NULL,
      workspace_slug TEXT NOT NULL,
      agent_id TEXT NOT NULL,
      service TEXT NOT NULL,
      access_token TEXT,
      refresh_token TEXT,
      expiry_date INTEGER,
      scopes TEXT,
      connection_id TEXT,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(user_id, workspace_id, agent_id, service),
      FOREIGN KEY(user_id) REFERENCES users(id)
    );

    INSERT INTO tokens_new (
      user_id,
      workspace_id,
      workspace_slug,
      agent_id,
      service,
      access_token,
      refresh_token,
      expiry_date,
      scopes,
      connection_id,
      updated_at
    )
    SELECT
      user_id,
      0,
      'legacy',
      'legacy',
      service,
      access_token,
      refresh_token,
      expiry_date,
      scopes,
      NULL,
      updated_at
    FROM tokens;

    DROP TABLE tokens;
    ALTER TABLE tokens_new RENAME TO tokens;
    CREATE INDEX IF NOT EXISTS tokens_lookup ON tokens(user_id, workspace_id, agent_id, service);
  `);

  setUserVersion(1);
}

migrateTokensToV1();

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
  workspaceId: number;
  workspaceSlug: string;
  agentId: string;
  service: string;
  accessToken: string | null;
  refreshToken: string | null;
  expiryDate: number | null;
  scopes: string | null;
  connectionId: string | null;
}) {
  const stmt = db.prepare(`
    INSERT INTO tokens (
      user_id,
      workspace_id,
      workspace_slug,
      agent_id,
      service,
      access_token,
      refresh_token,
      expiry_date,
      scopes,
      connection_id,
      updated_at
    )
    VALUES (
      @userId,
      @workspaceId,
      @workspaceSlug,
      @agentId,
      @service,
      @accessToken,
      @refreshToken,
      @expiryDate,
      @scopes,
      @connectionId,
      CURRENT_TIMESTAMP
    )
    ON CONFLICT(user_id, workspace_id, agent_id, service) DO UPDATE SET
      access_token=excluded.access_token,
      refresh_token=COALESCE(excluded.refresh_token, tokens.refresh_token),
      expiry_date=excluded.expiry_date,
      scopes=excluded.scopes,
      workspace_slug=excluded.workspace_slug,
      connection_id=excluded.connection_id,
      updated_at=CURRENT_TIMESTAMP
  `);
  stmt.run({
    userId: params.userId,
    workspaceId: params.workspaceId,
    workspaceSlug: params.workspaceSlug,
    agentId: params.agentId,
    service: params.service,
    accessToken: params.accessToken,
    refreshToken: params.refreshToken,
    expiryDate: params.expiryDate,
    scopes: params.scopes,
    connectionId: params.connectionId,
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

export function listConnections(userId: number, workspaceId: number): Array<{ agent_id: string; service: string }> {
  const rows = db
    .prepare(
      `SELECT agent_id, service
       FROM tokens
       WHERE user_id=? AND workspace_id=? AND refresh_token IS NOT NULL AND refresh_token != ''
       GROUP BY agent_id, service
       ORDER BY agent_id ASC, service ASC`
    )
    .all(userId, workspaceId) as Array<{ agent_id: string; service: string }>;
  return rows;
}

export function getTokenRow(userId: number, workspaceId: number, agentId: string, service: string) {
  return db
    .prepare(
      `SELECT id, user_id, workspace_id, workspace_slug, agent_id, service, access_token, refresh_token, expiry_date, scopes, connection_id, updated_at
       FROM tokens WHERE user_id=? AND workspace_id=? AND agent_id=? AND service=?`
    )
    .get(userId, workspaceId, agentId, service) as
    | {
        id: number;
        user_id: number;
        workspace_id: number;
        workspace_slug: string;
        agent_id: string;
        service: string;
        access_token: string | null;
        refresh_token: string | null;
        expiry_date: number | null;
        scopes: string | null;
        connection_id: string | null;
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

