---
name: Workspace-scoped agent OAuth
overview: "Make Google OAuth connections unique per (user, workspace, agent) instead of being implicitly shared, by adding workspace + agent identifiers to the API and token storage. This is a breaking change: callers must send workspaceId, workspaceSlug, and agentId."
todos:
  - id: db-migration
    content: "Implement SQLite migration: rebuild `tokens` with workspace_id/workspace_slug/agent_id + new UNIQUE constraint + index, tracked via PRAGMA user_version."
    status: completed
  - id: workspace-agent-plumbing
    content: Thread workspaceId/workspaceSlug/agentId through OAuth connect/callback and token retrieval.
    status: completed
  - id: jwt-payload-change
    content: Remove global grantedServices from JWT and adjust status endpoint to be workspace-scoped.
    status: completed
  - id: docs-update
    content: Update README API docs to reflect required query params and new status response.
    status: completed
isProject: false
---

## Observed current behavior (why it happens)

- Tokens are stored with a uniqueness constraint of **(user_id, service)**, and there is **no workspace/agent dimension**.
```18:29:src/database.ts
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
```


## Target behavior

- **Each installed agent connection is unique**, even for the same user.
- **Each agent connection is scoped to exactly one workspace**.
- Practically: store tokens keyed by **(userId, workspaceId, agentId, service)**.

## API contract changes (breaking)

All callers must provide these identifiers:

- **workspaceId**: integer (required)
- **workspaceSlug**: string (required; stored for audit/debug)
- **agentId**: string (required; identifies the installed agent instance)

Endpoints:

- `GET /auth/google/connect`
  - Required query: `service`, `userId`, `workspaceId`, `workspaceSlug`, `agentId`, `returnTo`
  - State payload must include `workspaceId`, `workspaceSlug`, `agentId`, plus a generated `connectionId` (UUID) for traceability.
- `GET /tokens/:service`
  - Required query: `workspaceId`, `workspaceSlug`, `agentId`
  - Returns an access token for that **exact** (user, workspace, agent, service) tuple.
- `GET /auth/status`
  - Required query: `workspaceId`, `workspaceSlug`
  - Returns connections for that workspace (at minimum: list of `{ agentId, service }`).

JWT payload change (breaking):

- Stop embedding global `grantedServices` in JWT (it is not workspace-scoped and encourages incorrect “connected” checks). Keep only `{ userId, email }` in the JWT.

## Data model changes

Update SQLite `tokens` to include workspace + agent dimensions:

- Add columns:
  - `workspace_id INTEGER NOT NULL`
  - `workspace_slug TEXT NOT NULL`
  - `agent_id TEXT NOT NULL`
  - `connection_id TEXT` (optional; last OAuth run id)
  - (keep existing token/scopes/expiry fields)
- Replace uniqueness constraint with:
  - `UNIQUE(user_id, workspace_id, agent_id, service)`
- Add index to speed lookups:
  - `INDEX tokens_lookup(user_id, workspace_id, agent_id, service)`

Migration approach (SQLite constraint change requires table rebuild):

- On service startup, run a small migration block in [`src/database.ts`](src/database.ts):
  - Create `tokens_new` with the new schema + new UNIQUE constraint.
  - Copy existing rows from `tokens` into `tokens_new` with placeholder workspace/agent values:
    - `workspace_id = 0`
    - `workspace_slug = 'legacy'`
    - `agent_id = 'legacy'`
    - `connection_id = NULL`
  - Drop old `tokens`, rename `tokens_new` to `tokens`.
  - Create the new index.
  - Track migration with `PRAGMA user_version` so it runs once.

## Code changes by file

- [`src/types.ts`](src/types.ts)
  - Update `JwtPayload` to remove `grantedServices`.
- [`src/auth.ts`](src/auth.ts)
  - `issueJwt()` should no longer call `listGrantedServices()`; only include user info.
  - `exchangeCodeAndStoreTokens()` must accept `workspaceId`, `workspaceSlug`, `agentId`, `connectionId` and pass them into DB storage.
  - `getValidAccessToken()` must require `workspaceId`, `agentId` and fetch tokens using the expanded key.
- [`src/database.ts`](src/database.ts)
  - Add migration logic described above.
  - Update `upsertTokens()`, `getTokenRow()`, and grant-listing helpers to include `workspaceId` + `agentId` (and store `workspaceSlug`, `connectionId`).
  - Add a new helper to list workspace connections, e.g. `listConnections(userId, workspaceId): Array<{ agent_id, service }>`.
- [`src/routes/oauth.ts`](src/routes/oauth.ts)
  - `connect`: parse/validate required `workspaceId`, `workspaceSlug`, `agentId`; include them in `state`; generate `connectionId`.
  - `callback`: decode/validate state fields; pass them into `exchangeCodeAndStoreTokens()`.
- [`src/routes/tokens.ts`](src/routes/tokens.ts)
  - Require `workspaceId`, `workspaceSlug`, `agentId` query params; pass into `getValidAccessToken()`.
- [`src/routes/user.ts`](src/routes/user.ts)
  - `status`: require `workspaceId`, `workspaceSlug`; return workspace-scoped connections.
- [`README.md`](README.md)
  - Update API summary and example URLs to include `workspaceId`, `workspaceSlug`, `agentId`.

## Validation plan (post-implementation)

- Connect Drive for `(user=1, workspaceId=10, agentId=A)` then connect Calendar for `(user=1, workspaceId=10, agentId=B)`:
  - `/auth/status?workspaceId=10&workspaceSlug=...` returns both connections (separate entries).
  - `/tokens/drive?...agentId=A` returns Drive token; `/tokens/calendar?...agentId=B` returns Calendar token.
- Connect Drive for workspaceId=11 with a different agentId:
  - Tokens and status are isolated from workspaceId=10.