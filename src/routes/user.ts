import type { Request, Response } from "express";
import { deleteAllTokensForUser, getUser, listConnections } from "../database";
import { issueJwt, revokeRefreshSession, rotateRefreshSession } from "../auth";
import { logger } from "../utils/logger";

function parseWorkspaceId(v: unknown): number | null {
  const n = Number(v);
  if (!Number.isFinite(n)) return null;
  const i = Math.trunc(n);
  if (i <= 0) return null;
  return i;
}

function parseNonEmptyString(v: unknown): string | null {
  if (!v) return null;
  const s = String(v).trim();
  if (!s) return null;
  return s;
}

export function status(req: Request, res: Response) {
  const userId = req.auth?.userId;
  if (!userId) return res.status(401).json({ success: false, error: "Unauthorized" });
  req.userId = userId;

  const workspaceId = parseWorkspaceId(req.query.workspaceId);
  const workspaceSlug = parseNonEmptyString(req.query.workspaceSlug);
  if (!workspaceId) return res.status(400).json({ success: false, error: "Missing or invalid workspaceId" });
  if (!workspaceSlug) return res.status(400).json({ success: false, error: "Missing or invalid workspaceSlug" });

  logger.info({
    event: "auth_status_requested",
    message: "Auth status requested",
    requestId: req.requestId,
    traceparent: req.traceparent,
    method: req.method,
    path: req.originalUrl || req.url,
    userId,
    workspaceId,
    workspaceSlug,
  });

  const u = getUser(userId);
  const connections = listConnections(userId, workspaceId).map((c) => ({
    agentId: c.agent_id,
    service: c.service,
  }));

  return res.json({
    success: true,
    data: {
      user: u || { id: userId, email: null, name: null, picture: null },
      workspaceId,
      workspaceSlug,
      connections,
    },
  });
}

export function refresh(req: Request, res: Response) {
  const refreshToken = req.body?.refreshToken ? String(req.body.refreshToken) : null;
  logger.info({
    event: "auth_refresh_requested",
    message: "Auth refresh requested",
    requestId: req.requestId,
    traceparent: req.traceparent,
    method: req.method,
    path: req.originalUrl || req.url,
  });
  if (!refreshToken) {
    logger.warn({
      event: "auth_refresh_failed",
      message: "Missing refreshToken",
      requestId: req.requestId,
      traceparent: req.traceparent,
      method: req.method,
      path: req.originalUrl || req.url,
    });
    return res.status(400).json({ success: false, error: "Missing refreshToken" });
  }

  const rotated = rotateRefreshSession(refreshToken);
  if (!rotated) {
    logger.warn({
      event: "auth_refresh_failed",
      message: "Invalid refreshToken",
      requestId: req.requestId,
      traceparent: req.traceparent,
      method: req.method,
      path: req.originalUrl || req.url,
    });
    return res.status(401).json({ success: false, error: "Invalid refreshToken" });
  }
  req.userId = rotated.userId;

  const accessJwt = issueJwt(rotated.userId);
  logger.info({
    event: "auth_refresh_succeeded",
    message: "Auth refresh succeeded",
    requestId: req.requestId,
    traceparent: req.traceparent,
    method: req.method,
    path: req.originalUrl || req.url,
    userId: rotated.userId,
  });
  return res.json({
    success: true,
    data: {
      token: accessJwt,
      refreshToken: rotated.refreshToken,
    },
  });
}

export function logout(req: Request, res: Response) {
  const refreshToken = req.body?.refreshToken ? String(req.body.refreshToken) : null;
  logger.info({
    event: "auth_logout_requested",
    message: "Auth logout requested",
    requestId: req.requestId,
    traceparent: req.traceparent,
    method: req.method,
    path: req.originalUrl || req.url,
    userId: req.auth?.userId,
  });
  if (!refreshToken) {
    logger.warn({
      event: "auth_logout_failed",
      message: "Missing refreshToken",
      requestId: req.requestId,
      traceparent: req.traceparent,
      method: req.method,
      path: req.originalUrl || req.url,
      userId: req.auth?.userId,
    });
    return res.status(400).json({ success: false, error: "Missing refreshToken" });
  }

  // Revoke the refresh session and wipe Google grants for that user
  const ok = revokeRefreshSession(refreshToken);
  if (!ok) {
    logger.warn({
      event: "auth_logout_failed",
      message: "Invalid refreshToken",
      requestId: req.requestId,
      traceparent: req.traceparent,
      method: req.method,
      path: req.originalUrl || req.url,
      userId: req.auth?.userId,
    });
    return res.status(401).json({ success: false, error: "Invalid refreshToken" });
  }

  // Best-effort: if token was valid we can derive userId by rotating, but we didn't.
  // Instead, allow caller to optionally include userId when still authenticated.
  const userId = req.auth?.userId;
  if (userId) deleteAllTokensForUser(userId);

  if (userId) req.userId = userId;
  logger.info({
    event: "auth_logout_succeeded",
    message: "Auth logout succeeded",
    requestId: req.requestId,
    traceparent: req.traceparent,
    method: req.method,
    path: req.originalUrl || req.url,
    userId,
  });
  return res.json({ success: true });
}

