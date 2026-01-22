import type { Request, Response } from "express";
import { getValidAccessToken } from "../auth";
import config from "../config";
import type { GoogleService } from "../types";
import { logger } from "../utils/logger";

function parseService(s: unknown): GoogleService | null {
  if (!s) return null;
  const v = String(s);
  const allowed: GoogleService[] = ["drive", "calendar", "gmail", "youtube", "forms", "analytics"];
  return (allowed as string[]).includes(v) ? (v as GoogleService) : null;
}

function buildRedirectUri(): string {
  return `${config.baseUrl}/auth/google/callback`;
}

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

export async function getToken(req: Request, res: Response) {
  const service = parseService(req.params.service);
  if (!service) {
    logger.warn({
      event: "service_token_invalid_service",
      message: "Invalid service parameter",
      requestId: req.requestId,
      traceparent: req.traceparent,
      method: req.method,
      path: req.originalUrl || req.url,
    });
    return res.status(400).json({ success: false, error: "Invalid service" });
  }
  req.googleService = service;

  const userId = req.auth?.userId;
  if (!userId) return res.status(401).json({ success: false, error: "Unauthorized" });
  req.userId = userId;

  const workspaceId = parseWorkspaceId(req.query.workspaceId);
  const workspaceSlug = parseNonEmptyString(req.query.workspaceSlug);
  const agentId = parseNonEmptyString(req.query.agentId);
  if (!workspaceId) return res.status(400).json({ success: false, error: "Missing or invalid workspaceId" });
  if (!workspaceSlug) return res.status(400).json({ success: false, error: "Missing or invalid workspaceSlug" });
  if (!agentId) return res.status(400).json({ success: false, error: "Missing or invalid agentId" });

  logger.info({
    event: "service_token_requested",
    message: "Service access token requested",
    requestId: req.requestId,
    traceparent: req.traceparent,
    method: req.method,
    path: req.originalUrl || req.url,
    userId,
    workspaceId,
    workspaceSlug,
    agentId,
    googleService: service,
  });

  try {
    const token = await getValidAccessToken({
      userId,
      workspaceId,
      agentId,
      service,
      redirectUri: buildRedirectUri(),
      requestId: req.requestId,
      traceparent: req.traceparent,
    });
    if (!token) return res.status(401).json({ success: false, error: "Not connected" });
    return res.json({ success: true, data: { accessToken: token } });
  } catch (e) {
    logger.error({
      event: "service_token_failed",
      message: "Failed to get service access token",
      requestId: req.requestId,
      traceparent: req.traceparent,
      method: req.method,
      path: req.originalUrl || req.url,
      userId,
      workspaceId,
      workspaceSlug,
      agentId,
      googleService: service,
      error: e,
    });
    return res.status(500).json({ success: false, error: "Internal Server Error" });
  }
}

