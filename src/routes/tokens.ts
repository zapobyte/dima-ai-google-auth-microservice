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

  logger.info({
    event: "service_token_requested",
    message: "Service access token requested",
    requestId: req.requestId,
    traceparent: req.traceparent,
    method: req.method,
    path: req.originalUrl || req.url,
    userId,
    googleService: service,
  });

  try {
    const token = await getValidAccessToken({
      userId,
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
      googleService: service,
      error: e,
    });
    return res.status(500).json({ success: false, error: "Internal Server Error" });
  }
}

