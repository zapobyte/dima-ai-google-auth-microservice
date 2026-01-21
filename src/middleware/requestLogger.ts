import type { NextFunction, Request, Response } from "express";
import { logger } from "../utils/logger";

function shouldLogRequestStart(): boolean {
  const raw = process.env.LOG_REQUEST_START;
  if (!raw) return false;
  const v = String(raw).trim().toLowerCase();
  return v === "1" || v === "true" || v === "yes" || v === "on";
}

function routeLabel(req: Request): string | undefined {
  const r = (req as unknown as { route?: { path?: string } }).route;
  if (!r?.path) return undefined;
  // include baseUrl if present
  const baseUrl = (req.baseUrl || "").toString();
  return `${baseUrl}${String(r.path)}`;
}

export function requestLogger(req: Request, res: Response, next: NextFunction) {
  const startNs = process.hrtime.bigint();
  const requestId = req.requestId;

  if (shouldLogRequestStart()) {
    logger.debug({
      event: "request_started",
      message: "Request started",
      requestId,
      traceparent: req.traceparent,
      method: req.method,
      path: req.originalUrl || req.url,
    });
  }

  res.on("finish", () => {
    const endNs = process.hrtime.bigint();
    const durationMs = Number(endNs - startNs) / 1_000_000;
    logger.info({
      event: "request_completed",
      message: "Request completed",
      requestId,
      traceparent: req.traceparent,
      method: req.method,
      path: req.originalUrl || req.url,
      route: routeLabel(req),
      statusCode: res.statusCode,
      durationMs: Math.round(durationMs),
      userId: req.userId,
      googleService: req.googleService,
    });
  });

  return next();
}

