import type { NextFunction, Request, Response } from "express";
import { randomUUID } from "crypto";

function sanitizeRequestId(input: unknown): string | null {
  if (!input) return null;
  const v = String(input).trim();
  if (!v) return null;
  // bound size to avoid log/header abuse
  if (v.length > 128) return v.slice(0, 128);
  return v;
}

export function requestContext(req: Request, res: Response, next: NextFunction) {
  const incoming = sanitizeRequestId(req.headers["x-request-id"]);
  const requestId = incoming || randomUUID();
  req.requestId = requestId;

  const traceparent = req.headers["traceparent"] ? String(req.headers["traceparent"]).trim() : "";
  if (traceparent) req.traceparent = traceparent;

  res.setHeader("X-Request-Id", requestId);
  return next();
}

