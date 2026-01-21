import type { NextFunction, Request, Response } from "express";
import { verifyJwt } from "../auth";
import type { JwtPayload } from "../types";
import { logger } from "../utils/logger";

declare module "express-serve-static-core" {
  interface Request {
    auth?: JwtPayload;
  }
}

export function authMiddleware(req: Request, res: Response, next: NextFunction) {
  const header = req.headers.authorization || "";
  const m = header.match(/^Bearer\s+(.+)$/i);
  if (!m) {
    logger.warn({
      event: "auth_missing_bearer",
      message: "Missing Authorization Bearer token",
      requestId: req.requestId,
      traceparent: req.traceparent,
      method: req.method,
      path: req.originalUrl || req.url,
    });
    return res.status(401).json({ success: false, error: "Missing Authorization Bearer token" });
  }

  try {
    req.auth = verifyJwt(m[1]);
    req.userId = req.auth.userId;
    return next();
  } catch {
    logger.warn({
      event: "auth_invalid_token",
      message: "Invalid Bearer token",
      requestId: req.requestId,
      traceparent: req.traceparent,
      method: req.method,
      path: req.originalUrl || req.url,
    });
    return res.status(401).json({ success: false, error: "Invalid token" });
  }
}

