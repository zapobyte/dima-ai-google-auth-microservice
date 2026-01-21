import express from "express";
import type { Server } from "http";
import type { Socket } from "net";
import config from "./config";
import { closeDatabase } from "./database";
import { connect, callback } from "./routes/oauth";
import { authMiddleware } from "./middleware/authMiddleware";
import { getToken } from "./routes/tokens";
import { logout, refresh, status } from "./routes/user";
import { requestContext } from "./middleware/requestContext";
import { requestLogger } from "./middleware/requestLogger";
import { asyncHandler } from "./utils/asyncHandler";
import { logger } from "./utils/logger";

const app = express();
let server: Server | null = null;
const sockets = new Set<Socket>();
let isShuttingDown = false;

app.use(express.json({ limit: "1mb" }));
app.use(requestContext);
app.use(requestLogger);

app.get("/health", (_req, res) => res.json({ ok: true }));

// OAuth flow
app.get("/auth/google/connect", asyncHandler(connect));
app.get("/auth/google/callback", asyncHandler(callback));

// Authenticated endpoints (JWT)
app.get("/auth/status", authMiddleware, asyncHandler(status));
app.post("/auth/refresh", asyncHandler(refresh));
app.post("/auth/logout", asyncHandler(logout));
app.get("/tokens/:service", authMiddleware, asyncHandler(getToken));

app.use((err: unknown, req: express.Request, res: express.Response, _next: express.NextFunction) => {
  logger.error({
    event: "request_error",
    message: "Unhandled request error",
    requestId: req.requestId,
    traceparent: req.traceparent,
    method: req.method,
    path: req.originalUrl || req.url,
    statusCode: 500,
    userId: req.userId,
    googleService: req.googleService,
    error: err,
  });
  return res.status(500).json({ success: false, error: "Internal Server Error" });
});

function shutdown(signal: string, exitCode: number, afterShutdown?: () => void) {
  if (isShuttingDown) return;
  isShuttingDown = true;

  logger.warn({ event: "shutdown_started", message: "Shutdown started", signal });

  const shutdownTimeoutMs = 10_000;
  const forceTimer = setTimeout(() => {
    logger.warn({
      event: "shutdown_force_socket_destroy",
      message: "Shutdown timeout reached; destroying remaining sockets",
      signal,
      socketCount: sockets.size,
    });
    for (const socket of sockets) socket.destroy();
    try {
      closeDatabase();
      logger.info({ event: "shutdown_db_closed", message: "Database closed", signal });
    } catch {
      // ignore
    }
    logger.warn({ event: "shutdown_complete", message: "Shutdown complete (forced)", signal, exitCode });
    if (afterShutdown) afterShutdown();
    if (signal === "SIGUSR2") return;
    process.exit(exitCode);
  }, shutdownTimeoutMs);

  const finalize = () => {
    clearTimeout(forceTimer);
    try {
      closeDatabase();
      logger.info({ event: "shutdown_db_closed", message: "Database closed", signal });
    } catch {
      // ignore
    }
    logger.warn({ event: "shutdown_complete", message: "Shutdown complete", signal, exitCode });
    if (afterShutdown) afterShutdown();
    if (signal === "SIGUSR2") return;
    process.exit(exitCode);
  };

  if (!server) {
    finalize();
    return;
  }

  try {
    server.close(() => {
      logger.info({ event: "shutdown_http_closed", message: "HTTP server closed", signal });
      finalize();
    });
  } catch {
    finalize();
  }
}

server = app.listen(config.port, () => {
  logger.info({
    event: "service_started",
    message: "Service started",
    port: config.port,
    baseUrlHost: (() => {
      try {
        return new URL(config.baseUrl).host;
      } catch {
        return config.baseUrl;
      }
    })(),
    nodeEnv: process.env.NODE_ENV || "development",
  });
});

server.on("connection", (socket: Socket) => {
  sockets.add(socket);
  socket.on("close", () => sockets.delete(socket));
});

process.once("SIGTERM", () => shutdown("SIGTERM", 0));
process.once("SIGINT", () => shutdown("SIGINT", 0));
process.once("SIGTSTP", () => shutdown("SIGTSTP", 0));
process.once("SIGUSR2", () => shutdown("SIGUSR2", 0, () => process.kill(process.pid, "SIGUSR2")));

process.on("unhandledRejection", (reason) => {
  logger.error({ event: "unhandled_rejection", message: "Unhandled promise rejection", error: reason });
  shutdown("unhandledRejection", 1);
});
process.on("uncaughtException", (error) => {
  logger.error({ event: "uncaught_exception", message: "Uncaught exception", error });
  shutdown("uncaughtException", 1);
});

