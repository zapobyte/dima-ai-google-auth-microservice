import type { Request, Response } from "express";
import { randomUUID } from "crypto";
import {
  createOAuthClient,
  createRefreshSession,
  exchangeCodeAndStoreTokens,
  getScopesForService,
  issueJwt,
  validateReturnTo,
} from "../auth";
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

export async function connect(req: Request, res: Response) {
  // #endregion
  const service = parseService(req.query.service);
  const userIdRaw = req.query.userId;
  const returnTo = validateReturnTo(req.query.returnTo ? String(req.query.returnTo) : null);

  const userId = Number(userIdRaw);
  if (!service) return res.status(400).json({ success: false, error: "Missing or invalid service" });
  if (!Number.isFinite(userId) || userId <= 0) return res.status(400).json({ success: false, error: "Missing or invalid userId" });
  if (!returnTo) return res.status(400).json({ success: false, error: "Missing or invalid returnTo" });

  const redirectUri = buildRedirectUri();
 
  req.userId = userId;
  req.googleService = service;
  logger.info({
    event: "oauth_connect_requested",
    message: "OAuth connect requested",
    requestId: req.requestId,
    traceparent: req.traceparent,
    method: req.method,
    path: req.originalUrl || req.url,
    userId,
    googleService: service,
    redirectUriHost: (() => {
      try {
        return new URL(redirectUri).host;
      } catch {
        return redirectUri;
      }
    })(),
  });

  const oauth2Client = createOAuthClient(redirectUri);

  const state = Buffer.from(
    JSON.stringify({
      token: randomUUID(),
      userId,
      service,
      returnTo,
    })
  ).toString("base64url");

  const authUrl = oauth2Client.generateAuthUrl({
    access_type: "offline",
    prompt: "consent",
    include_granted_scopes: true,
    scope: [
      ...getScopesForService(service),
      "https://www.googleapis.com/auth/userinfo.email",
      "https://www.googleapis.com/auth/userinfo.profile",
    ],
    state,
  });

  logger.info({
    event: "oauth_connect_generated_url",
    message: "OAuth authorization URL generated",
    requestId: req.requestId,
    traceparent: req.traceparent,
    method: req.method,
    path: req.originalUrl || req.url,
    userId,
    googleService: service,
    hasState: true,
    scopesCount: getScopesForService(service).length + 2,
    redirectUriHost: (() => {
      try {
        return new URL(redirectUri).host;
      } catch {
        return redirectUri;
      }
    })(),
  });

  return res.json({
    success: true,
    data: {
      authUrl,
      popupConfig: { target: "_blank", width: 600, height: 700 },
    },
  });
}

export async function callback(req: Request, res: Response) {
  try {
    logger.info({
      event: "oauth_callback_received",
      message: "OAuth callback received",
      requestId: req.requestId,
      traceparent: req.traceparent,
      method: req.method,
      path: req.originalUrl || req.url,
      host: String(req.headers["x-forwarded-host"] || req.headers.host || ""),
      proto: String(req.headers["x-forwarded-proto"] || ""),
      hasCode: !!req.query?.code,
      hasState: !!req.query?.state,
    });

    const code = req.query.code ? String(req.query.code) : null;
    const state = req.query.state ? String(req.query.state) : null;
    if (!code) throw new Error("No authorization code received");
    if (!state) throw new Error("No state parameter received");

    const decoded = JSON.parse(Buffer.from(state, "base64url").toString("utf8")) as {
      userId: number;
      service: GoogleService;
      returnTo: string;
    };

    const service = parseService(decoded?.service);
    const userId = Number(decoded?.userId);
    const returnTo = validateReturnTo(decoded?.returnTo ? String(decoded.returnTo) : null);

    if (!service) throw new Error("Invalid state.service");
    if (!Number.isFinite(userId) || userId <= 0) throw new Error("Invalid state.userId");
    if (!returnTo) throw new Error("Invalid state.returnTo");

    const redirectUri = buildRedirectUri();

    req.userId = userId;
    req.googleService = service;
    logger.info({
      event: "oauth_callback_state_decoded",
      message: "OAuth callback state decoded",
      requestId: req.requestId,
      traceparent: req.traceparent,
      method: req.method,
      path: req.originalUrl || req.url,
      userId,
      googleService: service,
      returnToOrigin: (() => {
        try {
          return new URL(returnTo).origin;
        } catch {
          return null;
        }
      })(),
      redirectUriHost: (() => {
        try {
          return new URL(redirectUri).host;
        } catch {
          return redirectUri;
        }
      })(),
    });

    try {
      await exchangeCodeAndStoreTokens({ userId, service, code, redirectUri });
      logger.info({
        event: "oauth_token_exchange_succeeded",
        message: "OAuth code exchanged and tokens stored",
        requestId: req.requestId,
        traceparent: req.traceparent,
        method: req.method,
        path: req.originalUrl || req.url,
        userId,
        googleService: service,
      });
    } catch (err) {
      logger.error({
        event: "oauth_token_exchange_failed",
        message: "OAuth code exchange failed",
        requestId: req.requestId,
        traceparent: req.traceparent,
        method: req.method,
        path: req.originalUrl || req.url,
        userId,
        googleService: service,
        error: err,
      });
      throw err;
    }

    const jwt = issueJwt(userId);
    const session = createRefreshSession(userId);
    logger.info({
      event: "session_refresh_issued",
      message: "Refresh session issued",
      requestId: req.requestId,
      traceparent: req.traceparent,
      method: req.method,
      path: req.originalUrl || req.url,
      userId,
      googleService: service,
      expiresAt: session.expiresAt,
    });
    const u = new URL(returnTo);
    u.searchParams.set("googleAuthJwt", jwt);
    u.searchParams.set("googleAuthRefreshToken", session.refreshToken);
    u.searchParams.set("service", service);

    res.setHeader("Content-Type", "text/html; charset=utf-8");
    return res.send(`<!DOCTYPE html>
<html>
  <head>
    <title>Google Connected</title>
    <meta charset="utf-8" />
  </head>
  <body style="font-family:sans-serif;background:#1a1a1a;color:#fff;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;">
    <div style="text-align:center;max-width:560px;">
      <div style="font-size:44px;line-height:1;color:#4CAF50;margin-bottom:10px;">✓</div>
      <h2 style="margin:0 0 6px 0;">Connected</h2>
      <div style="opacity:0.8;margin-bottom:16px;">You can close this window and return to the app.</div>
      <script>
        (function () {
          try {
            const url = ${JSON.stringify(u.toString())};
            if (window.opener && !window.opener.closed) {
              window.opener.postMessage({ type: "GOOGLE_AUTH_SUCCESS", service: ${JSON.stringify(service)}, timestamp: Date.now() }, "*");
            }
            window.location.replace(url);
          } catch (e) {
            // noop
          }
        })();
      </script>
    </div>
  </body>
</html>`);
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    logger.error({
      event: "oauth_callback_failed",
      message: "OAuth callback failed",
      requestId: req.requestId,
      traceparent: req.traceparent,
      method: req.method,
      path: req.originalUrl || req.url,
      userId: req.userId,
      googleService: req.googleService,
      error: e,
    });
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    return res.status(500).send(`<!DOCTYPE html>
<html><head><title>Google Error</title><meta charset="utf-8" /></head>
<body style="background:#1a1a1a;color:#fff;font-family:sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;">
  <div style="text-align:center;max-width:560px;">
    <h2 style="color:#f44336;margin-bottom:8px;">Authentication failed</h2>
    <div style="opacity:0.8;margin-bottom:16px;">${msg.replace(/</g, "&lt;")}</div>
    <button onclick="window.close()" style="padding:10px 14px;border-radius:8px;border:1px solid rgba(255,255,255,0.2);background:transparent;color:#fff;cursor:pointer;">Close</button>
  </div>
</body></html>`);
  }
}

