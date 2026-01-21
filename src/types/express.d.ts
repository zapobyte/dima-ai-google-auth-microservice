export {};

declare module "express-serve-static-core" {
  interface Request {
    requestId?: string;
    traceparent?: string;
    userId?: number;
    googleService?: string;
  }
}

