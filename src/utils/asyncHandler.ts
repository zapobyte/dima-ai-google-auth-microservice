import type { NextFunction, Request, Response } from "express";

export function asyncHandler<TReq extends Request = Request>(
  fn: (req: TReq, res: Response, next: NextFunction) => Promise<unknown> | unknown
) {
  return (req: TReq, res: Response, next: NextFunction) => {
    try {
      return Promise.resolve(fn(req, res, next)).catch(next);
    } catch (e) {
      return next(e);
    }
  };
}

