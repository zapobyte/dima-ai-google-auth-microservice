export type GoogleService =
  | "drive"
  | "calendar"
  | "gmail"
  | "youtube"
  | "forms"
  | "analytics";

export type JwtPayload = {
  userId: number;
  email: string | null;
  grantedServices: GoogleService[];
};

