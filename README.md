## Google Authentication Microservice

### What this service does
- Handles Google OAuth sign-in / consent
- Stores Google OAuth tokens in SQLite
- Issues a short-lived JWT for API calls
- Issues a rotating refresh token for renewing JWTs
- Provides Google access tokens per service via `GET /tokens/:service`

### Quickstart

#### 1) Configure environment
Copy `env.example` to your runtime environment and set values:
- `GOOGLE_CLIENT_ID`
- `GOOGLE_CLIENT_SECRET`
- `BASE_URL`
- `JWT_SECRET`
- `ALLOWED_RETURN_ORIGINS`

You must add this redirect URI in Google Cloud Console:
- `${BASE_URL}/auth/google/callback`

#### 2) Install + run
- Install dependencies
- Build:
  - `npm run build`
- Start:
  - `npm start`

### Environment variables
See `env.example`.

### API summary
- **GET** `/health`
- **GET** `/auth/google/connect?service=<service>&userId=<dimaUserId>&returnTo=<url>`
- **GET** `/auth/google/callback`
- **POST** `/auth/refresh` body `{ "refreshToken": "..." }`
- **POST** `/auth/logout` body `{ "refreshToken": "..." }`
- **GET** `/auth/status` (Bearer JWT)
- **GET** `/tokens/:service` (Bearer JWT)

### DIMA integration
The DIMA server stores the microservice refresh token per-user in its DB (encrypted) and requests service access tokens as needed.
See `docs/GOOGLE_AUTH_MICROSERVICE.md` in the main repo for details.

