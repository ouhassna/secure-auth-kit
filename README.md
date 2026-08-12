# Secure Auth Kit

A production-ready authentication backend with security best practices built in from day one — not bolted on after. Drop it into any Node.js project, or use it as a reference for how a secure auth system should actually be built.

![Node.js](https://img.shields.io/badge/Node.js-20-339933?logo=node.js&logoColor=white)
![Express](https://img.shields.io/badge/Express-4-000000?logo=express&logoColor=white)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-4169E1?logo=postgresql&logoColor=white)
![Prisma](https://img.shields.io/badge/Prisma-5-2D3748?logo=prisma&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-ready-2496ED?logo=docker&logoColor=white)
![Tests](https://img.shields.io/badge/tests-20%20passing-brightgreen)

## Why this exists

Most auth tutorials get you to "login works" and stop. This kit goes further: it's built to survive the questions a security-conscious client or a code review would actually ask — what happens after 5 failed logins, what happens if a refresh token leaks, what happens if the same password reset link gets used twice. Every one of those cases is handled and tested.

## Features

- ✅ Register with email verification
- ✅ Login with JWT access tokens + rotating refresh tokens
- ✅ Refresh token rotation with reuse detection (a used token can't be replayed)
- ✅ Account lockout after repeated failed login attempts
- ✅ Two-Factor Authentication (TOTP — compatible with Google Authenticator, Authy, etc.)
- ✅ Role-based access control (RBAC) middleware
- ✅ Rate limiting on sensitive endpoints
- ✅ Password reset flow with automatic session revocation
- ✅ Security headers (Helmet) + strict CORS
- ✅ Input validation on every endpoint (Zod)
- ✅ Centralized error handling (no leaked stack traces in production)
- ✅ Request logging (Morgan)
- ✅ Dockerized with PostgreSQL — one command to run
- ✅ 20 automated tests (Jest + Supertest) covering every flow above
- ✅ CI pipeline (GitHub Actions) running the full suite on every push

## Security notes

| Threat | Mitigation | Where |
|---|---|---|
| Password theft via DB leak | Passwords hashed with bcrypt (12 salt rounds), never stored in plain text | `utils/hash.js` |
| Brute-force login attempts | Account locks for a configurable duration after N failed attempts | `services/auth.service.js` |
| API-level brute force / spam | Rate limiting on register, login, password reset endpoints | `middleware/rateLimiter.js` |
| Leaked refresh token reused by an attacker | Refresh tokens rotate on every use; reusing an old (already-rotated) token is rejected | `services/auth.service.js` |
| Session hijack after password change | All refresh tokens revoked automatically on password reset | `services/auth.service.js` |
| Email enumeration (attacker checking which emails are registered) | Identical responses whether or not an email exists, on both login and forgot-password | `services/auth.service.js` |
| Stolen/forged JWTs | Signed and verified server-side with a secret key; short expiry (default 15 min) | `utils/token.js`, `middleware/verifyAuth.js` |
| Account takeover via password alone | Optional TOTP-based 2FA, enforced at login if enabled | `services/auth.service.js` |
| Unauthorized access to admin-only routes | Role-based middleware checks the authenticated user's role before allowing access | `middleware/requireRole.js` |
| Common web vulnerabilities (clickjacking, MIME sniffing, etc.) | Helmet sets standard protective HTTP headers | `app.js` |
| Cross-origin requests from untrusted origins | CORS restricted to a configured origin, not wildcard `*` | `app.js` |
| Malformed/malicious input | Every request body validated against a strict Zod schema before it reaches business logic | `validation/auth.schema.js` |
| Leaking internals via error messages | Centralized error handler hides stack traces and internals in production | `app.js` |

## Architecture

```
Client
  │
  ▼
Express App (helmet, cors, morgan, json parser)
  │
  ▼
Routes  ──────▶  Rate Limiter  ──────▶  Zod Validation
  │
  ▼
Controller (shapes HTTP request/response)
  │
  ▼
Service (business logic: hashing, tokens, lockout, 2FA, email)
  │
  ▼
Prisma ORM
  │
  ▼
PostgreSQL
```

Protected routes additionally pass through `verifyAuth` (checks JWT) and optionally `requireRole` (checks permissions) before reaching the controller.

## Quick start

Requires [Docker](https://www.docker.com/) — nothing else needs to be installed locally.

```bash
git clone https://github.com/<your-username>/secure-auth-kit.git
cd secure-auth-kit
cp .env.example .env
docker compose up --build
```

That's it. This automatically:
1. Builds the app image
2. Starts a PostgreSQL container
3. Applies database migrations
4. Starts the server on `http://localhost:3000`

Verify it's running:
```bash
curl http://localhost:3000/health
```

### Configuring email (optional, for testing verification/reset emails)

This project uses [Mailtrap](https://mailtrap.io) Email Sandbox for safe email testing — emails are caught in a test inbox instead of being sent anywhere real. Sign up free, grab your SMTP credentials from your inbox's "SMTP Settings" tab, and put them in `.env`:
```
SMTP_USER=<your Mailtrap username>
SMTP_PASS=<your Mailtrap password>
```
Without this configured, registration still works — the app logs a warning instead of failing if the email can't be sent.

### Generating secure JWT secrets

Don't use the placeholder values in `.env.example` for anything beyond local testing. Generate real random secrets:
```bash
node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"
```
Run it twice — once for `JWT_ACCESS_SECRET`, once for `JWT_REFRESH_SECRET`. They must be different values.

## Running tests

```bash
docker compose exec app npm test
```

All 20 tests should pass, covering registration, validation, email verification, login (including lockout and 2FA), protected routes, refresh token rotation, logout, and password reset.

## Making schema changes

Migrations are meant to be generated on your local machine (outside Docker), then committed to the repo — Docker only ever *applies* existing migrations, it never generates new ones. This is the standard Prisma workflow, not specific to this project:

1. Edit `prisma/schema.prisma`
2. With `.env`'s `DATABASE_URL` pointed at `localhost:5432` (Postgres is exposed by `docker-compose.yml`), run:
   ```bash
   npx prisma migrate dev --name describe_your_change
   ```
3. Commit the new migration folder it creates
4. Anyone pulling your changes gets it applied automatically on their next `docker compose up`

## API endpoints

| Method | Endpoint | Auth required | Description |
|---|---|---|---|
| POST | `/api/auth/register` | No | Create a new account, sends verification email |
| POST | `/api/auth/verify-email` | No | Verify account using the emailed token |
| POST | `/api/auth/login` | No | Log in, returns access + refresh tokens |
| POST | `/api/auth/refresh` | No | Exchange a refresh token for a new token pair |
| POST | `/api/auth/logout` | No | Revoke a refresh token |
| POST | `/api/auth/forgot-password` | No | Request a password reset email |
| POST | `/api/auth/reset-password` | No | Reset password using the emailed token |
| GET | `/api/auth/me` | Yes | Get the current authenticated user |
| POST | `/api/auth/2fa/setup` | Yes | Generate a 2FA secret to scan in an authenticator app |
| POST | `/api/auth/2fa/enable` | Yes | Confirm and enable 2FA with a TOTP code |

## Tech stack

Node.js · Express · PostgreSQL · Prisma · JWT · Zod · bcrypt · otplib (TOTP/2FA) · Helmet · Docker · Jest & Supertest · GitHub Actions

## About

Built by HASSNA OUATTOU — backend engineer specializing in secure, well-tested API systems. eJPT-certified in penetration testing.

Open to backend engineering roles — freelance or full-time. Building something and want the backend done securely from day one? 
