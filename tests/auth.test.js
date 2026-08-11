// Mock email sending — tests should never depend on real SMTP/network,
// and should run fast and deterministically.
jest.mock("../src/utils/email", () => ({
  sendVerificationEmail: jest.fn().mockResolvedValue(undefined),
  sendPasswordResetEmail: jest.fn().mockResolvedValue(undefined),
}));

const request = require("supertest");
const app = require("../src/app");
const prisma = require("../src/config/db");
const { authenticator } = require("otplib");

const testUser = { email: "jest-user@example.com", password: "Passw0rd123" };

async function registerAndVerify(user = testUser) {
  await request(app).post("/api/auth/register").send(user);
  const dbUser = await prisma.user.findUnique({ where: { email: user.email } });
  await request(app).post("/api/auth/verify-email").send({ token: dbUser.verifyToken });
  return dbUser;
}

describe("POST /api/auth/register", () => {
  it("registers a new user successfully", async () => {
    const res = await request(app).post("/api/auth/register").send(testUser);
    expect(res.status).toBe(201);
    expect(res.body.user.email).toBe(testUser.email);
  });

  it("rejects a duplicate email", async () => {
    await request(app).post("/api/auth/register").send(testUser);
    const res = await request(app).post("/api/auth/register").send(testUser);
    expect(res.status).toBe(400);
  });

  it("rejects a weak password", async () => {
    const res = await request(app)
      .post("/api/auth/register")
      .send({ email: "weak@example.com", password: "weak" });
    expect(res.status).toBe(400);
  });

  it("rejects an invalid email format", async () => {
    const res = await request(app)
      .post("/api/auth/register")
      .send({ email: "not-an-email", password: "Passw0rd123" });
    expect(res.status).toBe(400);
  });
});

describe("Email verification", () => {
  it("blocks login before the account is verified", async () => {
    await request(app).post("/api/auth/register").send(testUser);
    const res = await request(app).post("/api/auth/login").send(testUser);
    expect(res.status).toBe(403);
  });

  it("allows login after verification", async () => {
    await registerAndVerify();
    const res = await request(app).post("/api/auth/login").send(testUser);
    expect(res.status).toBe(200);
    expect(res.body.accessToken).toBeDefined();
    expect(res.body.refreshToken).toBeDefined();
  });

  it("rejects an invalid verification token", async () => {
    const res = await request(app)
      .post("/api/auth/verify-email")
      .send({ token: "not-a-real-token" });
    expect(res.status).toBe(400);
  });
});

describe("POST /api/auth/login", () => {
  it("rejects wrong password", async () => {
    await registerAndVerify();
    const res = await request(app)
      .post("/api/auth/login")
      .send({ email: testUser.email, password: "WrongPass123" });
    expect(res.status).toBe(401);
  });

  it("rejects a non-existent email with a generic error (no user enumeration)", async () => {
    const res = await request(app)
      .post("/api/auth/login")
      .send({ email: "nobody@example.com", password: "Passw0rd123" });
    expect(res.status).toBe(401);
    expect(res.body.error).toBe("Invalid email or password");
  });

  it("locks the account after repeated failed attempts", async () => {
    await registerAndVerify();

    // MAX_FAILED_LOGIN_ATTEMPTS defaults to 5 — fail that many times
    for (let i = 0; i < 5; i++) {
      await request(app)
        .post("/api/auth/login")
        .send({ email: testUser.email, password: "WrongPass123" });
    }

    // Next attempt, even with the CORRECT password, should now be locked
    const res = await request(app).post("/api/auth/login").send(testUser);
    expect(res.status).toBe(423);
  });
});

describe("Protected routes", () => {
  it("rejects a request with no token", async () => {
    const res = await request(app).get("/api/auth/me");
    expect(res.status).toBe(401);
  });

  it("rejects a malformed/invalid token", async () => {
    const res = await request(app)
      .get("/api/auth/me")
      .set("Authorization", "Bearer not-a-real-token");
    expect(res.status).toBe(401);
  });

  it("allows access with a valid access token", async () => {
    await registerAndVerify();
    const loginRes = await request(app).post("/api/auth/login").send(testUser);
    const res = await request(app)
      .get("/api/auth/me")
      .set("Authorization", `Bearer ${loginRes.body.accessToken}`);
    expect(res.status).toBe(200);
    expect(res.body.user.id).toBeDefined();
  });
});

describe("POST /api/auth/refresh", () => {
  it("issues a new token pair for a valid refresh token", async () => {
    await registerAndVerify();
    const loginRes = await request(app).post("/api/auth/login").send(testUser);

    const res = await request(app)
      .post("/api/auth/refresh")
      .send({ refreshToken: loginRes.body.refreshToken });

    expect(res.status).toBe(200);
    expect(res.body.accessToken).toBeDefined();
    expect(res.body.refreshToken).toBeDefined();
    // Rotation: the new refresh token must differ from the old one
    expect(res.body.refreshToken).not.toBe(loginRes.body.refreshToken);
  });

  it("rejects a refresh token that was already used (rotation/reuse protection)", async () => {
    await registerAndVerify();
    const loginRes = await request(app).post("/api/auth/login").send(testUser);

    // Use it once — should succeed
    await request(app)
      .post("/api/auth/refresh")
      .send({ refreshToken: loginRes.body.refreshToken });

    // Reuse the same (now revoked) token — should fail
    const res = await request(app)
      .post("/api/auth/refresh")
      .send({ refreshToken: loginRes.body.refreshToken });

    expect(res.status).toBe(401);
  });
});

describe("POST /api/auth/logout", () => {
  it("revokes the refresh token so it can no longer be used", async () => {
    await registerAndVerify();
    const loginRes = await request(app).post("/api/auth/login").send(testUser);

    await request(app)
      .post("/api/auth/logout")
      .send({ refreshToken: loginRes.body.refreshToken });

    const res = await request(app)
      .post("/api/auth/refresh")
      .send({ refreshToken: loginRes.body.refreshToken });

    expect(res.status).toBe(401);
  });
});

describe("Password reset flow", () => {
  it("always returns success-shaped response, even for an unknown email (no enumeration)", async () => {
    const res = await request(app)
      .post("/api/auth/forgot-password")
      .send({ email: "unknown@example.com" });
    expect(res.status).toBe(200);
  });

  it("resets the password with a valid token and revokes old sessions", async () => {
    await registerAndVerify();
    const loginRes = await request(app).post("/api/auth/login").send(testUser);

    await request(app).post("/api/auth/forgot-password").send({ email: testUser.email });
    const dbUser = await prisma.user.findUnique({ where: { email: testUser.email } });

    const resetRes = await request(app)
      .post("/api/auth/reset-password")
      .send({ token: dbUser.resetToken, newPassword: "NewPassw0rd456" });
    expect(resetRes.status).toBe(200);

    // Old refresh token should now be revoked
    const refreshRes = await request(app)
      .post("/api/auth/refresh")
      .send({ refreshToken: loginRes.body.refreshToken });
    expect(refreshRes.status).toBe(401);

    // Old password should no longer work
    const oldLoginRes = await request(app).post("/api/auth/login").send(testUser);
    expect(oldLoginRes.status).toBe(401);

    // New password should work
    const newLoginRes = await request(app)
      .post("/api/auth/login")
      .send({ email: testUser.email, password: "NewPassw0rd456" });
    expect(newLoginRes.status).toBe(200);
  });

  it("rejects an invalid reset token", async () => {
    const res = await request(app)
      .post("/api/auth/reset-password")
      .send({ token: "fake-token", newPassword: "NewPassw0rd456" });
    expect(res.status).toBe(400);
  });
});

describe("2FA flow", () => {
  it("sets up and enables 2FA, then requires it on login", async () => {
    await registerAndVerify();
    const loginRes = await request(app).post("/api/auth/login").send(testUser);
    const accessToken = loginRes.body.accessToken;

    const setupRes = await request(app)
      .post("/api/auth/2fa/setup")
      .set("Authorization", `Bearer ${accessToken}`);
    expect(setupRes.status).toBe(200);
    const secret = setupRes.body.secret;

    const validCode = authenticator.generate(secret);
    const enableRes = await request(app)
      .post("/api/auth/2fa/enable")
      .set("Authorization", `Bearer ${accessToken}`)
      .send({ token: validCode });
    expect(enableRes.status).toBe(200);

    // Login without a 2FA code should now be rejected, flagged as requiring 2FA
    const loginNoCode = await request(app).post("/api/auth/login").send(testUser);
    expect(loginNoCode.status).toBe(401);
    expect(loginNoCode.body.requires2FA).toBe(true);

    // Login with the correct TOTP code should succeed
    const freshCode = authenticator.generate(secret);
    const loginWithCode = await request(app)
      .post("/api/auth/login")
      .send({ ...testUser, twoFACode: freshCode });
    expect(loginWithCode.status).toBe(200);
  });
});
