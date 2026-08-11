const crypto = require("crypto");
const { authenticator } = require("otplib");
const prisma = require("../config/db");
const { hashPassword, comparePassword } = require("../utils/hash");
const {
  generateAccessToken,
  generateRefreshTokenValue,
  refreshTokenExpiryDate,
} = require("../utils/token");
const { sendVerificationEmail, sendPasswordResetEmail } = require("../utils/email");

const MAX_ATTEMPTS = parseInt(process.env.MAX_FAILED_LOGIN_ATTEMPTS || "5", 10);
const LOCKOUT_MINUTES = parseInt(process.env.LOCKOUT_DURATION_MINUTES || "15", 10);

async function register(email, password) {
  const existing = await prisma.user.findUnique({ where: { email } });
  if (existing) {
    // Same message for "exists" as other validation errors — avoids leaking which emails are registered.
    const err = new Error("Unable to register with these details");
    err.status = 400;
    throw err;
  }

  const hashed = await hashPassword(password);
  const verifyToken = crypto.randomBytes(32).toString("hex");

  const user = await prisma.user.create({
    data: { email, password: hashed, verifyToken },
  });

  try {
    await sendVerificationEmail(email, verifyToken);
  } catch (emailErr) {
    // Don't fail registration just because email delivery had a hiccup —
    // the account is created either way. Log it so it's visible in ops,
    // and the user can be offered a "resend verification email" option later.
    console.error("Failed to send verification email:", emailErr.message);
  }

  return { id: user.id, email: user.email };
}

async function verifyEmail(token) {
  const user = await prisma.user.findFirst({ where: { verifyToken: token } });
  if (!user) {
    const err = new Error("Invalid or expired verification token");
    err.status = 400;
    throw err;
  }
  await prisma.user.update({
    where: { id: user.id },
    data: { isVerified: true, verifyToken: null },
  });
}

async function login(email, password, twoFACode) {
  const user = await prisma.user.findUnique({ where: { email } });

  // Generic error for "no such user" — never confirm/deny an email exists.
  const invalidCredsError = () => {
    const err = new Error("Invalid email or password");
    err.status = 401;
    return err;
  };

  if (!user) throw invalidCredsError();

  // Check account lockout
  if (user.lockedUntil && user.lockedUntil > new Date()) {
    const err = new Error(
      `Account temporarily locked. Try again after ${user.lockedUntil.toISOString()}`
    );
    err.status = 423; // Locked
    throw err;
  }

  const validPassword = await comparePassword(password, user.password);
  if (!validPassword) {
    const attempts = user.failedLoginAttempts + 1;
    const shouldLock = attempts >= MAX_ATTEMPTS;

    await prisma.user.update({
      where: { id: user.id },
      data: {
        failedLoginAttempts: shouldLock ? 0 : attempts,
        lockedUntil: shouldLock
          ? new Date(Date.now() + LOCKOUT_MINUTES * 60 * 1000)
          : null,
      },
    });

    throw invalidCredsError();
  }

  if (!user.isVerified) {
    const err = new Error("Please verify your email before logging in");
    err.status = 403;
    throw err;
  }

  // 2FA check
  if (user.twoFAEnabled) {
    if (!twoFACode) {
      const err = new Error("2FA code required");
      err.status = 401;
      err.requires2FA = true;
      throw err;
    }
    const valid2FA = authenticator.check(twoFACode, user.twoFASecret);
    if (!valid2FA) {
      const err = new Error("Invalid 2FA code");
      err.status = 401;
      throw err;
    }
  }

  // Successful login — reset failed attempts, issue tokens
  await prisma.user.update({
    where: { id: user.id },
    data: { failedLoginAttempts: 0, lockedUntil: null },
  });

  const accessToken = generateAccessToken(user);
  const refreshTokenValue = generateRefreshTokenValue();

  await prisma.refreshToken.create({
    data: {
      token: refreshTokenValue,
      userId: user.id,
      expiresAt: refreshTokenExpiryDate(),
    },
  });

  return {
    accessToken,
    refreshToken: refreshTokenValue,
    user: { id: user.id, email: user.email, role: user.role },
  };
}

async function refresh(oldRefreshToken) {
  const stored = await prisma.refreshToken.findUnique({
    where: { token: oldRefreshToken },
    include: { user: true },
  });

  if (!stored || stored.revoked || stored.expiresAt < new Date()) {
    const err = new Error("Invalid or expired refresh token");
    err.status = 401;
    throw err;
  }

  // Rotation: revoke the old one, issue a new pair. Limits damage if a refresh token leaks.
  await prisma.refreshToken.update({
    where: { id: stored.id },
    data: { revoked: true },
  });

  const newRefreshTokenValue = generateRefreshTokenValue();
  await prisma.refreshToken.create({
    data: {
      token: newRefreshTokenValue,
      userId: stored.userId,
      expiresAt: refreshTokenExpiryDate(),
    },
  });

  const accessToken = generateAccessToken(stored.user);

  return { accessToken, refreshToken: newRefreshTokenValue };
}

async function logout(refreshTokenValue) {
  await prisma.refreshToken.updateMany({
    where: { token: refreshTokenValue },
    data: { revoked: true },
  });
}

async function forgotPassword(email) {
  const user = await prisma.user.findUnique({ where: { email } });
  // Always respond success-shaped even if user doesn't exist — prevents email enumeration.
  if (!user) return;

  const resetToken = crypto.randomBytes(32).toString("hex");
  const resetTokenExpiresAt = new Date(Date.now() + 60 * 60 * 1000); // 1 hour

  await prisma.user.update({
    where: { id: user.id },
    data: { resetToken, resetTokenExpiresAt },
  });

  await sendPasswordResetEmail(email, resetToken);
}

async function resetPassword(token, newPassword) {
  const user = await prisma.user.findFirst({ where: { resetToken: token } });
  if (!user || !user.resetTokenExpiresAt || user.resetTokenExpiresAt < new Date()) {
    const err = new Error("Invalid or expired reset token");
    err.status = 400;
    throw err;
  }

  const hashed = await hashPassword(newPassword);
  await prisma.user.update({
    where: { id: user.id },
    data: { password: hashed, resetToken: null, resetTokenExpiresAt: null },
  });

  // Revoke all existing sessions on password change — a leaked password shouldn't
  // leave old refresh tokens valid.
  await prisma.refreshToken.updateMany({
    where: { userId: user.id },
    data: { revoked: true },
  });
}

async function generate2FASecret(userId) {
  const secret = authenticator.generateSecret();
  await prisma.user.update({ where: { id: userId }, data: { twoFASecret: secret } });
  return secret;
}

async function enable2FA(userId, token) {
  const user = await prisma.user.findUnique({ where: { id: userId } });
  const valid = authenticator.check(token, user.twoFASecret);
  if (!valid) {
    const err = new Error("Invalid 2FA code");
    err.status = 400;
    throw err;
  }
  await prisma.user.update({ where: { id: userId }, data: { twoFAEnabled: true } });
}

module.exports = {
  register,
  verifyEmail,
  login,
  refresh,
  logout,
  forgotPassword,
  resetPassword,
  generate2FASecret,
  enable2FA,
};
