const { z } = require("zod");

const passwordRule = z
  .string()
  .min(8, "Password must be at least 8 characters")
  .regex(/[A-Z]/, "Password must contain an uppercase letter")
  .regex(/[0-9]/, "Password must contain a number");

const registerSchema = z.object({
  email: z.string().email(),
  password: passwordRule,
});

const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(1),
  twoFACode: z.string().optional(),
});

const refreshSchema = z.object({
  refreshToken: z.string().min(1),
});

const forgotPasswordSchema = z.object({
  email: z.string().email(),
});

const resetPasswordSchema = z.object({
  token: z.string().min(1),
  newPassword: passwordRule,
});

const verifyEmailSchema = z.object({
  token: z.string().min(1),
});

const enable2FASchema = z.object({
  token: z.string().min(1), // TOTP code confirming setup
});

module.exports = {
  registerSchema,
  loginSchema,
  refreshSchema,
  forgotPasswordSchema,
  resetPasswordSchema,
  verifyEmailSchema,
  enable2FASchema,
};
