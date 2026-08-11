const express = require("express");
const controller = require("../controllers/auth.controller");
const validate = require("../middleware/validate");
const verifyAuth = require("../middleware/verifyAuth");
const { authLimiter, generalLimiter } = require("../middleware/rateLimiter");
const {
  registerSchema,
  loginSchema,
  refreshSchema,
  forgotPasswordSchema,
  resetPasswordSchema,
  verifyEmailSchema,
  enable2FASchema,
} = require("../validation/auth.schema");

const router = express.Router();

router.post("/register", authLimiter, validate(registerSchema), controller.register);
router.post("/verify-email", generalLimiter, validate(verifyEmailSchema), controller.verifyEmail);
router.post("/login", authLimiter, validate(loginSchema), controller.login);
router.post("/refresh", generalLimiter, validate(refreshSchema), controller.refresh);
router.post("/logout", generalLimiter, validate(refreshSchema), controller.logout);
router.post("/forgot-password", authLimiter, validate(forgotPasswordSchema), controller.forgotPassword);
router.post("/reset-password", authLimiter, validate(resetPasswordSchema), controller.resetPassword);

// Protected routes (require a valid access token)
router.get("/me", verifyAuth, controller.me);
router.post("/2fa/setup", verifyAuth, controller.setup2FA);
router.post("/2fa/enable", verifyAuth, validate(enable2FASchema), controller.enable2FA);

module.exports = router;
