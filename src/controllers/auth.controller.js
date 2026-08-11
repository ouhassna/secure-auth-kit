const authService = require("../services/auth.service");

function handleError(res, err) {
  const status = err.status || 500;
  const body = { error: err.message || "Internal server error" };
  if (err.requires2FA) body.requires2FA = true;
  return res.status(status).json(body);
}

async function register(req, res) {
  try {
    const { email, password } = req.body;
    const user = await authService.register(email, password);
    res.status(201).json({ message: "Registered. Please check your email to verify your account.", user });
  } catch (err) {
    handleError(res, err);
  }
}

async function verifyEmail(req, res) {
  try {
    const { token } = req.body;
    await authService.verifyEmail(token);
    res.json({ message: "Email verified successfully" });
  } catch (err) {
    handleError(res, err);
  }
}

async function login(req, res) {
  try {
    const { email, password, twoFACode } = req.body;
    const result = await authService.login(email, password, twoFACode);
    res.json(result);
  } catch (err) {
    handleError(res, err);
  }
}

async function refresh(req, res) {
  try {
    const { refreshToken } = req.body;
    const result = await authService.refresh(refreshToken);
    res.json(result);
  } catch (err) {
    handleError(res, err);
  }
}

async function logout(req, res) {
  try {
    const { refreshToken } = req.body;
    await authService.logout(refreshToken);
    res.json({ message: "Logged out" });
  } catch (err) {
    handleError(res, err);
  }
}

async function forgotPassword(req, res) {
  try {
    const { email } = req.body;
    await authService.forgotPassword(email);
    // Always the same response, whether or not the email exists.
    res.json({ message: "If that email is registered, a reset link has been sent." });
  } catch (err) {
    handleError(res, err);
  }
}

async function resetPassword(req, res) {
  try {
    const { token, newPassword } = req.body;
    await authService.resetPassword(token, newPassword);
    res.json({ message: "Password reset successfully" });
  } catch (err) {
    handleError(res, err);
  }
}

async function setup2FA(req, res) {
  try {
    const secret = await authService.generate2FASecret(req.user.id);
    res.json({ secret, message: "Scan this secret in your authenticator app, then confirm with /2fa/enable" });
  } catch (err) {
    handleError(res, err);
  }
}

async function enable2FA(req, res) {
  try {
    const { token } = req.body;
    await authService.enable2FA(req.user.id, token);
    res.json({ message: "2FA enabled" });
  } catch (err) {
    handleError(res, err);
  }
}

async function me(req, res) {
  res.json({ user: req.user });
}

module.exports = {
  register,
  verifyEmail,
  login,
  refresh,
  logout,
  forgotPassword,
  resetPassword,
  setup2FA,
  enable2FA,
  me,
};
