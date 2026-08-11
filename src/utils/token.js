const jwt = require("jsonwebtoken");
const crypto = require("crypto");

function generateAccessToken(user) {
  return jwt.sign(
    { sub: user.id, role: user.role },
    process.env.JWT_ACCESS_SECRET,
    { expiresIn: process.env.JWT_ACCESS_EXPIRES_IN || "15m" }
  );
}

function verifyAccessToken(token) {
  return jwt.verify(token, process.env.JWT_ACCESS_SECRET);
}

// Refresh tokens are random opaque strings (not JWTs) stored + rotated in the DB.
// This lets us revoke a specific refresh token without needing a blocklist for JWTs.
function generateRefreshTokenValue() {
  return crypto.randomBytes(40).toString("hex");
}

function refreshTokenExpiryDate() {
  const days = parseInt((process.env.JWT_REFRESH_EXPIRES_IN || "7d").replace("d", ""), 10) || 7;
  const date = new Date();
  date.setDate(date.getDate() + days);
  return date;
}

module.exports = {
  generateAccessToken,
  verifyAccessToken,
  generateRefreshTokenValue,
  refreshTokenExpiryDate,
};
