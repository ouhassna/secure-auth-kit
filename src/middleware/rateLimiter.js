const rateLimit = require("express-rate-limit");

const isTestEnv = process.env.NODE_ENV === "test";

// Strict limiter for login/register: prevents brute-force and spam-signup abuse.
// Skipped entirely in tests — the test suite intentionally fires many requests
// back-to-back, which isn't representative of a real attacker and would make
// tests fail for the wrong reason.
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // 10 requests per window per IP
  standardHeaders: true,
  legacyHeaders: false,
  skip: () => isTestEnv,
  message: { error: "Too many requests, please try again later." },
});

// Looser limiter for less sensitive endpoints (e.g. refresh)
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 50,
  standardHeaders: true,
  legacyHeaders: false,
  skip: () => isTestEnv,
});

module.exports = { authLimiter, generalLimiter };
