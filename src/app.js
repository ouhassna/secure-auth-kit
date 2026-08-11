require("dotenv").config();
const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const morgan = require("morgan");
const authRoutes = require("./routes/auth.routes");

const app = express();

// Security headers
app.use(helmet());

// Request logging — shows method, path, status code, and response time for every request
app.use(morgan(process.env.NODE_ENV === "production" ? "combined" : "dev"));

// CORS — restrict to your actual frontend origin in production, never "*"
app.use(
  cors({
    origin: process.env.CLIENT_URL || "http://localhost:3000",
    credentials: true,
  })
);

app.use(express.json());

app.get("/health", (req, res) => res.json({ status: "ok" }));

app.use("/api/auth", authRoutes);

// Centralized error handler — never leak stack traces in production
app.use((err, req, res, next) => {
  console.error(err);
  const status = err.status || 500;
  res.status(status).json({
    error: process.env.NODE_ENV === "production" ? "Internal server error" : err.message,
  });
});

const PORT = process.env.PORT || 3000;

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`secure-auth-kit running on port ${PORT}`);
  });
}

module.exports = app;
