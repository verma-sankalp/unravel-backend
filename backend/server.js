"use strict";

require("dotenv").config();

const express = require("express");
const cors = require("cors");
const rateLimit = require("express-rate-limit");

const scanRoute = require("./src/routes/scan");

const app = express();
const PORT = process.env.PORT || 8787;

const allowedOrigins = (process.env.ALLOWED_ORIGINS || "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

app.use(
  cors({
    origin: allowedOrigins.length ? allowedOrigins : true, // "true" = reflect any origin (fine for local dev only)
    methods: ["POST", "GET"]
  })
);

app.use(express.json({ limit: "10kb" }));

// Basic abuse protection: 20 scans/minute per IP. Each scan already
// makes 4 outbound calls, so this keeps you from hammering RDAP/URLhaus.
app.use(
  "/api/",
  rateLimit({
    windowMs: 60 * 1000,
    max: 20,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: "Too many scans — wait a moment and try again." }
  })
);

app.get("/api/health", (req, res) => {
  res.json({ ok: true, service: "unravel-backend", time: new Date().toISOString() });
});

app.use("/api", scanRoute);

app.use((req, res) => {
  res.status(404).json({ error: "Not found." });
});

app.listen(PORT, () => {
  console.log(`Unravel backend listening on http://localhost:${PORT}`);
  if (!allowedOrigins.length) {
    console.warn("ALLOWED_ORIGINS not set in .env — accepting requests from any origin (fine for local dev, not for production).");
  }
});
