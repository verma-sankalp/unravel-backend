"use strict";

const express = require("express");
const { lookupDomainInfo } = require("../services/domainInfo");
const { followRedirectChain } = require("../services/redirectChain");
const { checkUrlhaus, checkSafeBrowsing } = require("../services/threatIntel");
const { buildBackendReasons } = require("../services/scoring");

const router = express.Router();

const TIMEOUT_MS = Number(process.env.CHECK_TIMEOUT_MS || 6000);

router.post("/scan", async (req, res) => {
  const rawUrl = typeof req.body?.url === "string" ? req.body.url.trim() : "";
  if (!rawUrl) {
    return res.status(400).json({ error: "Missing \"url\" in request body." });
  }

  const candidate = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(rawUrl) ? rawUrl : `http://${rawUrl}`;

  let parsed;
  try {
    parsed = new URL(candidate);
  } catch (e) {
    return res.status(400).json({ error: "That doesn't parse as a URL." });
  }

  // Only ever fetch http/https — refuse file:, javascript:, data:, etc.
  if (!["http:", "https:"].includes(parsed.protocol)) {
    return res.status(400).json({ error: "Only http:// and https:// URLs are supported." });
  }

  try {
    const [domainInfo, redirectInfo, urlhaus, safeBrowsing] = await Promise.all([
      lookupDomainInfo(parsed.hostname, TIMEOUT_MS),
      followRedirectChain(candidate, TIMEOUT_MS),
      checkUrlhaus(candidate, TIMEOUT_MS),
      checkSafeBrowsing(candidate, process.env.SAFE_BROWSING_API_KEY, TIMEOUT_MS)
    ]);

    const { reasons, scoreDelta } = buildBackendReasons({ domainInfo, redirectInfo, urlhaus, safeBrowsing });

    res.json({
      url: candidate,
      hostname: parsed.hostname,
      checkedAt: new Date().toISOString(),
      domainInfo,
      redirectInfo,
      threatIntel: { urlhaus, safeBrowsing },
      backendReasons: reasons,
      scoreDelta
    });
  } catch (err) {
    console.error("Scan failed:", err);
    res.status(502).json({ error: "One or more backend checks failed unexpectedly." });
  }
});

module.exports = router;
