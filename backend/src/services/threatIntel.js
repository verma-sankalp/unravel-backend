"use strict";

/**
 * URLhaus (run by abuse.ch) maintains a free, keyless database of URLs
 * reported for distributing malware or used in phishing. Good first line
 * of defense with zero setup.
 */
async function checkUrlhaus(targetUrl, timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch("https://urlhaus-api.abuse.ch/v1/url/", {
      method: "POST",
      signal: controller.signal,
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: `url=${encodeURIComponent(targetUrl)}`
    });
    if (!res.ok) return { checked: false, note: `URLhaus returned HTTP ${res.status}.` };

    const data = await res.json();
    if (data.query_status === "ok") {
      return {
        checked: true,
        listed: true,
        threatType: data.threat || "malware_distribution",
        dateAdded: data.date_added || null,
        reference: data.urlhaus_reference || null
      };
    }
    // "no_results" = not in the database (not the same as "confirmed clean")
    return { checked: true, listed: false };
  } catch (err) {
    const timedOut = err.name === "AbortError";
    return { checked: false, note: timedOut ? "URLhaus lookup timed out." : "URLhaus lookup failed." };
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Google Safe Browsing v4 — the same list Chrome uses. Requires a free
 * API key from Google Cloud Console. Skipped (not faked) if no key is
 * configured in .env.
 */
async function checkSafeBrowsing(targetUrl, apiKey, timeoutMs) {
  if (!apiKey) {
    return { checked: false, note: "No SAFE_BROWSING_API_KEY configured — see .env.example." };
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`,
      {
        method: "POST",
        signal: controller.signal,
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          client: { clientId: "unravel-url-checker", clientVersion: "1.0.0" },
          threatInfo: {
            threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            platformTypes: ["ANY_PLATFORM"],
            threatEntryTypes: ["URL"],
            threatEntries: [{ url: targetUrl }]
          }
        })
      }
    );
    if (!res.ok) return { checked: false, note: `Safe Browsing returned HTTP ${res.status}.` };

    const data = await res.json();
    const matches = data.matches || [];
    return {
      checked: true,
      listed: matches.length > 0,
      threatTypes: matches.map((m) => m.threatType)
    };
  } catch (err) {
    const timedOut = err.name === "AbortError";
    return { checked: false, note: timedOut ? "Safe Browsing lookup timed out." : "Safe Browsing lookup failed." };
  } finally {
    clearTimeout(timer);
  }
}

module.exports = { checkUrlhaus, checkSafeBrowsing };
