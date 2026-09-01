"use strict";

/**
 * Turns the raw results of the three backend checks into the same
 * { level, title, detail } shape the frontend already renders, plus a
 * numeric score contribution (0–100 scale, same as the frontend's
 * client-side heuristics) that the frontend adds to its own total.
 */
function buildBackendReasons({ domainInfo, redirectInfo, urlhaus, safeBrowsing }) {
  const reasons = [];
  let scoreDelta = 0;

  // --- Domain age -------------------------------------------------
  if (domainInfo.error || (!domainInfo.found && domainInfo.note)) {
    reasons.push({
      level: "info",
      title: "Domain registration age — unavailable",
      detail: domainInfo.note || "The registry didn't return RDAP data for this domain."
    });
  } else if (domainInfo.ageInDays === null) {
    reasons.push({
      level: "warning",
      title: "Domain registration date unknown",
      detail: "RDAP returned a record but no registration date — treat age as unverified."
    });
    scoreDelta += 6;
  } else if (domainInfo.ageInDays < 30) {
    reasons.push({
      level: "danger",
      title: "Domain registered very recently",
      detail: `Registered ${domainInfo.ageInDays} day(s) ago${domainInfo.registrar ? ` via ${domainInfo.registrar}` : ""}. Scam domains are disproportionately young — legitimate services are rarely this new.`
    });
    scoreDelta += 25;
  } else if (domainInfo.ageInDays < 180) {
    reasons.push({
      level: "warning",
      title: "Domain registered fairly recently",
      detail: `Registered about ${Math.round(domainInfo.ageInDays / 30)} month(s) ago${domainInfo.registrar ? ` via ${domainInfo.registrar}` : ""}.`
    });
    scoreDelta += 10;
  } else {
    reasons.push({
      level: "safe",
      title: "Domain has an established registration history",
      detail: `Registered about ${Math.round(domainInfo.ageInDays / 365)} year(s) ago${domainInfo.registrar ? ` via ${domainInfo.registrar}` : ""}.`
    });
  }

  // --- Redirect behavior -------------------------------------------
  if (redirectInfo.error) {
    reasons.push({
      level: "warning",
      title: "Redirect check incomplete",
      detail: redirectInfo.error
    });
    scoreDelta += 4;
  } else if (redirectInfo.hopCount === 0) {
    reasons.push({
      level: "safe",
      title: "No redirects",
      detail: "The link loads directly with no intermediate hops."
    });
  } else {
    const level = redirectInfo.crossDomainHops > 0 ? "danger" : "warning";
    reasons.push({
      level,
      title: `Redirects ${redirectInfo.hopCount} time(s) before landing`,
      detail:
        (redirectInfo.crossDomainHops > 0
          ? `Crosses to a different domain along the way — ends at ${safeHostname(redirectInfo.finalUrl)}. `
          : `Stays on the same domain, ending at ${safeHostname(redirectInfo.finalUrl)}. `) +
        "The address you paste isn't always the page you land on."
    });
    scoreDelta += redirectInfo.crossDomainHops > 0 ? 16 : 6;
    if (redirectInfo.hopCount >= 4) scoreDelta += 6;
  }

  // --- URLhaus -------------------------------------------------------
  if (!urlhaus.checked) {
    reasons.push({
      level: "info",
      title: "URLhaus threat feed — unavailable",
      detail: urlhaus.note || "Lookup didn't complete."
    });
  } else if (urlhaus.listed) {
    reasons.push({
      level: "danger",
      title: "Listed on URLhaus",
      detail: `Reported for ${urlhaus.threatType}${urlhaus.dateAdded ? ` (added ${urlhaus.dateAdded})` : ""} — this is a confirmed community report, not a guess.`
    });
    scoreDelta += 40;
  } else {
    reasons.push({
      level: "safe",
      title: "Not listed on URLhaus",
      detail: "No matching report in abuse.ch's malware/phishing URL database. Absence isn't proof of safety — only that nobody has reported it there yet."
    });
  }

  // --- Google Safe Browsing ------------------------------------------
  if (!safeBrowsing.checked) {
    reasons.push({
      level: "info",
      title: "Google Safe Browsing — unavailable",
      detail: safeBrowsing.note || "Lookup didn't complete."
    });
  } else if (safeBrowsing.listed) {
    reasons.push({
      level: "danger",
      title: "Flagged by Google Safe Browsing",
      detail: `Matches the same list Chrome uses to block dangerous sites (${safeBrowsing.threatTypes.join(", ")}).`
    });
    scoreDelta += 40;
  } else {
    reasons.push({
      level: "safe",
      title: "Clear on Google Safe Browsing",
      detail: "No match against Google's known-threat list."
    });
  }

  return { reasons, scoreDelta: Math.max(0, Math.min(100, scoreDelta)) };
}

function safeHostname(url) {
  try {
    return new URL(url).hostname;
  } catch (e) {
    return url;
  }
}

module.exports = { buildBackendReasons };
