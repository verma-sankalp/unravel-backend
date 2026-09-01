"use strict";

/**
 * Approximates the "registrable domain" (a.k.a. eTLD+1) by taking the last
 * two dot-separated labels of a hostname.
 *
 * LIMITATION: this is a simplification. Domains under multi-part public
 * suffixes (e.g. "co.uk", "com.au", "github.io") will be mis-split — this
 * would return "co.uk" or "github.io" as the "registrable domain" for those.
 * For production accuracy, swap this for the `psl` package (the public
 * suffix list) or Node's `tldts` package:
 *
 *   npm install tldts
 *   const { getDomain } = require("tldts");
 *   const registrable = getDomain(hostname);
 */
function registrableDomain(hostname) {
  const labels = hostname.toLowerCase().split(".").filter(Boolean);
  if (labels.length <= 2) return labels.join(".");
  return labels.slice(-2).join(".");
}

module.exports = { registrableDomain };
