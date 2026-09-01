"use strict";

const { registrableDomain } = require("../utils/registrableDomain");

const MAX_HOPS = 8;

/**
 * Follows a URL's redirect chain manually (one hop at a time) so we can
 * inspect every intermediate destination, rather than letting fetch()
 * silently follow redirects and hand us only the final URL.
 *
 * Times the WHOLE chain against timeoutMs, not each individual hop.
 */
async function followRedirectChain(startUrl, timeoutMs) {
  const chain = [{ url: startUrl, status: null }];
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  let currentUrl = startUrl;
  let crossDomainHops = 0;
  let error = null;

  try {
    for (let hop = 0; hop < MAX_HOPS; hop++) {
      let res;
      try {
        res = await fetch(currentUrl, {
          method: "GET",
          redirect: "manual",
          signal: controller.signal,
          headers: { "User-Agent": "Unravel-URL-Checker/1.0 (+link safety scan)" }
        });
      } catch (fetchErr) {
        error = fetchErr.name === "AbortError" ? "Redirect check timed out." : "Could not reach the destination (DNS failure, refused connection, or blocked).";
        break;
      }

      chain[chain.length - 1].status = res.status;

      const isRedirect = res.status >= 300 && res.status < 400;
      const location = res.headers.get("location");

      if (!isRedirect || !location) break;

      let nextUrl;
      try {
        nextUrl = new URL(location, currentUrl).toString();
      } catch (e) {
        error = "Redirected to a malformed location.";
        break;
      }

      if (registrableDomain(new URL(nextUrl).hostname) !== registrableDomain(new URL(currentUrl).hostname)) {
        crossDomainHops++;
      }

      chain.push({ url: nextUrl, status: null });
      currentUrl = nextUrl;
    }
  } finally {
    clearTimeout(timer);
  }

  return {
    startUrl,
    finalUrl: currentUrl,
    hopCount: chain.length - 1,
    crossDomainHops,
    chain,
    error
  };
}

module.exports = { followRedirectChain };
