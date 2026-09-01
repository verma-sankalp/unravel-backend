"use strict";

const { registrableDomain } = require("../utils/registrableDomain");

/**
 * Looks up domain registration info via RDAP (the modern, structured
 * successor to WHOIS). rdap.org acts as a free public bootstrap that
 * redirects to the correct registry RDAP server for the domain's TLD —
 * no API key or signup required.
 *
 * Returns null fields (rather than throwing) when RDAP has no data for
 * the domain (common for very new or unregistered domains, or ccTLDs
 * that don't publish RDAP) — the caller decides how to treat "unknown".
 */
async function lookupDomainInfo(hostname, timeoutMs) {
  const domain = registrableDomain(hostname);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const res = await fetch(`https://rdap.org/domain/${encodeURIComponent(domain)}`, {
      signal: controller.signal,
      headers: { Accept: "application/rdap+json" }
    });

    if (res.status === 404) {
      return { domain, found: false, registeredAt: null, ageInDays: null, registrar: null, note: "No RDAP record — domain may be unregistered or the registry doesn't publish RDAP." };
    }
    if (!res.ok) {
      return { domain, found: false, registeredAt: null, ageInDays: null, registrar: null, note: `RDAP lookup returned HTTP ${res.status}.`, error: true };
    }

    const data = await res.json();

    const registrationEvent = (data.events || []).find(
      (e) => e.eventAction === "registration"
    );
    const registeredAt = registrationEvent ? registrationEvent.eventDate : null;

    let registrar = null;
    if (Array.isArray(data.entities)) {
      const registrarEntity = data.entities.find(
        (e) => Array.isArray(e.roles) && e.roles.includes("registrar")
      );
      if (registrarEntity && Array.isArray(registrarEntity.vcardArray)) {
        const vcard = registrarEntity.vcardArray[1] || [];
        const fnField = vcard.find((f) => f[0] === "fn");
        registrar = fnField ? fnField[3] : null;
      }
    }

    const ageInDays = registeredAt
      ? Math.floor((Date.now() - new Date(registeredAt).getTime()) / 86400000)
      : null;

    return { domain, found: true, registeredAt, ageInDays, registrar, note: null };
  } catch (err) {
    const timedOut = err.name === "AbortError";
    return {
      domain,
      found: false,
      registeredAt: null,
      ageInDays: null,
      registrar: null,
      note: timedOut ? "RDAP lookup timed out." : "RDAP lookup failed.",
      error: true
    };
  } finally {
    clearTimeout(timer);
  }
}

module.exports = { lookupDomainInfo };
