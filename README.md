# Unravel Backend
LinkSpect

Adds three checks the frontend can't do on its own (browsers can't query WHOIS,
follow redirects transparently, or call most threat-intel APIs directly):

- **Domain age** — via RDAP (free, no key)
- **Redirect chain** — follows the link hop-by-hop and reports where it actually lands
- **Threat intel** — URLhaus (free, no key) + optional Google Safe Browsing (free key)

## 1. Install

Requires **Node.js 18 or newer** (for built-in `fetch`). Check with `node -v`.

```bash
cd backend
npm install
```

## 2. Configure

```bash
cp .env.example .env
```

Open `.env` and set `ALLOWED_ORIGINS` to wherever your frontend is served from.
Everything else is optional — the server runs fine with just the copy-paste above.

To enable Google Safe Browsing (optional, free):
1. Go to https://console.cloud.google.com/ → create a project
2. APIs & Services → Library → enable **"Safe Browsing API"**
3. APIs & Services → Credentials → **Create API key**
4. Paste it into `.env` as `SAFE_BROWSING_API_KEY=...`

## 3. Run

```bash
npm start
```

You should see:
```
Unravel backend listening on http://localhost:8787
```

Confirm it's alive:
```bash
curl http://localhost:8787/api/health
```

Test a scan:
```bash
curl -X POST http://localhost:8787/api/scan \
  -H "Content-Type: application/json" \
  -d '{"url":"https://example.com"}'
```

## 4. Connect it to the frontend

The frontend (`script.js`) already has this wired in behind a constant near the
top of the file:

```js
var BACKEND_URL = "http://localhost:8787"; // set to "" to disable backend checks
```

- Running the backend locally on the default port → leave it as-is.
- Deployed the backend somewhere (Render, Railway, Fly.io, a VPS, etc.) →
  change this to that URL, e.g. `"https://unravel-api.yourdomain.com"`.
- Don't want the backend at all → set it to `""`. The frontend falls back to
  client-only heuristics automatically (this is what it did before — nothing
  breaks).

**You must serve `index.html` over `http://` or `https://`, not open it as a
`file://` path**, or the browser will block the request to the backend (CORS).
Easiest options:

```bash
# from the frontend folder
python3 -m http.server 5500
# or
npx serve -l 5500
```

Then open `http://localhost:5500`. Make sure `5500` (or whatever port you use)
is listed in the backend's `.env` under `ALLOWED_ORIGINS`.

## Where each file does what

| File | Responsibility |
|---|---|
| `server.js` | Express app setup: CORS, rate limiting, mounts routes |
| `src/routes/scan.js` | `POST /api/scan` — validates input, runs all checks in parallel |
| `src/services/domainInfo.js` | RDAP lookup → domain registration age |
| `src/services/redirectChain.js` | Follows redirects manually, hop by hop |
| `src/services/threatIntel.js` | URLhaus + Google Safe Browsing lookups |
| `src/services/scoring.js` | Turns raw check results into scored, human-readable reasons |
| `src/utils/registrableDomain.js` | Best-effort "example.com" extraction from a hostname |

## Known limitations (by design, not hidden)

- `registrableDomain.js` uses a simple last-two-labels rule, not a full public
  suffix list — domains like `something.co.uk` or `something.github.io` will
  be mis-parsed. Swap in the `tldts` package for production accuracy (see the
  comment in that file).
- RDAP coverage varies by TLD/registry; some return no data even for real,
  registered domains. The API reports this as "unavailable," not "safe."
- No database, no auth, no persistence — this is a stateless scoring API, not
  a full product backend. Add a datastore if you want server-side history
  instead of the frontend's `localStorage`.

## Deploying

Any Node host works (Render, Railway, Fly.io, a plain VPS with `pm2`). Steps
are the same everywhere:
1. Push this `backend/` folder to its own repo or subfolder
2. Set the build command to `npm install` and start command to `npm start`
3. Set `PORT` (most platforms inject this automatically), `ALLOWED_ORIGINS`,
   and optionally `SAFE_BROWSING_API_KEY` as environment variables in the
   host's dashboard — never commit `.env` itself
4. Update `BACKEND_URL` in the frontend's `script.js` to the deployed URL
