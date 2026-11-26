
# Sentinel OSINT

A dark, responsive public-source research workspace with a React + TypeScript frontend, a Node.js/Express API, and local SQLite persistence.

## Deploy to GitHub Pages

The `Deploy to GitHub Pages` workflow builds and publishes the frontend on every push to `main` and on manual runs. In repository **Settings → Pages**, set the build and deployment source to **GitHub Actions**. The Vite base path is derived from the repository name, so project sites load their assets from the correct subpath.

GitHub Pages is static hosting; it cannot run the Node API or safely hold provider secrets. The Pages build enables a static workspace: cases, findings, and lookup history are stored in the browser's local storage, and domain, public-IP, and email syntax/MX checks use browser-accessible public endpoints. Website fetches and secret-key integrations (VirusTotal, AbuseIPDB, Shodan, and HIBP) need a separately hosted backend; those are reported as unavailable instead of simulated. Browser storage is specific to that browser and deployment origin.

## Run locally

Requirements: Node.js 20.19+ or 22.12+.

```bash
npm install
npm run dev
```

Vite serves the frontend on `http://localhost:5173` and proxies `/api` requests to the local API on port `3001`. The API binds to loopback by default; set `HOST` explicitly only when you intend to expose it on another interface. Lookup requests are rate-limited to five per minute per client. The SQLite database is created at `data/sentinel.sqlite`. Production builds can be created with `npm run build`, then served with `npm start` (port `3001` by default).

## Public data sources

RDAP, Google DNS-over-HTTPS, crt.sh, and ipwho.is are queried server-side without API keys. Optional provider keys can be supplied as backend environment variables; never place them in frontend code:

| Variable | Provider | Used for |
| --- | --- | --- |
| `VIRUSTOTAL_API_KEY` | VirusTotal | Domain/IP reputation |
| `ABUSEIPDB_API_KEY` | AbuseIPDB | IP reputation |
| `SHODAN_API_KEY` | Shodan | Public IP host summary |
| `HIBP_API_KEY` | Have I Been Pwned | Publicly documented email breach records |
| `DATABASE_PATH` | Local configuration | SQLite file path |
| `PORT` | Local configuration | API port (default `3001`) |
| `HOST` | Local configuration | API bind address (default `127.0.0.1`) |

Integration configuration is reported by `/api/health` and in the Tools workspace. Provider availability and terms/rate limits may change; a provider outage is shown as unavailable, not as a clean result.

## Research and privacy boundaries

- Lookup modules query public registration, DNS, certificate-transparency, geolocation, and public website metadata only.
- Website lookups do not follow redirects and reject local/private-network destinations. Requests use a descriptive user agent and have timeouts and response-size limits.
- Username search creates unverified public profile links only; it does not query platforms or confirm that an account exists.
- Images are inspected in the browser. The image file is not sent to Sentinel; external reverse-image services open separately and require the analyst to choose whether to upload.
- Email checks validate syntax and public MX records. Breach checks require an authorized HIBP API key. The app never accesses inboxes or accounts.
- Dashboard sample counts and sample activity are illustrative and explicitly labeled. Lookup results are never substituted with sample intelligence.
- Case notes, findings, and lookup history are stored in the local SQLite database. Case reports use the browser print dialog so the analyst can save to PDF.

Only investigate information you are authorized to research. Verify material findings at their original sources.
