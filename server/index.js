import express from "express";
import { rateLimit } from "express-rate-limit";
import Database from "better-sqlite3";
import ipaddr from "ipaddr.js";
import { isIP } from "node:net";
import { lookup } from "node:dns/promises";
import { randomUUID } from "node:crypto";
import tls from "node:tls";
import { existsSync, mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";

const app = express();
const port = Number(process.env.PORT || 3001);
const dbPath = resolve(process.env.DATABASE_PATH || "./data/sentinel.sqlite");
if (!existsSync(dirname(dbPath))) mkdirSync(dirname(dbPath), { recursive: true });
const db = new Database(dbPath);
db.pragma("journal_mode = WAL");
db.exec(`
  CREATE TABLE IF NOT EXISTS cases (
    id TEXT PRIMARY KEY, title TEXT NOT NULL, description TEXT DEFAULT '',
    tags TEXT DEFAULT '[]', created_at TEXT NOT NULL, updated_at TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY, case_id TEXT NOT NULL, title TEXT NOT NULL,
    content TEXT DEFAULT '', source_url TEXT DEFAULT '', tags TEXT DEFAULT '[]',
    collected_at TEXT NOT NULL, FOREIGN KEY(case_id) REFERENCES cases(id) ON DELETE CASCADE
  );
  CREATE TABLE IF NOT EXISTS searches (
    id INTEGER PRIMARY KEY AUTOINCREMENT, query TEXT NOT NULL,
    type TEXT NOT NULL, searched_at TEXT NOT NULL
  );
`);
db.pragma("foreign_keys = ON");

app.use(express.json({ limit: "1mb" }));
const lookupLimiter = rateLimit({
  windowMs: 60_000,
  limit: 5,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  handler: (_req, res) => res.status(429).json({ error: "Lookup rate limit reached. Wait a minute before trying again." }),
});

const fetchJson = async (url, headers = {}) => {
  const response = await fetch(url, { headers, signal: AbortSignal.timeout(9000) });
  if (!response.ok) throw new Error(`Source returned HTTP ${response.status}`);
  return response.json();
};

function isPublicIp(ip) {
  if (!isIP(ip)) return false;
  try {
    return ipaddr.process(ip).range() === "unicast";
  } catch {
    return false;
  }
}

async function assertPublicHost(hostname) {
  const host = hostname.replace(/^\[|\]$/g, "").toLowerCase();
  if (!host || host === "localhost" || host.endsWith(".localhost") || host.endsWith(".local")) {
    throw new Error("Private or local network addresses are not available for lookup.");
  }
  if (isIP(host)) {
    if (!isPublicIp(host)) throw new Error("Private or local network addresses are not available for lookup.");
    return;
  }
  const addresses = await lookup(host, { all: true, verbatim: true });
  if (!addresses.length || addresses.some(({ address }) => !isPublicIp(address))) {
    throw new Error("The host does not resolve exclusively to public IP addresses.");
  }
}

const isDomain = (value) => value.length <= 253 &&
  /^(?=.{1,253}$)(?:[a-z\d](?:[a-z\d-]{0,61}[a-z\d])?\.)+[a-z]{2,63}$/i.test(value);
const cleanDomain = (value) => value.trim().replace(/^https?:\/\//i, "").split(/[/?#]/)[0].replace(/:\d+$/, "").toLowerCase();
const now = () => new Date().toISOString();
function reverseIpv6(ip) {
  let address = ip.toLowerCase();
  if (address.includes(".")) {
    const lastColon = address.lastIndexOf(":");
    const [first, second, third, fourth] = address.slice(lastColon + 1).split(".").map(Number);
    address = `${address.slice(0, lastColon)}:${((first << 8) | second).toString(16)}:${((third << 8) | fourth).toString(16)}`;
  }
  const [leftPart, rightPart = ""] = address.split("::");
  const left = leftPart ? leftPart.split(":") : [];
  const right = rightPart ? rightPart.split(":") : [];
  const groups = [...left, ...Array(8 - left.length - right.length).fill("0"), ...right];
  return `${groups.map((group) => Number.parseInt(group || "0", 16).toString(16).padStart(4, "0")).join("").split("").reverse().join(".")}.ip6.arpa`;
}
const records = async (name, type) => {
  const data = await fetchJson(`https://dns.google/resolve?name=${encodeURIComponent(name)}&type=${type}`, {
    accept: "application/dns-json",
  });
  if (data.Status !== 0 && data.Status !== 3) throw new Error(`DNS-over-HTTPS lookup failed with status ${data.Status}.`);
  return (data.Answer || []).map((item) => item.data);
};
const optionalJson = async (url, headers) => fetchJson(url, headers).catch(() => null);
function certificateFor(hostname) {
  return new Promise((resolveCertificate) => {
    const socket = tls.connect({ host: hostname, port: 443, servername: hostname, rejectUnauthorized: false, timeout: 5000 }, () => {
      const certificate = socket.getPeerCertificate();
      socket.end();
      resolveCertificate(certificate?.subject ? {
        subject: certificate.subject,
        issuer: certificate.issuer,
        validFrom: certificate.valid_from,
        validTo: certificate.valid_to,
        fingerprint: certificate.fingerprint256,
        subjectAltName: certificate.subjectaltname,
        authorized: socket.authorized,
      } : null);
    });
    socket.on("timeout", () => { socket.destroy(); resolveCertificate(null); });
    socket.on("error", () => resolveCertificate(null));
  });
}
async function optionalIpReputation(ip) {
  const [virusTotal, abuseIpDb, shodan] = await Promise.all([
    process.env.VIRUSTOTAL_API_KEY
      ? optionalJson(`https://www.virustotal.com/api/v3/ip_addresses/${encodeURIComponent(ip)}`, { "x-apikey": process.env.VIRUSTOTAL_API_KEY })
      : Promise.resolve(null),
    process.env.ABUSEIPDB_API_KEY
      ? optionalJson(`https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90`, { Key: process.env.ABUSEIPDB_API_KEY, Accept: "application/json" })
      : Promise.resolve(null),
    process.env.SHODAN_API_KEY
      ? optionalJson(`https://api.shodan.io/shodan/host/${encodeURIComponent(ip)}?key=${encodeURIComponent(process.env.SHODAN_API_KEY)}`)
      : Promise.resolve(null),
  ]);
  return {
    virusTotal: virusTotal?.data?.attributes ? {
      reputation: virusTotal.data.attributes.reputation,
      lastAnalysisStats: virusTotal.data.attributes.last_analysis_stats,
    } : { status: process.env.VIRUSTOTAL_API_KEY ? "provider-unavailable" : "not-configured" },
    abuseIpDb: abuseIpDb?.data ? {
      confidenceScore: abuseIpDb.data.abuseConfidenceScore,
      totalReports: abuseIpDb.data.totalReports,
      lastReportedAt: abuseIpDb.data.lastReportedAt,
      isp: abuseIpDb.data.isp,
    } : { status: process.env.ABUSEIPDB_API_KEY ? "provider-unavailable" : "not-configured" },
    shodan: shodan && !shodan.error ? {
      organization: shodan.org,
      isp: shodan.isp,
      ports: shodan.ports,
      lastUpdate: shodan.last_update,
    } : { status: process.env.SHODAN_API_KEY ? "provider-unavailable" : "not-configured" },
  };
}

async function domainLookup(domain) {
  if (!isDomain(domain)) throw new Error("Enter a valid public domain name.");
  await assertPublicHost(domain);
  const [rdap, a, aaaa, mx, ns, txt, certificates, sslCertificate, virusTotal] = await Promise.all([
    fetchJson(`https://rdap.org/domain/${encodeURIComponent(domain)}`).catch(() => null),
    records(domain, "A"), records(domain, "AAAA"), records(domain, "MX"),
    records(domain, "NS"), records(domain, "TXT"),
    fetchJson(`https://crt.sh/?q=${encodeURIComponent(domain)}&output=json`).catch(() => null),
    certificateFor(domain),
    process.env.VIRUSTOTAL_API_KEY
      ? optionalJson(`https://www.virustotal.com/api/v3/domains/${encodeURIComponent(domain)}`, { "x-apikey": process.env.VIRUSTOTAL_API_KEY })
      : Promise.resolve(null),
  ]);
  const events = rdap?.events || [];
  return {
    domain,
    registration: {
      registrar: rdap?.entities?.find((entity) => entity.roles?.includes("registrar"))?.vcardArray?.[1]?.find((item) => item[0] === "fn")?.[3] || "Not listed by RDAP",
      rdapStatus: rdap ? "available" : "unavailable",
      created: events.find((event) => event.eventAction === "registration")?.eventDate || null,
      expires: events.find((event) => event.eventAction === "expiration")?.eventDate || null,
      updated: events.find((event) => event.eventAction === "last changed")?.eventDate || null,
      status: rdap?.status || [],
    },
    dns: { A: a, AAAA: aaaa, MX: mx, NS: ns, TXT: txt },
    certificates: Array.isArray(certificates) ? certificates.slice(0, 20).map((cert) => ({
      issuer: cert.issuer_name, commonName: cert.common_name, notBefore: cert.not_before,
      notAfter: cert.not_after, name: cert.name_value,
    })) : [],
    certificateTransparencyStatus: certificates === null ? "unavailable" : "available",
    sslCertificate,
    sslCertificateStatus: sslCertificate ? "available" : "unavailable",
    reputation: virusTotal?.data?.attributes ? {
      virusTotal: { reputation: virusTotal.data.attributes.reputation, lastAnalysisStats: virusTotal.data.attributes.last_analysis_stats },
    } : { virusTotal: { status: process.env.VIRUSTOTAL_API_KEY ? "provider-unavailable" : "not-configured" } },
    sources: ["RDAP (rdap.org)", "Google DNS-over-HTTPS", "crt.sh"],
  };
}

async function ipLookup(ip) {
  if (!isIP(ip) || !isPublicIp(ip)) throw new Error("Enter a valid public IP address. Private and local addresses are not queried.");
  const [rdap, geo, reverse, reputation] = await Promise.all([
    fetchJson(`https://rdap.org/ip/${encodeURIComponent(ip)}`).catch(() => null),
    fetchJson(`https://ipwho.is/${encodeURIComponent(ip)}`).catch(() => null),
    records(ip.includes(":") ? reverseIpv6(ip) :
      `${ip.split(".").reverse().join(".")}.in-addr.arpa`, "PTR"),
    optionalIpReputation(ip),
  ]);
  if (geo && geo.success === false) throw new Error(geo.message || "Public geolocation source could not resolve this IP.");
  const connection = geo?.connection || {};
  return {
    ip,
    location: [geo?.city, geo?.region, geo?.country].filter(Boolean).join(", ") || "Not available",
    geolocationStatus: geo ? "available" : "unavailable",
    coordinates: geo?.latitude && geo?.longitude ? [geo.latitude, geo.longitude] : null,
    timezone: geo?.timezone?.id || null,
    isp: connection.isp || "Not listed",
    organization: connection.org || "Not listed",
    asn: connection.asn ? `AS${connection.asn}` : "Not listed",
    reverseDns: reverse,
    network: rdap ? { name: rdap.name, handle: rdap.handle, country: rdap.country, startAddress: rdap.startAddress, endAddress: rdap.endAddress } : null,
    networkRegistrationStatus: rdap ? "available" : "unavailable",
    reputation,
    sources: ["ipwho.is (approximate geolocation)", "RDAP (rdap.org)", "Google DNS-over-HTTPS"],
  };
}

async function websiteLookup(input) {
  let url;
  try {
    url = new URL(input.includes("://") ? input : `https://${input}`);
  } catch {
    throw new Error("Enter a valid public website URL.");
  }
  if (!["http:", "https:"].includes(url.protocol)) throw new Error("Only HTTP and HTTPS websites can be checked.");
  if (url.username || url.password) throw new Error("URLs containing credentials are not supported.");
  await assertPublicHost(url.hostname);
  const response = await fetch(url, {
    redirect: "manual", signal: AbortSignal.timeout(10000),
    headers: { "user-agent": "SentinelOSINT/1.0 (public metadata research)" },
  });
  const headers = Object.fromEntries([...response.headers.entries()]);
  if (response.status >= 300 && response.status < 400) {
    return { url: url.href, status: response.status, headers, title: null, description: null, technologies: [], redirect: response.headers.get("location"), robots: null, sitemap: null, note: "Redirect was not followed. Inspect the destination separately.", sources: [url.origin] };
  }
  const html = (await response.text()).slice(0, 750_000);
  const title = html.match(/<title[^>]*>([\s\S]*?)<\/title>/i)?.[1]?.replace(/\s+/g, " ").trim() || null;
  const description = html.match(/<meta[^>]+name=["']description["'][^>]+content=["']([^"']*)/i)?.[1] ||
    html.match(/<meta[^>]+content=["']([^"']*)["'][^>]+name=["']description["']/i)?.[1] || null;
  const generator = html.match(/<meta[^>]+name=["']generator["'][^>]+content=["']([^"']*)/i)?.[1] || null;
  const technologies = [generator, /wp-content|wp-includes/i.test(html) ? "WordPress" : null,
    headers["server"] ? `Server: ${headers["server"]}` : null,
    headers["x-powered-by"] ? `Powered by: ${headers["x-powered-by"]}` : null].filter(Boolean);
  const [robots, sitemap] = await Promise.all([
    fetch(new URL("/robots.txt", url), { redirect: "manual", signal: AbortSignal.timeout(6000) }).then((res) => res.ok ? res.text() : null).catch(() => null),
    fetch(new URL("/sitemap.xml", url), { redirect: "manual", signal: AbortSignal.timeout(6000) }).then((res) => res.ok ? res.text() : null).catch(() => null),
  ]);
  const sslCertificate = url.protocol === "https:" ? await certificateFor(url.hostname) : null;
  return {
    url: url.href, status: response.status, headers, title, description, technologies,
    robots: robots?.slice(0, 12000) || null, sitemap: sitemap?.slice(0, 12000) || null,
    ssl: url.protocol === "https:" ? sslCertificate : "Not using HTTPS",
    sslStatus: url.protocol === "https:" ? sslCertificate ? "available" : "unavailable" : "not-applicable",
    sources: [url.origin, `${url.origin}/robots.txt`, `${url.origin}/sitemap.xml`],
  };
}

async function emailLookup(email) {
  const normalized = email.trim().toLowerCase();
  if (normalized.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalized)) {
    throw new Error("Enter an email address with valid syntax.");
  }
  const domain = normalized.split("@")[1];
  if (!isDomain(domain)) throw new Error("The email domain is not valid.");
  const mx = await records(domain, "MX");
  let breaches = { status: "unavailable", message: "Configure HIBP_API_KEY on the server to check publicly documented breach records." };
  if (process.env.HIBP_API_KEY) {
    try {
      const data = await fetchJson(`https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(normalized)}?truncateResponse=true`, {
        "hibp-api-key": process.env.HIBP_API_KEY, "user-agent": "SentinelOSINT/1.0",
      });
      breaches = { status: "matches", records: data.map((item) => ({ name: item.Name, domain: item.Domain, date: item.BreachDate })) };
    } catch (error) {
      if (String(error.message).includes("404")) breaches = { status: "no-matches-returned", records: [] };
      else breaches = { status: "unavailable", message: "Breach provider could not complete this check." };
    }
  }
  return { email: normalized, syntaxValid: true, domain, mxRecords: mx, mxConfigured: mx.length > 0, breaches, sources: ["Google DNS-over-HTTPS", ...(process.env.HIBP_API_KEY ? ["Have I Been Pwned"] : [])] };
}

app.get("/api/health", (_req, res) => res.json({
  status: "ok",
  integrations: { rdap: true, dnsOverHttps: true, crtSh: true, virusTotal: Boolean(process.env.VIRUSTOTAL_API_KEY), abuseIpDb: Boolean(process.env.ABUSEIPDB_API_KEY), shodan: Boolean(process.env.SHODAN_API_KEY), hibp: Boolean(process.env.HIBP_API_KEY) },
}));

app.post("/api/lookup", lookupLimiter, async (req, res) => {
  const { type, query } = req.body || {};
  if (typeof query !== "string" || query.length > 500) return res.status(400).json({ error: "Provide a search value under 500 characters." });
  try {
    const value = query.trim();
    let result;
    if (type === "domain") result = await domainLookup(cleanDomain(value));
    else if (type === "ip") result = await ipLookup(value);
    else if (type === "website") result = await websiteLookup(value);
    else if (type === "email") result = await emailLookup(value);
    else return res.status(400).json({ error: "This lookup type is not supported by the research API." });
    db.prepare("INSERT INTO searches (query, type, searched_at) VALUES (?, ?, ?)").run(value, type, now());
    res.json({ type, query: value, collectedAt: now(), result });
  } catch (error) {
    res.status(422).json({ error: error.message || "The public source could not complete this lookup." });
  }
});

app.post("/api/searches", (req, res) => {
  const { query, type } = req.body || {};
  if (typeof query !== "string" || !query.trim() || query.length > 500 ||
      !["domain", "ip", "website", "username", "email", "image"].includes(type)) {
    return res.status(400).json({ error: "Provide a valid search value and supported search type." });
  }
  db.prepare("INSERT INTO searches (query, type, searched_at) VALUES (?, ?, ?)").run(query.trim(), type, now());
  res.status(201).json({ status: "saved" });
});

app.get("/api/dashboard", (_req, res) => {
  const searches = db.prepare("SELECT query, type, searched_at AS searchedAt FROM searches ORDER BY id DESC").all();
  const cases = db.prepare("SELECT id, title, description, tags, created_at AS createdAt, updated_at AS updatedAt FROM cases ORDER BY updated_at DESC").all()
    .map((item) => ({ ...item, tags: JSON.parse(item.tags || "[]") }));
  const findings = db.prepare("SELECT id, case_id AS caseId, title, content, source_url AS sourceUrl, tags, collected_at AS collectedAt FROM findings ORDER BY collected_at DESC").all()
    .map((item) => ({ ...item, tags: JSON.parse(item.tags || "[]") }));
  const stats = {
    investigations: db.prepare("SELECT COUNT(*) AS count FROM cases").get().count,
    searches: db.prepare("SELECT COUNT(*) AS count FROM searches").get().count,
    findings: db.prepare("SELECT COUNT(*) AS count FROM findings").get().count,
  };
  res.json({ searches, cases, findings, stats });
});

app.post("/api/cases", (req, res) => {
  const { title, description = "", tags = [] } = req.body || {};
  if (typeof title !== "string" || !title.trim() || title.length > 120) return res.status(400).json({ error: "A case title between 1 and 120 characters is required." });
  const id = randomUUID();
  const timestamp = now();
  db.prepare("INSERT INTO cases (id,title,description,tags,created_at,updated_at) VALUES (?,?,?,?,?,?)")
    .run(id, title.trim(), String(description).slice(0, 2000), JSON.stringify(Array.isArray(tags) ? tags.slice(0, 20) : []), timestamp, timestamp);
  res.status(201).json({ id, title: title.trim(), description, tags, createdAt: timestamp, updatedAt: timestamp });
});

app.post("/api/cases/:id/findings", (req, res) => {
  const { title, content = "", sourceUrl = "", tags = [] } = req.body || {};
  if (!db.prepare("SELECT id FROM cases WHERE id = ?").get(req.params.id)) return res.status(404).json({ error: "Investigation case not found." });
  if (typeof title !== "string" || !title.trim() || title.length > 160) return res.status(400).json({ error: "A finding title is required (160 characters maximum)." });
  const id = randomUUID();
  const timestamp = now();
  db.prepare("INSERT INTO findings (id,case_id,title,content,source_url,tags,collected_at) VALUES (?,?,?,?,?,?,?)")
    .run(id, req.params.id, title.trim(), String(content).slice(0, 10000), String(sourceUrl).slice(0, 1000), JSON.stringify(Array.isArray(tags) ? tags.slice(0, 20) : []), timestamp);
  db.prepare("UPDATE cases SET updated_at = ? WHERE id = ?").run(timestamp, req.params.id);
  res.status(201).json({ id, caseId: req.params.id, title: title.trim(), content, sourceUrl, tags, collectedAt: timestamp });
});

app.delete("/api/cases/:id", (req, res) => {
  const result = db.prepare("DELETE FROM cases WHERE id = ?").run(req.params.id);
  if (!result.changes) return res.status(404).json({ error: "Investigation case not found." });
  res.status(204).end();
});

app.use(express.static(resolve("dist")));
const host = process.env.HOST || "127.0.0.1";
app.listen(port, host, () => console.log(`Sentinel API listening on http://${host}:${port}`));
