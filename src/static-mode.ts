import ipaddr from "ipaddr.js";

type SearchType = "domain" | "ip" | "website" | "username" | "email" | "image";
type RecordMap = Record<string, unknown>;
type CaseRecord = { id: string; title: string; description: string; tags: string[]; createdAt: string; updatedAt: string };
type FindingRecord = { id: string; caseId: string; title: string; content: string; sourceUrl: string; tags: string[]; collectedAt: string };
type SearchRecord = { query: string; type: string; searchedAt: string };
type Store = { cases: CaseRecord[]; findings: FindingRecord[]; searches: SearchRecord[] };

const STORAGE_KEY = "sentinel-osint-static-v1";
const emptyStore = (): Store => ({ cases: [], findings: [], searches: [] });

function readStore(): Store {
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    if (!raw) return emptyStore();
    const parsed: unknown = JSON.parse(raw);
    if (!parsed || typeof parsed !== "object") return emptyStore();
    const store = parsed as Partial<Store>;
    return {
      cases: Array.isArray(store.cases) ? store.cases : [],
      findings: Array.isArray(store.findings) ? store.findings : [],
      searches: Array.isArray(store.searches) ? store.searches : [],
    };
  } catch {
    throw new Error("Local workspace storage is unavailable. Check your browser storage settings.");
  }
}

function writeStore(store: Store) {
  try {
    window.localStorage.setItem(STORAGE_KEY, JSON.stringify(store));
  } catch {
    throw new Error("Could not save this workspace to browser storage. Check available storage and privacy settings.");
  }
}

function jsonBody(init?: RequestInit): RecordMap {
  if (!init?.body || typeof init.body !== "string") return {};
  try {
    return JSON.parse(init.body) as RecordMap;
  } catch {
    throw new Error("Invalid request data.");
  }
}

async function publicJson(url: string): Promise<RecordMap> {
  const response = await fetch(url, { signal: AbortSignal.timeout(9000) });
  if (!response.ok) throw new Error(`Public source returned HTTP ${response.status}.`);
  return response.json() as Promise<RecordMap>;
}

async function dnsRecords(name: string, type: string) {
  const data = await publicJson(`https://dns.google/resolve?name=${encodeURIComponent(name)}&type=${type}`);
  const status = Number(data.Status);
  if (status !== 0 && status !== 3) throw new Error(`DNS-over-HTTPS lookup failed with status ${status}.`);
  return {
    status: status === 0 ? "available" : "no-records",
    records: Array.isArray(data.Answer) ? data.Answer.map((record: RecordMap) => record.data) : [],
  };
}

async function optionalJson(url: string): Promise<RecordMap | null> {
  try {
    return await publicJson(url);
  } catch {
    return null;
  }
}

const isDomain = (value: string) => value.length <= 253 &&
  /^(?=.{1,253}$)(?:[a-z\d](?:[a-z\d-]{0,61}[a-z\d])?\.)+[a-z]{2,63}$/i.test(value);

function validatePublicIp(value: string) {
  if (!ipaddr.isValid(value)) throw new Error("Enter a valid public IP address.");
  if (ipaddr.process(value).range() !== "unicast") throw new Error("Private, reserved, and local IP addresses are not queried.");
}

async function domainLookup(value: string): Promise<RecordMap> {
  const domain = value.trim().replace(/^https?:\/\//i, "").split(/[/?#]/)[0].replace(/:\d+$/, "").toLowerCase();
  if (!isDomain(domain)) throw new Error("Enter a valid domain name.");
  const [rdap, a, aaaa, mx, ns, txt, certificates] = await Promise.all([
    optionalJson(`https://rdap.org/domain/${encodeURIComponent(domain)}`),
    dnsRecords(domain, "A"), dnsRecords(domain, "AAAA"), dnsRecords(domain, "MX"),
    dnsRecords(domain, "NS"), dnsRecords(domain, "TXT"),
    optionalJson(`https://crt.sh/?q=${encodeURIComponent(domain)}&output=json`),
  ]);
  const events = Array.isArray(rdap?.events) ? rdap.events as RecordMap[] : [];
  const entities = Array.isArray(rdap?.entities) ? rdap.entities as RecordMap[] : [];
  const registrar = entities.find((entity) => Array.isArray(entity.roles) && entity.roles.includes("registrar"));
  const vcard = registrar?.vcardArray as unknown[] | undefined;
  const vcardEntries = Array.isArray(vcard?.[1]) ? vcard[1] as unknown[][] : [];
  const registrarName = vcardEntries.find((entry) => entry[0] === "fn")?.[3];
  const certificatesList = Array.isArray(certificates) ? certificates as RecordMap[] : null;
  return {
    domain,
    registration: {
      registrar: typeof registrarName === "string" ? registrarName : "Not listed by RDAP",
      created: events.find((event) => event.eventAction === "registration")?.eventDate || null,
      expires: events.find((event) => event.eventAction === "expiration")?.eventDate || null,
      updated: events.find((event) => event.eventAction === "last changed")?.eventDate || null,
      status: rdap?.status || [],
      rdapStatus: rdap ? "available" : "unavailable",
    },
    dns: { A: a.records, AAAA: aaaa.records, MX: mx.records, NS: ns.records, TXT: txt.records },
    dnsStatus: { A: a.status, AAAA: aaaa.status, MX: mx.status, NS: ns.status, TXT: txt.status },
    certificates: certificatesList?.slice(0, 20).map((cert) => ({
      issuer: cert.issuer_name, commonName: cert.common_name, notBefore: cert.not_before,
      notAfter: cert.not_after, name: cert.name_value,
    })) || [],
    certificateTransparencyStatus: certificatesList ? "available" : "unavailable",
    sslCertificateStatus: "unavailable",
    reputation: { virusTotal: { status: "not-configured" } },
    sources: ["Google DNS-over-HTTPS", ...(rdap ? ["RDAP (rdap.org)"] : []), ...(certificatesList ? ["crt.sh"] : [])],
  };
}

async function ipLookup(ip: string): Promise<RecordMap> {
  validatePublicIp(ip);
  const [rdap, geo, reverse, reputation] = await Promise.all([
    optionalJson(`https://rdap.org/ip/${encodeURIComponent(ip)}`),
    optionalJson(`https://ipwho.is/${encodeURIComponent(ip)}`),
    dnsRecords(`${ip.split(".").reverse().join(".")}.in-addr.arpa`, "PTR").catch(() => null),
    Promise.resolve({
      virusTotal: { status: "not-configured" },
      abuseIpDb: { status: "not-configured" },
      shodan: { status: "not-configured" },
    }),
  ]);
  if (geo?.success === false) throw new Error(String(geo.message || "The geolocation source could not resolve this IP."));
  const connection = (geo?.connection || {}) as RecordMap;
  return {
    ip,
    location: [geo?.city, geo?.region, geo?.country].filter(Boolean).join(", ") || "Not available",
    coordinates: typeof geo?.latitude === "number" && typeof geo?.longitude === "number" ? [geo.latitude, geo.longitude] : null,
    geolocationStatus: geo ? "available" : "unavailable",
    timezone: (geo?.timezone as RecordMap | undefined)?.id || null,
    isp: connection.isp || "Not listed",
    organization: connection.org || "Not listed",
    asn: connection.asn ? `AS${connection.asn}` : "Not listed",
    reverseDns: reverse?.records || [],
    reverseDnsStatus: reverse?.status || "unavailable",
    network: rdap ? { name: rdap.name, handle: rdap.handle, country: rdap.country, startAddress: rdap.startAddress, endAddress: rdap.endAddress } : null,
    networkRegistrationStatus: rdap ? "available" : "unavailable",
    reputation,
    sources: ["ipwho.is (approximate geolocation)", "RDAP (rdap.org)", ...(reverse ? ["Google DNS-over-HTTPS"] : [])],
  };
}

async function emailLookup(value: string): Promise<RecordMap> {
  const email = value.trim().toLowerCase();
  if (email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) throw new Error("Enter an email address with valid syntax.");
  const domain = email.split("@")[1];
  if (!isDomain(domain)) throw new Error("The email domain is not valid.");
  const mx = await dnsRecords(domain, "MX");
  return {
    email, syntaxValid: true, domain, mxRecords: mx.records, mxStatus: mx.status,
    mxConfigured: mx.records.length > 0,
    breaches: { status: "not-configured", message: "Breach checks require a server-side HIBP_API_KEY. No breach provider was queried." },
    sources: ["Google DNS-over-HTTPS"],
  };
}

async function lookup(type: SearchType, query: string) {
  let result: RecordMap;
  if (type === "domain") result = await domainLookup(query);
  else if (type === "ip") result = await ipLookup(query);
  else if (type === "email") result = await emailLookup(query);
  else if (type === "website") throw new Error("Website analysis needs a backend: browser security blocks safely fetching arbitrary websites. Deploy the API separately for this module.");
  else throw new Error("This lookup is available from the local workspace only.");
  return { type, query, collectedAt: new Date().toISOString(), result };
}

export async function staticApi<T>(url: string, init?: RequestInit): Promise<T> {
  const method = (init?.method || "GET").toUpperCase();
  const body = jsonBody(init);
  const store = readStore();

  if (url === "/api/dashboard" && method === "GET") {
    return {
      searches: store.searches,
      cases: store.cases,
      findings: store.findings,
      stats: {
        investigations: store.cases.length,
        searches: store.searches.length,
        findings: store.findings.length,
      },
    } as T;
  }

  if (url === "/api/health" && method === "GET") {
    return {
      status: "static",
      integrations: { rdap: true, dnsOverHttps: true, crtSh: true, virusTotal: false, abuseIpDb: false, shodan: false, hibp: false },
    } as T;
  }

  if (url === "/api/cases" && method === "POST") {
    if (typeof body.title !== "string" || !body.title.trim()) throw new Error("An investigation title is required.");
    const timestamp = new Date().toISOString();
    const item: CaseRecord = {
      id: crypto.randomUUID(), title: body.title.trim(), description: String(body.description || ""),
      tags: Array.isArray(body.tags) ? body.tags as string[] : [], createdAt: timestamp, updatedAt: timestamp,
    };
    writeStore({ ...store, cases: [item, ...store.cases] });
    return item as T;
  }

  if (url === "/api/searches" && method === "POST") {
    if (typeof body.query !== "string" || typeof body.type !== "string") throw new Error("A search query and type are required.");
    writeStore({ ...store, searches: [{ query: body.query, type: body.type, searchedAt: new Date().toISOString() }, ...store.searches] });
    return { status: "saved" } as T;
  }

  const findingMatch = url.match(/^\/api\/cases\/([^/]+)\/findings$/);
  if (findingMatch && method === "POST") {
    const caseId = decodeURIComponent(findingMatch[1]);
    if (!store.cases.some((item) => item.id === caseId)) throw new Error("Investigation case not found.");
    if (typeof body.title !== "string" || !body.title.trim()) throw new Error("A finding title is required.");
    const timestamp = new Date().toISOString();
    const finding: FindingRecord = {
      id: crypto.randomUUID(), caseId, title: body.title.trim(), content: String(body.content || ""),
      sourceUrl: String(body.sourceUrl || ""), tags: Array.isArray(body.tags) ? body.tags as string[] : [], collectedAt: timestamp,
    };
    writeStore({
      ...store,
      cases: store.cases.map((item) => item.id === caseId ? { ...item, updatedAt: timestamp } : item),
      findings: [finding, ...store.findings],
    });
    return finding as T;
  }

  const caseMatch = url.match(/^\/api\/cases\/([^/]+)$/);
  if (caseMatch && method === "DELETE") {
    const caseId = decodeURIComponent(caseMatch[1]);
    writeStore({ ...store, cases: store.cases.filter((item) => item.id !== caseId), findings: store.findings.filter((item) => item.caseId !== caseId) });
    return undefined as T;
  }

  if (url === "/api/lookup" && method === "POST") {
    const type = body.type;
    if (!["domain", "ip", "website", "email"].includes(String(type)) || typeof body.query !== "string") {
      throw new Error("This lookup type is not available in static mode.");
    }
    const response = await lookup(type as SearchType, body.query);
    writeStore({ ...store, searches: [{ query: body.query, type: String(type), searchedAt: response.collectedAt }, ...store.searches] });
    return response as T;
  }

  throw new Error("This action is not available in the static workspace.");
}
