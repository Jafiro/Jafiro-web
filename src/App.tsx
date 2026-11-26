import { useEffect, useMemo, useRef, useState, type FormEvent, type ReactNode, type RefObject } from "react";
import ReactFlow, { Background, Controls, MiniMap, type Edge, type Node } from "reactflow";
import {
  ArrowDownRight, ArrowRight, ArrowUpRight, Bookmark, BriefcaseBusiness,
  Check, ChevronDown, ChevronRight, CircleAlert, Clock3, Copy, Database, Download,
  ExternalLink, FileImage, FileSearch, Fingerprint, Globe2, Hexagon, History, House,
  Info, Layers3, LoaderCircle, LockKeyhole, Mail, Menu, Plus, Radar,
  Search, SearchCheck, Shield, ShieldCheck, Sparkles, Target, Trash2, Upload,
  UserRound, X,
} from "lucide-react";
import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { staticApi } from "./static-mode";

type ToolKey = "domain" | "ip" | "website" | "username" | "email" | "image";
type RecordMap = Record<string, unknown>;
type LookupResponse = { type: string; query: string; collectedAt: string; result: RecordMap };
type Investigation = { id: string; title: string; description?: string; tags: string[]; createdAt: string; updatedAt: string };
type Finding = { id: string; caseId: string; title: string; content: string; sourceUrl: string; tags: string[]; collectedAt: string };
type Dashboard = { searches: { query: string; type: string; searchedAt: string }[]; cases: Investigation[]; findings: Finding[]; stats: { investigations: number; searches: number; findings: number } };
type Integrations = { rdap: boolean; dnsOverHttps: boolean; crtSh: boolean; virusTotal: boolean; abuseIpDb: boolean; shodan: boolean; hibp: boolean };

const tools: { id: ToolKey; label: string; description: string; icon: typeof Globe2; placeholder: string; color: string }[] = [
  { id: "domain", label: "Domain intelligence", description: "WHOIS · DNS · certificates", icon: Globe2, placeholder: "example.com", color: "mint" },
  { id: "ip", label: "IP intelligence", description: "Geolocation · ASN · reverse DNS", icon: Radar, placeholder: "8.8.8.8", color: "blue" },
  { id: "website", label: "Website analysis", description: "Headers · metadata · public files", icon: FileSearch, placeholder: "https://example.com", color: "violet" },
  { id: "username", label: "Username search", description: "Public profile links · unverified", icon: UserRound, placeholder: "username", color: "amber" },
  { id: "email", label: "Email intelligence", description: "Syntax · MX · public breach data", icon: Mail, placeholder: "name@example.com", color: "blue" },
  { id: "image", label: "Image metadata", description: "EXIF · dimensions · reverse search", icon: FileImage, placeholder: "Choose an image file", color: "violet" },
];

const demoActivity = [
  { day: "MON", searches: 3 }, { day: "TUE", searches: 5 }, { day: "WED", searches: 4 },
  { day: "THU", searches: 8 }, { day: "FRI", searches: 6 }, { day: "SAT", searches: 10 },
  { day: "SUN", searches: 7 },
];
const todayLabel = new Intl.DateTimeFormat("en", { weekday: "long", month: "long", day: "numeric", year: "numeric" }).format(new Date()).toUpperCase();
const demoDomains = [
  { domain: "northstar-labs.io", date: "2 min ago", status: "DEMO" },
  { domain: "meridian-data.org", date: "18 min ago", status: "DEMO" },
  { domain: "atlas-network.net", date: "1 hr ago", status: "DEMO" },
];
const profiles = [
  ["GitHub", "https://github.com/"], ["Reddit", "https://www.reddit.com/user/"],
  ["Instagram", "https://www.instagram.com/"], ["X", "https://x.com/"],
  ["TikTok", "https://www.tiktok.com/@"], ["Medium", "https://medium.com/@"],
  ["Pinterest", "https://www.pinterest.com/"], ["Keybase", "https://keybase.io/"],
];

function guessType(query: string): ToolKey {
  const value = query.trim();
  if (value.includes("@")) return "email";
  if (/^(https?:\/\/)/i.test(value) || (value.includes("/") && value.includes("."))) return "website";
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(value) || value.includes(":")) return "ip";
  if (/^(?=.{1,253}$)(?:[a-z\d](?:[a-z\d-]{0,61}[a-z\d])?\.)+[a-z]{2,63}$/i.test(value)) return "domain";
  return "username";
}

async function api<T>(url: string, init?: RequestInit): Promise<T> {
  if (import.meta.env.VITE_STATIC_MODE === "true") return staticApi<T>(url, init);
  const response = await fetch(url, {
    ...init,
    headers: { "Content-Type": "application/json", ...init?.headers },
  });
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    throw new Error(body.error || `Request failed (${response.status})`);
  }
  if (response.status === 204) return undefined as T;
  return response.json();
}

function display(value: unknown): string {
  if (value === null || value === undefined || value === "") return "Not available";
  if (Array.isArray(value)) return value.length ? value.map((item) => typeof item === "object" ? JSON.stringify(item) : String(item)).join(", ") : "None returned";
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}

function formatTime(value?: string) {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString([], { dateStyle: "medium", timeStyle: "short" });
}

function App() {
  const [page, setPage] = useState("Overview");
  const [tool, setTool] = useState<ToolKey>("domain");
  const [query, setQuery] = useState("");
  const [result, setResult] = useState<LookupResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [dashboard, setDashboard] = useState<Dashboard>({ searches: [], cases: [], findings: [], stats: { investigations: 0, searches: 0, findings: 0 } });
  const [backendOnline, setBackendOnline] = useState(false);
  const [integrations, setIntegrations] = useState<Integrations | null>(null);
  const [modal, setModal] = useState<"case" | "finding" | null>(null);
  const [selectedCase, setSelectedCase] = useState("");
  const [mobileNav, setMobileNav] = useState(false);
  const [toast, setToast] = useState("");
  const [imageData, setImageData] = useState<RecordMap | null>(null);
  const [exif, setExif] = useState<RecordMap | null>(null);
  const [imageName, setImageName] = useState("");
  const imageInput = useRef<HTMLInputElement>(null);
  const formInput = useRef<HTMLInputElement>(null);

  const refresh = async () => {
    try {
      const data = await api<Dashboard>("/api/dashboard");
      setDashboard(data);
      setBackendOnline(import.meta.env.VITE_STATIC_MODE !== "true");
    } catch {
      setBackendOnline(false);
    }
  };
  useEffect(() => {
    void refresh();
    void api<{ integrations: Integrations }>("/api/health").then((health) => setIntegrations(health.integrations)).catch(() => setIntegrations(null));
  }, []);

  useEffect(() => {
    if (!toast) return;
    const timer = window.setTimeout(() => setToast(""), 3200);
    return () => window.clearTimeout(timer);
  }, [toast]);

  const activeTool = tools.find((item) => item.id === tool)!;
  const chartData = useMemo(() => {
    if (!dashboard.searches.length) return demoActivity;
    const lastWeek = Array.from({ length: 7 }, (_, index) => {
      const date = new Date();
      date.setDate(date.getDate() - (6 - index));
      const key = date.toLocaleDateString("en", { weekday: "short" }).toUpperCase();
      const count = dashboard.searches.filter((item) => new Date(item.searchedAt).toDateString() === date.toDateString()).length;
      return { day: key, searches: count };
    });
    return lastWeek;
  }, [dashboard.searches]);

  const startSearch = (value: string, selected = guessType(value)) => {
    setQuery(value);
    setTool(selected);
    setResult(null);
    setError("");
    setPage("Tools");
    setMobileNav(false);
    window.setTimeout(() => formInput.current?.focus(), 0);
  };

  const submitSearch = async (event?: FormEvent) => {
    event?.preventDefault();
    const value = query.trim();
    if (!value) {
      setError("Enter a value to investigate.");
      return;
    }
    setLoading(true);
    setError("");
    setResult(null);
    try {
      if (tool === "username") {
        const username = value.replace(/^@/, "").trim();
        if (!/^[\w.-]{1,39}$/.test(username)) throw new Error("Use a username with letters, numbers, dots, underscores or hyphens.");
        setResult({
          type: "username", query: username, collectedAt: new Date().toISOString(),
          result: { profiles: profiles.map(([platform, base]) => ({ platform, url: `${base}${encodeURIComponent(username)}`, status: "unverified" })), note: "Links are search starting points only. No platform was queried, and profile existence is not confirmed.", sources: ["Public profile URL patterns"] },
        });
        await api("/api/searches", { method: "POST", body: JSON.stringify({ query: username, type: "username" }) });
        await refresh();
      } else if (tool === "image") {
        if (!imageData) throw new Error("Choose an image file first.");
        setResult({ type: "image", query: imageName, collectedAt: new Date().toISOString(), result: { ...imageData, exif, sources: ["Local image file metadata"] } });
        await api("/api/searches", { method: "POST", body: JSON.stringify({ query: imageName, type: "image" }) });
        await refresh();
      } else {
        const data = await api<LookupResponse>("/api/lookup", {
          method: "POST", body: JSON.stringify({ type: tool, query: value }),
        });
        setResult(data);
        await refresh();
      }
    } catch (issue) {
      setError(issue instanceof Error ? issue.message : "The lookup failed. Please try again.");
    } finally {
      setLoading(false);
    }
  };

  const pickImage = async (file?: File) => {
    setImageData(null);
    setExif(null);
    if (!file) return;
    if (!file.type.startsWith("image/")) {
      setError("Choose a valid image file.");
      return;
    }
    setError("");
    setImageName(file.name);
    const objectUrl = URL.createObjectURL(file);
    const image = new Image();
    image.onload = async () => {
      setImageData({ name: file.name, type: file.type, size: `${(file.size / 1024).toFixed(1)} KB`, width: image.naturalWidth, height: image.naturalHeight, lastModified: formatTime(new Date(file.lastModified).toISOString()) });
      URL.revokeObjectURL(objectUrl);
    };
    image.onerror = () => {
      URL.revokeObjectURL(objectUrl);
      setError("This image could not be read.");
    };
    image.src = objectUrl;
    try {
      const { parse } = await import("exifr");
      const meta = await parse(file, { gps: true, tiff: true, exif: true, xmp: true, iptc: true });
      if (meta) setExif(meta as RecordMap);
    } catch {
      setExif(null);
    }
    setQuery(file.name);
  };

  const createCase = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    try {
      const item = await api<Investigation>("/api/cases", {
        method: "POST", body: JSON.stringify({ title: form.get("title"), description: form.get("description"), tags: String(form.get("tags") || "").split(",").map((tag) => tag.trim()).filter(Boolean) }),
      });
      await refresh();
      setSelectedCase(item.id);
      setModal(null);
      setToast("Investigation created");
    } catch (issue) {
      setError(issue instanceof Error ? issue.message : "Could not create the investigation.");
      setModal(null);
    }
  };

  const saveFinding = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!selectedCase) {
      setToast("Create an investigation case before saving findings.");
      setModal(null);
      return;
    }
    const form = new FormData(event.currentTarget);
    try {
      await api(`/api/cases/${selectedCase}/findings`, {
        method: "POST",
        body: JSON.stringify({
          title: form.get("title"), content: form.get("content"),
          sourceUrl: form.get("sourceUrl"),
          tags: String(form.get("tags") || "").split(",").map((tag) => tag.trim()).filter(Boolean),
        }),
      });
      await refresh();
      setModal(null);
      setToast("Finding saved to investigation");
    } catch (issue) {
      setError(issue instanceof Error ? issue.message : "Could not save this finding.");
      setModal(null);
    }
  };

  const deleteCase = async (item: Investigation) => {
    if (!window.confirm(`Delete "${item.title}" and all of its findings? This cannot be undone.`)) return;
    try {
      await api(`/api/cases/${item.id}`, { method: "DELETE" });
      if (selectedCase === item.id) setSelectedCase("");
      await refresh();
      setToast("Investigation deleted");
    } catch (issue) {
      setError(issue instanceof Error ? issue.message : "Could not delete the investigation.");
    }
  };

  const exportReport = () => {
    if (!selectedCase) {
      setToast("Select an investigation to export.");
      return;
    }
    window.print();
  };

  const navigation = [
    { label: "Overview", icon: House, group: "WORKSPACE" },
    { label: "Investigations", icon: BriefcaseBusiness, group: "WORKSPACE" },
    { label: "Tools", icon: Layers3, group: "INTELLIGENCE" },
    { label: "Activity", icon: History, group: "INTELLIGENCE" },
  ];

  return (
    <div className="app-shell">
      <aside className={`sidebar ${mobileNav ? "sidebar-open" : ""}`}>
        <div className="brand"><div className="brand-mark"><Hexagon size={20} strokeWidth={2.2} /><span /></div><div><div className="brand-name">SENTINEL<span>.</span></div><div className="brand-caption">OPEN-SOURCE INTELLIGENCE</div></div><button className="icon-btn sidebar-close" aria-label="Close menu" onClick={() => setMobileNav(false)}><X size={17} /></button></div>
        <button className="workspace-switch" onClick={() => setToast("Personal workspace · SQLite data stays on this server")}><span className="workspace-avatar">S</span><span className="workspace-copy"><b>Research workspace</b><small>Personal workspace</small></span><ChevronDown size={15} /></button>
        {["WORKSPACE", "INTELLIGENCE"].map((group) => (
          <div className="nav-group" key={group}>
            <div className="nav-label">{group}</div>
            {navigation.filter((item) => item.group === group).map(({ label, icon: Icon }) => (
              <button key={label} className={`nav-item ${page === label ? "selected" : ""}`} onClick={() => { setPage(label); setMobileNav(false); }}>
                <Icon size={17} strokeWidth={1.8} /><span>{label}</span>{label === "Investigations" && dashboard.cases.length > 0 && <span className="nav-count">{dashboard.cases.length}</span>}
              </button>
            ))}
          </div>
        ))}
        <div className="sidebar-tools">
          <div className="nav-label">QUICK LOOKUP</div>
          {tools.slice(0, 4).map(({ id, label, icon: Icon, color }) => (
            <button key={id} className="nav-tool" onClick={() => startSearch("", id)}>
              <span className={`tiny-icon ${color}`}><Icon size={14} /></span>{label.replace(" intelligence", "").replace(" analysis", "")}<ArrowRight size={13} className="nav-tool-arrow" />
            </button>
          ))}
        </div>
        <div className="sidebar-bottom">
          <div className="privacy-card"><div className="privacy-icon"><ShieldCheck size={16} /></div><div><b>Privacy-first research</b><span>Public sources only</span></div><Check size={14} className="privacy-check" /></div>
          <div className="user-profile"><div className="user-avatar">AN</div><div className="user-copy"><b>Analyst</b><small>Free workspace</small></div><button className="icon-btn" title="Workspace information" onClick={() => setToast("Sentinel OSINT · local SQLite workspace")}><ChevronDown size={15} /></button></div>
        </div>
      </aside>
      {mobileNav && <button className="nav-backdrop" onClick={() => setMobileNav(false)} aria-label="Close navigation" />}

      <main className="main-area">
        <header className="topbar">
          <div className="topbar-left"><button className="icon-btn menu-toggle" onClick={() => setMobileNav(true)} aria-label="Open menu"><Menu size={19} /></button><div className="breadcrumb"><span>Workspace</span><ChevronRight size={14} /><b>{page}</b></div></div>
          <form className="global-search" onSubmit={(event) => { event.preventDefault(); startSearch((event.currentTarget.elements.namedItem("global-search") as HTMLInputElement).value); }}>
            <Search size={16} /><input name="global-search" placeholder="Search a domain, IP, email, username or URL..." aria-label="Universal search" /><kbd>↵</kbd>
          </form>
          <div className="topbar-right"><span className={`connection ${backendOnline ? "online" : "offline"}`}><i />{backendOnline ? "API CONNECTED" : import.meta.env.VITE_STATIC_MODE === "true" ? "STATIC · LOCAL DATA" : "DEMO MODE"}</span><button className="icon-btn top-info" title="Data source information" onClick={() => setToast(import.meta.env.VITE_STATIC_MODE === "true" ? "Investigation data is stored in this browser. Live lookups use public endpoints; private-key integrations require a backend." : "Lookups query public sources. Demo dashboard metrics are illustrative only.")}><Info size={17} /></button><div className="user-avatar top-avatar">AN</div></div>
        </header>

        <div className="content-scroll">
          {page === "Overview" && <DashboardPage dashboard={dashboard} chartData={chartData} onNavigate={setPage} onSearch={startSearch} />}
          {page === "Tools" && <ToolsPage tool={tool} query={query} setQuery={setQuery} activeTool={activeTool} result={result} loading={loading} error={error} submitSearch={submitSearch} startSearch={startSearch} setModal={setModal} imageInput={imageInput} formInput={formInput} pickImage={pickImage} imageName={imageName} imageData={imageData} integrations={integrations} />}
          {page === "Investigations" && <InvestigationsPage dashboard={dashboard} selectedCase={selectedCase} setSelectedCase={setSelectedCase} setModal={setModal} deleteCase={deleteCase} exportReport={exportReport} />}
          {page === "Activity" && <ActivityPage dashboard={dashboard} chartData={chartData} onSearch={startSearch} />}
          <footer className="page-footer"><span><Shield size={13} /> Sentinel OSINT · public-source research workspace</span><span>Research responsibly. Verify every source.</span></footer>
        </div>
      </main>

      {modal && <Modal type={modal} dashboard={dashboard} selectedCase={selectedCase} setSelectedCase={setSelectedCase} onClose={() => setModal(null)} onSubmit={modal === "case" ? createCase : saveFinding} result={result} />}
      {toast && <div className="toast"><Check size={15} />{toast}</div>}
    </div>
  );
}

function PageHeading({ eyebrow, title, description, children }: { eyebrow: string; title: string; description: string; children?: ReactNode }) {
  return <div className="page-heading"><div><div className="eyebrow"><span />{eyebrow}</div><h1>{title}</h1><p>{description}</p></div>{children && <div className="heading-actions">{children}</div>}</div>;
}

function DashboardPage({ dashboard, chartData, onNavigate, onSearch }: { dashboard: Dashboard; chartData: typeof demoActivity; onNavigate: (page: string) => void; onSearch: (query: string, type?: ToolKey) => void }) {
  const demo = !dashboard.searches.length;
  const domains = dashboard.searches.filter((search) => search.type === "domain").slice(0, 3);
  const domainRows = domains.length
    ? domains.map((item) => ({ domain: item.query, date: formatTime(item.searchedAt), status: "LIVE" }))
    : dashboard.searches.length ? [] : demoDomains;
  return (
    <>
      <PageHeading eyebrow={todayLabel} title="Intelligence overview" description="Your research workspace, at a glance. Pick up where your investigation left off."><button className="button button-outline" onClick={() => onNavigate("Activity")}><Clock3 size={15} /> Activity log</button><button className="button button-primary" onClick={() => onNavigate("Tools")}><Plus size={16} /> New lookup</button></PageHeading>
      <div className="demo-banner"><span className="demo-dot" /><span><b>DEMO WORKSPACE</b> — illustrative sample metrics. No intelligence is presented as verified. Start a lookup to collect live public-source results.</span><ArrowRight size={15} /></div>
      <section className="metric-grid">
        <MetricCard title="Investigations" value={String(dashboard.stats.investigations || 12)} trend={dashboard.stats.investigations ? "YOUR CASES" : "+ 2 this week"} icon={<BriefcaseBusiness size={17} />} accent="green" onClick={() => onNavigate("Investigations")} demo={!dashboard.stats.investigations} />
        <MetricCard title="Recent searches" value={String(dashboard.stats.searches || 48)} trend={dashboard.stats.searches ? "YOUR SEARCHES" : "Across 7 days"} icon={<SearchCheck size={17} />} accent="cyan" onClick={() => onNavigate("Activity")} demo={demo} />
        <MetricCard title="Saved findings" value={String(dashboard.stats.findings || 23)} trend={dashboard.stats.findings ? "YOUR FINDINGS" : "Across 4 cases"} icon={<Bookmark size={17} />} accent="purple" onClick={() => onNavigate("Investigations")} demo={!dashboard.stats.findings} />
        <MetricCard title="Sources checked" value={dashboard.searches.length ? String(new Set(dashboard.searches.map((item) => item.type)).size) : "07"} trend="Public sources" icon={<Database size={17} />} accent="orange" onClick={() => onNavigate("Tools")} demo={demo} />
      </section>
      <section className="dashboard-grid">
        <article className="panel activity-panel">
          <div className="panel-heading"><div><h2>Research activity</h2><p>Searches over the last 7 days</p></div><div className="panel-heading-side"><span className="chart-legend"><i /> Searches</span><button className="icon-btn" title="Open activity log" onClick={() => onNavigate("Activity")}><ArrowRight size={16} /></button></div></div>
          <div className="chart-wrap"><ResponsiveContainer width="100%" height="100%"><AreaChart data={chartData} margin={{ top: 12, right: 6, bottom: 0, left: -20 }}>
            <defs><linearGradient id="activityGradient" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#38e6b0" stopOpacity={0.22} /><stop offset="100%" stopColor="#38e6b0" stopOpacity={0} /></linearGradient></defs>
            <CartesianGrid stroke="#1b272d" vertical={false} />
            <XAxis dataKey="day" axisLine={false} tickLine={false} tick={{ fill: "#64727a", fontSize: 10, fontFamily: "DM Mono" }} dy={10} />
            <YAxis axisLine={false} tickLine={false} tick={{ fill: "#64727a", fontSize: 10, fontFamily: "DM Mono" }} />
            <Tooltip contentStyle={{ background: "#111a20", border: "1px solid #29363c", borderRadius: 8, color: "#eaf3ef", fontSize: 12 }} />
            <Area type="monotone" dataKey="searches" stroke="#38e6b0" strokeWidth={2} fill="url(#activityGradient)" activeDot={{ r: 4, fill: "#38e6b0", stroke: "#10191e", strokeWidth: 3 }} />
          </AreaChart></ResponsiveContainer></div>
          <div className="chart-caption"><span><i className="chart-live-dot" />{demo ? "SAMPLE ACTIVITY · DEMO DATA" : "LIVE · YOUR SEARCH HISTORY"}</span><span>LAST 7 DAYS</span></div>
        </article>
        <article className="panel domains-panel">
          <div className="panel-heading"><div><h2>Recently analyzed</h2><p>Your domain lookups</p></div><button className="text-button" onClick={() => onNavigate("Activity")}>View all <ArrowRight size={13} /></button></div>
          <div className="domain-list">
            {domainRows.map((item) => (
              <button key={item.domain} className="domain-row" onClick={() => onSearch(item.domain, "domain")}><span className="domain-orb"><Globe2 size={15} /></span><span className="domain-copy"><b>{item.domain}</b><small>{item.date}</small></span><span className={`mini-status ${item.status === "DEMO" ? "status-demo" : ""}`}>{item.status}</span><ChevronRight size={14} className="row-chevron" /></button>
            ))}
            {!domainRows.length && <div className="empty-inline">No domain lookups have been recorded yet.</div>}
          </div>
          <button className="add-domain" onClick={() => onSearch("", "domain")}><Plus size={15} /> Start a domain lookup</button>
        </article>
      </section>
      <section className="lower-grid">
        <article className="panel quick-panel"><div className="panel-heading"><div><h2>Quick access</h2><p>Choose an intelligence module to get started</p></div><Sparkles size={17} className="muted-icon" /></div><div className="quick-tools">
          {tools.map(({ id, label, description, icon: Icon, color }) => <button key={id} className="quick-tool" onClick={() => onSearch("", id)}><span className={`tool-icon ${color}`}><Icon size={17} /></span><span className="quick-tool-copy"><b>{label}</b><small>{description}</small></span><ArrowUpRight size={15} className="quick-arrow" /></button>)}
        </div></article>
        <article className="panel timeline-panel"><div className="panel-heading"><div><h2>Recent activity</h2><p>Latest workspace updates</p></div><button className="text-button" onClick={() => onNavigate("Activity")}>Full timeline <ArrowRight size={13} /></button></div>
          <div className="timeline">
            {dashboard.searches.slice(0, 4).map((item, index) => <div key={`${item.query}-${item.searchedAt}`} className="timeline-item"><span className={`timeline-marker ${index === 0 ? "active" : ""}`} /><div><b>Looked up <button className="inline-link" onClick={() => onSearch(item.query, item.type as ToolKey)}>{item.query}</button></b><small>{formatTime(item.searchedAt)} · {item.type}</small></div></div>)}
            {dashboard.searches.length === 0 && dashboard.cases.length === 0 && dashboard.findings.length === 0 && [
              ["Domain scan completed", "northstar-labs.io · 2 min ago"], ["New finding added", "Meridian infrastructure · 18 min ago"], ["Investigation created", "Project Northstar · 1 hr ago"],
            ].map(([title, detail], index) => <div key={title} className="timeline-item"><span className={`timeline-marker ${index === 0 ? "active" : ""}`} /><div><b>{title}</b><small>{detail} <em className="sample-inline">· DEMO</em></small></div></div>)}
            {dashboard.searches.length === 0 && (dashboard.cases.length > 0 || dashboard.findings.length > 0) && <div className="empty-inline">No lookup activity recorded yet.</div>}
          </div>
          <div className="integrity-note"><LockKeyhole size={15} /><span><b>Ethical research only</b><small>Publicly accessible sources. No private accounts or access bypasses.</small></span></div>
        </article>
      </section>
    </>
  );
}

function MetricCard({ title, value, trend, icon, accent, onClick, demo }: { title: string; value: string; trend: string; icon: ReactNode; accent: string; onClick: () => void; demo: boolean }) {
  return <button className={`metric-card ${accent}`} onClick={onClick}><div className="metric-top"><span>{title}</span><span className="metric-icon">{icon}</span></div><div className="metric-value">{value}{demo && <span className="metric-demo">SAMPLE</span>}</div><div className="metric-bottom">{demo ? <span className="metric-trend"><ArrowUpRight size={12} />{trend}</span> : <span className="metric-trend"><ArrowDownRight size={12} />{trend}</span>}<span className="metric-link">Explore <ArrowRight size={12} /></span></div></button>;
}

function ToolsPage({ tool, query, setQuery, activeTool, result, loading, error, submitSearch, startSearch, setModal, imageInput, formInput, pickImage, imageName, imageData, integrations }: {
  tool: ToolKey; query: string; setQuery: (value: string) => void; activeTool: (typeof tools)[number];
  result: LookupResponse | null; loading: boolean; error: string; submitSearch: (event?: FormEvent) => void;
  startSearch: (query: string, type?: ToolKey) => void; setModal: (modal: "case" | "finding" | null) => void;
  imageInput: RefObject<HTMLInputElement | null>; formInput: RefObject<HTMLInputElement | null>;
  pickImage: (file?: File) => void; imageName: string; imageData: RecordMap | null;
  integrations: Integrations | null;
}) {
  const Icon = activeTool.icon;
  const resultObject = result?.result || {};
  const usernameResults = result?.type === "username" ? resultObject.profiles as { platform: string; url: string; status: string }[] : [];
  const topFields: [string, unknown][] = tool === "domain"
    ? [["Domain", resultObject.domain], ["Registrar", (resultObject.registration as RecordMap | undefined)?.registrar], ["Registered", (resultObject.registration as RecordMap | undefined)?.created], ["Expires", (resultObject.registration as RecordMap | undefined)?.expires]]
    : tool === "ip"
      ? [["IP address", resultObject.ip], ["Approx. location", resultObject.location], ["ISP", resultObject.isp], ["ASN", resultObject.asn]]
      : tool === "website"
        ? [["Website", resultObject.url], ["HTTP status", resultObject.status], ["Title", resultObject.title], ["SSL", resultObject.ssl]]
        : tool === "email"
          ? [["Email syntax", resultObject.syntaxValid ? "Valid" : "Invalid"], ["Domain", resultObject.domain], ["MX records", (resultObject.mxRecords as unknown[])?.length], ["Breach check", ((resultObject.breaches as RecordMap | undefined)?.status) || "Not checked"]]
          : tool === "image"
            ? [["File", resultObject.name], ["Dimensions", `${resultObject.width || "—"} × ${resultObject.height || "—"}`], ["Size", resultObject.size], ["EXIF fields", Object.keys((resultObject.exif as RecordMap) || {}).length]]
            : [["Username", result?.query], ["Profile links", usernameResults.length], ["Verified profiles", 0], ["Collection", "Public links only"]];
  const dns = resultObject.dns as RecordMap | undefined;
  const registration = resultObject.registration as RecordMap | undefined;
  const flowNodes: Node[] = [
    { id: "domain", position: { x: 260, y: 30 }, data: { label: String(resultObject.domain || resultObject.ip || result?.query || "Target") }, type: "input" },
    { id: "a-record", position: { x: 70, y: 150 }, data: { label: "A · " + display(dns?.A || resultObject.location) } },
    { id: "ns-record", position: { x: 260, y: 150 }, data: { label: "NS · " + display(dns?.NS || resultObject.asn) } },
    { id: "mx-record", position: { x: 450, y: 150 }, data: { label: "MX · " + display(dns?.MX || "Email records") } },
  ];
  const flowEdges: Edge[] = ["a-record", "ns-record", "mx-record"].map((id) => ({ id: `e-${id}`, source: "domain", target: id, animated: true, style: { stroke: "#38e6b0", strokeWidth: 1.4 } }));

  return (
    <>
      <PageHeading eyebrow="RESEARCH MODULES" title="Intelligence tools" description="Run focused, non-intrusive lookups against publicly available data sources." />
      <div className="tool-layout">
        <aside className="tool-selector panel"><div className="tool-selector-heading">MODULES <span>06</span></div>{tools.map(({ id, label, icon: ToolIcon, color }) => <button key={id} className={`tool-selector-row ${tool === id ? "active" : ""}`} onClick={() => startSearch("", id)}><span className={`tool-selector-icon ${color}`}><ToolIcon size={16} /></span><span>{label}</span>{tool === id && <ChevronRight size={14} />}</button>)}<div className="source-note"><ShieldCheck size={16} /><span>Lookup sources are public and read-only.</span></div></aside>
        <div className="tool-main">
          <section className="tool-intro panel"><div className={`tool-intro-icon ${activeTool.color}`}><Icon size={21} /></div><div className="tool-intro-copy"><div><h2>{activeTool.label}</h2><span className="public-label"><i /> PUBLIC SOURCES</span></div><p>{activeTool.description}. Results show their source and collection time.</p></div></section>
          <form className="lookup-form panel" onSubmit={(event) => submitSearch(event)}>
            <label htmlFor="lookup-value">Search target</label>
            {tool === "image" ? <button className="file-picker" type="button" onClick={() => imageInput.current?.click()}><Upload size={17} /><span>{imageName || "Select an image from your device"}</span><small>Browse</small></button> : <div className="lookup-input-wrap"><Icon size={17} /><input ref={formInput} id="lookup-value" value={query} onChange={(event) => setQuery(event.target.value)} placeholder={activeTool.placeholder} autoComplete="off" /><kbd>Enter ↵</kbd></div>}
            <input ref={imageInput} type="file" accept="image/*" className="visually-hidden" onChange={(event) => pickImage(event.target.files?.[0])} />
            {tool === "image" && imageData && <div className="file-detail"><Check size={13} /> Image selected · {String(imageData.width)} × {String(imageData.height)} px · metadata stays in your browser</div>}
            <div className="lookup-form-bottom"><span><LockKeyhole size={13} />{tool === "image" ? "Your image is processed locally and never uploaded." : "Queries use public sources. No authentication bypasses."}</span><button className="button button-primary" type="submit" disabled={loading || (tool === "image" && !imageData)}>{loading ? <><LoaderCircle size={15} className="spin" /> Analyzing</> : <><Search size={15} /> Run lookup</>}</button></div>
            {error && <div className="inline-error"><CircleAlert size={15} />{error}</div>}
          </form>

          {!result && !loading && <section className="tool-empty panel"><div className="empty-visual"><span /><span /><span /><Icon size={24} /></div><h3>Ready when you are</h3><p>Enter a target above to collect its public information.<br />No demo results are shown in lookup modules.</p><div className="empty-sources"><span><i /> RDAP</span><span><i /> DNS-over-HTTPS</span><span><i /> crt.sh</span></div></section>}
          {loading && <section className="tool-loading panel"><div className="loader-ring"><LoaderCircle size={30} className="spin" /></div><b>Collecting public-source data</b><span>Connecting to configured providers · this may take a few seconds</span><div className="loading-track"><i /></div></section>}
          {result && <>
            <div className="result-heading"><div><div className="result-eyebrow"><span /> LOOKUP COMPLETE</div><h2>{result.query}</h2><p>Collected {formatTime(result.collectedAt)} · {result.type} intelligence</p></div><div className="result-actions"><button className="button button-outline" onClick={() => setModal("finding")}><Bookmark size={14} /> Save finding</button><button className="icon-btn" title="Copy result JSON" onClick={() => { void navigator.clipboard.writeText(JSON.stringify(result, null, 2)); }}><Copy size={15} /></button></div></div>
            <div className="result-summary-grid">{topFields.map(([label, value]) => <div key={label} className="result-summary"><span>{label}</span><b>{display(value)}</b></div>)}</div>
            {result.type === "username" && <section className="panel results-card"><div className="panel-heading"><div><h2>Public profile links</h2><p>These are unverified link patterns. The sites have not been queried.</p></div><span className="unverified-pill">UNVERIFIED</span></div><div className="profile-grid">{usernameResults.map((item) => <a href={item.url} key={item.platform} target="_blank" rel="noreferrer" className="profile-link"><span className="profile-platform">{item.platform.slice(0, 1)}</span><b>{item.platform}</b><span>Unverified</span><ExternalLink size={14} /></a>)}</div><div className="note-banner"><Info size={15} />A link does not confirm an account exists. Respect each platform's access rules and privacy settings.</div></section>}
            {result.type === "image" && <>
              <section className="panel results-card"><div className="panel-heading"><div><h2>Image metadata</h2><p>Read from the selected local file only.</p></div><span className="live-pill">LOCAL FILE</span></div><DataRows data={{ ...resultObject, exif: resultObject.exif }} exclude={["sources"]} /></section>
              <section className="panel results-card"><div className="panel-heading"><div><h2>Reverse image search</h2><p>Open a provider to upload an image directly to their service.</p></div></div><div className="reverse-links">{[["Google Lens", "https://lens.google.com/"], ["Bing Visual Search", "https://www.bing.com/visualsearch"], ["TinEye", "https://tineye.com/"]].map(([label, href]) => <a key={label} className="button button-outline" href={href} target="_blank" rel="noreferrer"><ExternalLink size={14} /> {label}</a>)}</div><div className="note-banner"><Info size={14} />No image is uploaded by Sentinel. Review each external provider's privacy policy before sharing.</div></section>
            </>}
            {result.type === "domain" && <>
              <section className="panel results-card"><div className="panel-heading"><div><h2>Registration & DNS</h2><p>Public registration details and DNS records</p></div><span className="live-pill">VERIFIED SOURCE</span></div><DataRows data={{ registration, dns, sslCertificate: resultObject.sslCertificate, certificateTransparencyStatus: resultObject.certificateTransparencyStatus, reputation: resultObject.reputation }} exclude={["status"]} /><div className="dns-chips">{Object.entries(dns || {}).map(([recordType, value]) => <span key={recordType}><b>{recordType}</b> {Array.isArray(value) ? value.length : 0} records</span>)}</div></section>
              <section className="panel graph-panel"><div className="panel-heading"><div><h2>Relationship map</h2><p>DNS records associated with this domain</p></div><span className="live-pill">FROM LOOKUP</span></div><div className="flow-area"><ReactFlow nodes={flowNodes} edges={flowEdges} fitView fitViewOptions={{ padding: 0.3 }} nodesDraggable={false} nodesConnectable={false} elementsSelectable={false}><Background color="#28363a" gap={20} size={1} /><MiniMap nodeColor="#183a32" maskColor="rgba(8,13,18,0.65)" /><Controls /></ReactFlow></div></section>
              <section className="panel results-card"><div className="panel-heading"><div><h2>Certificate transparency</h2><p>Publicly logged certificates · crt.sh</p></div></div><CertificateList certificates={resultObject.certificates} status={String(resultObject.certificateTransparencyStatus)} /></section>
            </>}
            {(result.type === "ip" || result.type === "website" || result.type === "email") && <section className="panel results-card"><div className="panel-heading"><div><h2>{result.type === "ip" ? "Network & location details" : result.type === "website" ? "Website metadata" : "Mail domain & breach records"}</h2><p>Returned data from configured public sources</p></div><span className="live-pill">LIVE RESULTS</span></div><DataRows data={resultObject} exclude={["sources", "certificates", "robots", "sitemap"]} /><WebsiteFiles type={result.type} data={resultObject} /></section>}
            {result.type === "ip" && Array.isArray(resultObject.coordinates) && <section className="panel geo-card"><div className="geo-map"><span className="geo-grid" /><span className="geo-pulse" /><span className="geo-pin"><Target size={17} /></span><span className="geo-caption">APPROXIMATE LOCATION · NOT PRECISE</span></div><div className="geo-detail"><div><span>ESTIMATED REGION</span><b>{display(resultObject.location)}</b><small>{display(resultObject.coordinates)} · Public IP geolocation is approximate</small></div><a className="button button-outline" href={`https://www.openstreetmap.org/?mlat=${encodeURIComponent(String((resultObject.coordinates as number[])[0]))}&mlon=${encodeURIComponent(String((resultObject.coordinates as number[])[1]))}#map=8/${encodeURIComponent(String((resultObject.coordinates as number[])[0]))}/${encodeURIComponent(String((resultObject.coordinates as number[])[1]))}`} target="_blank" rel="noreferrer"><ExternalLink size={13} /> Open map</a></div></section>}
            {Array.isArray(resultObject.sources) && <div className="sources-line"><span>SOURCES</span>{(resultObject.sources as string[]).map((source) => <span key={source}><Check size={11} /> {source}</span>)}</div>}
            <div className="result-disclaimer"><Info size={14} />Information reflects public sources at the collection time shown. Validate critical findings independently.</div>
          </>}
          {!result && <div className="suggested-targets"><span>Try a public target</span>{["example.com", "8.8.8.8"].map((target) => <button key={target} onClick={() => startSearch(target, guessType(target))}>{target} <ArrowUpRight size={12} /></button>)}</div>}
          <ProviderStatus integrations={integrations} />
        </div>
      </div>
    </>
  );
}

function ProviderStatus({ integrations }: { integrations: Integrations | null }) {
  const providers: [string, keyof Integrations][] = [
    ["RDAP", "rdap"], ["DNS-over-HTTPS", "dnsOverHttps"], ["crt.sh", "crtSh"],
    ["VirusTotal", "virusTotal"], ["AbuseIPDB", "abuseIpDb"], ["Shodan", "shodan"], ["HIBP", "hibp"],
  ];
  return <section className="provider-status panel"><div><h3>Data providers</h3><p>Optional API keys are read from server environment variables only.</p></div><div className="provider-list">{providers.map(([name, key]) => {
    const ready = integrations?.[key] ?? false;
    const configured = ["rdap", "dnsOverHttps", "crtSh"].includes(key);
    return <span key={key} className={ready ? "provider-ready" : "provider-optional"}><i />{name}<small>{ready ? configured ? "PUBLIC" : "CONFIGURED" : "NOT CONFIGURED"}</small></span>;
  })}</div></section>;
}

function DataRows({ data, exclude = [] }: { data: RecordMap; exclude?: string[] }) {
  const rows = Object.entries(data).filter(([key, value]) => !exclude.includes(key) && value !== undefined && value !== null && value !== "");
  return <div className="data-rows">{rows.map(([key, value]) => <div className="data-row" key={key}><span>{key.replace(/([A-Z])/g, " $1").replace(/^./, (letter) => letter.toUpperCase())}</span><b>{typeof value === "object" ? <pre>{JSON.stringify(value, null, 2)}</pre> : display(value)}</b></div>)}</div>;
}

function CertificateList({ certificates, status }: { certificates: unknown; status: string }) {
  const list = Array.isArray(certificates) ? certificates as RecordMap[] : [];
  if (!list.length) return <div className="empty-inline">{status === "unavailable" ? "crt.sh could not be reached. Certificate results are unavailable, not empty." : "No public certificates were returned for this query."}</div>;
  return <div className="certificate-list">{list.slice(0, 8).map((item, index) => <div key={`${String(item.commonName)}-${index}`} className="certificate-row"><span className="cert-icon"><LockKeyhole size={15} /></span><span><b>{display(item.commonName || item.name)}</b><small>Issuer: {display(item.issuer)} · Valid from {display(item.notBefore)} to {display(item.notAfter)}</small></span><ShieldCheck size={15} className="cert-check" /></div>)}</div>;
}

function WebsiteFiles({ type, data }: { type: string; data: RecordMap }) {
  const [open, setOpen] = useState("");
  if (type !== "website") return null;
  return <div className="website-inspect">
    {(["headers", "robots", "sitemap"] as const).map((key) => <div key={key} className="inspect-section"><button onClick={() => setOpen(open === key ? "" : key)}><span>{key === "headers" ? "HTTP response headers" : key === "robots" ? "robots.txt" : "sitemap.xml"}</span><span>{data[key] ? key === "headers" ? `${Object.keys(data[key] as object).length} headers` : "available" : "not returned"}</span><ChevronDown size={15} className={open === key ? "rotate" : ""} /></button>{open === key && <pre>{typeof data[key] === "object" ? JSON.stringify(data[key], null, 2) : display(data[key])}</pre>}</div>)}
  </div>;
}

function InvestigationsPage({ dashboard, selectedCase, setSelectedCase, setModal, deleteCase, exportReport }: { dashboard: Dashboard; selectedCase: string; setSelectedCase: (id: string) => void; setModal: (modal: "case" | "finding" | null) => void; deleteCase: (item: Investigation) => void; exportReport: () => void }) {
  const selected = dashboard.cases.find((item) => item.id === selectedCase);
  const findings = dashboard.findings.filter((item) => item.caseId === selectedCase);
  return <>
    <PageHeading eyebrow="CASE MANAGEMENT" title="Investigations" description="Organize research into cases, capture sourced findings, and export reports."><button className="button button-outline" onClick={exportReport}><Download size={15} /> Export report</button><button className="button button-primary" onClick={() => setModal("case")}><Plus size={16} /> New investigation</button></PageHeading>
    {!dashboard.cases.length ? <section className="panel case-empty"><div className="empty-visual"><BriefcaseBusiness size={25} /></div><h3>Your investigation workspace</h3><p>Create a case to organize findings, add source links, record collection times, and export a printable report.</p><button className="button button-primary" onClick={() => setModal("case")}><Plus size={15} /> Create first investigation</button><span>Cases and findings are stored in your local SQLite database.</span></section> : <div className="investigations-layout">
      <aside className="panel case-list"><div className="case-list-heading"><span>YOUR CASES</span><button className="icon-btn" title="Create investigation" onClick={() => setModal("case")}><Plus size={16} /></button></div>
        {dashboard.cases.map((item) => <button className={`case-list-item ${item.id === selectedCase ? "active" : ""}`} key={item.id} onClick={() => setSelectedCase(item.id)}><span className="case-color"><Target size={15} /></span><span><b>{item.title}</b><small>Updated {formatTime(item.updatedAt)}</small></span><ChevronRight size={14} /></button>)}
      </aside>
      {selected ? <section className="case-detail panel"><div className="case-detail-heading"><div><div className="eyebrow"><span /> INVESTIGATION CASE</div><h2>{selected.title}</h2><p>{selected.description || "No case description provided."}</p></div><button className="icon-btn danger-icon" title="Delete case" onClick={() => deleteCase(selected)}><Trash2 size={16} /></button></div>
        <div className="case-meta"><span><Clock3 size={13} /> Created {formatTime(selected.createdAt)}</span><span><FileSearch size={13} /> {findings.length} findings</span>{selected.tags.map((tag) => <span className="tag" key={tag}>#{tag}</span>)}</div>
        <div className="case-section-heading"><div><h3>Findings timeline</h3><p>Sources and collection timestamps are retained with every finding.</p></div><button className="button button-primary" onClick={() => setModal("finding")}><Plus size={14} /> Add finding</button></div>
        {findings.length ? <div className="finding-timeline">{findings.map((item) => <article key={item.id} className="finding-card"><span className="finding-marker"><Fingerprint size={14} /></span><div className="finding-content"><div className="finding-title"><h4>{item.title}</h4><time>{formatTime(item.collectedAt)}</time></div><p>{item.content || "No notes added."}</p>{item.sourceUrl && <a href={item.sourceUrl} target="_blank" rel="noreferrer"><ExternalLink size={12} /> {item.sourceUrl}</a>}{item.tags.map((tag) => <span className="tag" key={tag}>#{tag}</span>)}</div></article>)}</div> : <div className="empty-inline">No findings yet. Add your first sourced observation to this case.</div>}
        <div className="case-report-footer"><ShieldCheck size={14} /> Report exports use the browser's print-to-PDF workflow.</div>
      </section> : <section className="panel case-empty"><h3>Select an investigation</h3><p>Choose a case from the list to view its findings and timeline.</p></section>}
    </div>}
  </>;
}

function ActivityPage({ dashboard, chartData, onSearch }: { dashboard: Dashboard; chartData: typeof demoActivity; onSearch: (query: string, type?: ToolKey) => void }) {
  return <>
    <PageHeading eyebrow="WORKSPACE HISTORY" title="Activity log" description="A transparent record of your public-source lookups and collection times." />
    <section className="panel activity-full"><div className="panel-heading"><div><h2>Lookup history</h2><p>{dashboard.searches.length ? `${dashboard.searches.length} recorded lookups` : "Your real lookups will appear here after the first search."}</p></div><span className={`live-pill ${dashboard.searches.length ? "" : "demo-live"}`}>{dashboard.searches.length ? "YOUR DATA" : "NO LIVE DATA YET"}</span></div><div className="activity-chart-small"><ResponsiveContainer width="100%" height="100%"><AreaChart data={chartData}><defs><linearGradient id="activityGradient2" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#38e6b0" stopOpacity={0.16} /><stop offset="100%" stopColor="#38e6b0" stopOpacity={0} /></linearGradient></defs><CartesianGrid stroke="#1b272d" vertical={false} /><XAxis dataKey="day" axisLine={false} tickLine={false} tick={{ fill: "#64727a", fontSize: 10 }} /><YAxis axisLine={false} tickLine={false} tick={{ fill: "#64727a", fontSize: 10 }} /><Tooltip contentStyle={{ background: "#111a20", border: "1px solid #29363c", borderRadius: 8, color: "#eaf3ef", fontSize: 12 }} /><Area type="monotone" dataKey="searches" stroke="#38e6b0" fill="url(#activityGradient2)" /></AreaChart></ResponsiveContainer></div>
      {dashboard.searches.length ? <div className="history-table"><div className="history-head"><span>QUERY</span><span>TYPE</span><span>COLLECTED</span><span>RESULT</span></div>{dashboard.searches.map((item) => <button key={`${item.query}-${item.searchedAt}`} className="history-row" onClick={() => onSearch(item.query, item.type as ToolKey)}><b><Search size={14} />{item.query}</b><span className="history-type">{item.type}</span><span>{formatTime(item.searchedAt)}</span><span className="source-ok"><Check size={12} /> public sources <ArrowUpRight size={12} /></span></button>)}</div> : <div className="activity-empty"><History size={18} /><span>No live lookups have been recorded in this workspace.</span></div>}
    </section>
  </>;
}

function Modal({ type, dashboard, selectedCase, setSelectedCase, onClose, onSubmit, result }: { type: "case" | "finding"; dashboard: Dashboard; selectedCase: string; setSelectedCase: (id: string) => void; onClose: () => void; onSubmit: (event: FormEvent<HTMLFormElement>) => void; result: LookupResponse | null }) {
  const [caseChoice, setCaseChoice] = useState(selectedCase);
  return <div className="modal-backdrop" onMouseDown={(event) => { if (event.target === event.currentTarget) onClose(); }}><section className="modal panel"><div className="modal-heading"><div><div className="eyebrow"><span />{type === "case" ? "CASE MANAGEMENT" : "EVIDENCE CAPTURE"}</div><h2>{type === "case" ? "New investigation" : "Save finding"}</h2></div><button className="icon-btn" onClick={onClose}><X size={18} /></button></div>
    <form onSubmit={onSubmit} className="modal-form">
      {type === "case" ? <>
        <label>Investigation name<input name="title" placeholder="e.g. Project Northstar" required maxLength={120} /></label>
        <label>Brief description<textarea name="description" placeholder="What are you researching?" rows={3} /></label>
        <label>Tags <span className="label-optional">OPTIONAL · COMMA SEPARATED</span><input name="tags" placeholder="infrastructure, due diligence" /></label>
      </> : <>
        {dashboard.cases.length ? <label>Investigation case<select name="caseId" value={caseChoice} required onChange={(event) => { setCaseChoice(event.target.value); setSelectedCase(event.target.value); }}>{dashboard.cases.map((item) => <option value={item.id} key={item.id}>{item.title}</option>)}</select></label> : <div className="inline-error"><CircleAlert size={15} />Create an investigation before saving a finding.</div>}
        <label>Finding title<input name="title" placeholder="Short, descriptive observation" required maxLength={160} /></label>
        <label>Notes<textarea name="content" rows={4} placeholder="Summarize what you observed. Separate fact from inference." /></label>
        <label>Source URL<input name="sourceUrl" type="url" placeholder={result?.query ? `https://${result.query}` : "https://source.example"} defaultValue={result?.type === "website" ? String(result.result.url || "") : result?.type === "domain" ? `https://${result.query}` : ""} /></label>
        <label>Tags <span className="label-optional">OPTIONAL · COMMA SEPARATED</span><input name="tags" placeholder="confirmed, infrastructure" /></label>
        <div className="collection-note"><Clock3 size={14} />Collection timestamp will be recorded automatically.</div>
      </>}
      <div className="modal-actions"><button type="button" className="button button-outline" onClick={onClose}>Cancel</button><button type="submit" className="button button-primary"><Check size={15} />{type === "case" ? "Create investigation" : "Save finding"}</button></div>
    </form>
  </section></div>;
}

export default App;
