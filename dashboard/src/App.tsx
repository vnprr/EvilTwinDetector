import {
  Activity,
  AlertTriangle,
  Database,
  Info,
  LayoutDashboard,
  Radio,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  Signal,
  Wifi,
} from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { ReactNode } from "react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { api, apiBase, liveWebSocketUrl } from "./api";
import type {
  APDetail,
  APListItem,
  Classification,
  CorrelatedAlert,
  HealthPayload,
  RuntimeStats,
  TimelineEvent,
} from "./types";

type View = "overview" | "alerts" | "ap-detail" | "activity";

const statusRank: Record<Classification, number> = {
  clean: 0,
  info: 1,
  suspicious: 2,
  evil_twin: 3,
};

const statusCopy: Record<Classification, string> = {
  clean: "Clean",
  info: "Info",
  suspicious: "Suspicious",
  evil_twin: "Evil Twin",
};

export function App() {
  const [view, setView] = useState<View>("overview");
  const [health, setHealth] = useState<HealthPayload | null>(null);
  const [stats, setStats] = useState<(RuntimeStats & { state_path: string }) | null>(null);
  const [aps, setAps] = useState<APListItem[]>([]);
  const [alerts, setAlerts] = useState<CorrelatedAlert[]>([]);
  const [timeline, setTimeline] = useState<TimelineEvent[]>([]);
  const [selectedBssid, setSelectedBssid] = useState<string | null>(null);
  const [selectedAlertKey, setSelectedAlertKey] = useState<string | null>(null);
  const [apDetail, setApDetail] = useState<APDetail | null>(null);
  const [alertDetail, setAlertDetail] = useState<CorrelatedAlert | null>(null);
  const [alertTimeline, setAlertTimeline] = useState<TimelineEvent[]>([]);
  const [classificationFilter, setClassificationFilter] = useState("");
  const [statusFilter, setStatusFilter] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [liveState, setLiveState] = useState<"connecting" | "live" | "fallback">("connecting");
  const timelineRef = useRef<TimelineEvent[]>([]);

  const loadDashboard = useCallback(async () => {
    const query = new URLSearchParams();
    if (classificationFilter) query.set("classification", classificationFilter);
    if (statusFilter) query.set("status", statusFilter);
    const alertQuery = query.toString() ? `?${query.toString()}` : "";
    try {
      const [nextHealth, nextStats, nextAps, nextAlerts, nextTimeline] = await Promise.all([
        api.health(),
        api.stats(),
        api.aps(),
        api.alerts(alertQuery),
        api.timeline(),
      ]);
      setHealth(nextHealth);
      setStats(nextStats);
      setAps(nextAps);
      setAlerts(nextAlerts);
      setTimeline(limitTimeline(nextTimeline));
      setError(null);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
    } finally {
      setLoading(false);
    }
  }, [classificationFilter, statusFilter]);

  useEffect(() => {
    void loadDashboard();
    const interval = window.setInterval(() => void loadDashboard(), 10_000);
    return () => window.clearInterval(interval);
  }, [loadDashboard]);

  useEffect(() => {
    let active = true;
    async function loadDetail() {
      if (!selectedBssid) {
        setApDetail(null);
        return;
      }
      try {
        const detail = await api.apDetail(selectedBssid);
        if (active) setApDetail(detail);
      } catch (cause) {
        if (active) setError(cause instanceof Error ? cause.message : String(cause));
      }
    }
    void loadDetail();
    return () => {
      active = false;
    };
  }, [selectedBssid]);

  useEffect(() => {
    let active = true;
    async function loadAlertDetail() {
      if (!selectedAlertKey) {
        setAlertDetail(null);
        setAlertTimeline([]);
        return;
      }
      try {
        const detail = await api.alertDetail(selectedAlertKey);
        if (active) {
          setAlertDetail(detail.alert);
          setAlertTimeline(detail.timeline);
        }
      } catch (cause) {
        if (active) setError(cause instanceof Error ? cause.message : String(cause));
      }
    }
    void loadAlertDetail();
    return () => {
      active = false;
    };
  }, [selectedAlertKey]);

  useEffect(() => {
    timelineRef.current = timeline;
  }, [timeline]);

  useEffect(() => {
    let cancelled = false;
    let fallbackTimer: number | undefined;
    const socket = new WebSocket(liveWebSocketUrl(lastTimelineId(timelineRef.current)));
    socket.onopen = () => {
      if (!cancelled) setLiveState("live");
    };
    socket.onmessage = (event) => {
      const payload = JSON.parse(event.data) as { items?: TimelineEvent[] };
      if (payload.items?.length) {
        setTimeline((current) => limitTimeline(mergeTimeline(current, payload.items ?? [])));
      }
    };
    socket.onerror = () => {
      if (!cancelled) setLiveState("fallback");
    };
    socket.onclose = () => {
      if (!cancelled) setLiveState((state) => (state === "live" ? "fallback" : state));
    };
    fallbackTimer = window.setInterval(async () => {
      if (socket.readyState === WebSocket.OPEN) return;
      try {
        const items = await api.timeline(lastTimelineId(timelineRef.current));
        setTimeline((current) => limitTimeline(mergeTimeline(current, items)));
        setLiveState("fallback");
      } catch {
        setLiveState("fallback");
      }
    }, 5_000);
    return () => {
      cancelled = true;
      socket.close();
      if (fallbackTimer) window.clearInterval(fallbackTimer);
    };
  }, []);

  const selectedAp = useMemo(
    () => aps.find((ap) => ap.bssid === selectedBssid) ?? null,
    [aps, selectedBssid],
  );

  const topStatus = useMemo(() => {
    return aps.reduce<Classification>(
      (current, ap) => (statusRank[ap.status] > statusRank[current] ? ap.status : current),
      "clean",
    );
  }, [aps]);

  const chartData = useMemo(() => {
    const counts = stats?.classification_counts ?? {};
    return ["info", "suspicious", "evil_twin"].map((name) => ({
      name: statusCopy[name as Classification],
      count: counts[name] ?? 0,
    }));
  }, [stats]);

  return (
    <main className="app-shell">
      <aside className="sidebar" aria-label="WiGuard navigation">
        <div className="brand">
          <div className="brand-mark"><ShieldCheck size={20} /></div>
          <div>
            <strong>WiGuard</strong>
            <span>Operator Console</span>
          </div>
        </div>
        <nav className="nav-list">
          <NavButton active={view === "overview"} icon={<LayoutDashboard size={18} />} label="Overview" onClick={() => setView("overview")} />
          <NavButton active={view === "alerts"} icon={<ShieldAlert size={18} />} label="Alerts" onClick={() => setView("alerts")} />
          <NavButton active={view === "ap-detail"} icon={<Wifi size={18} />} label="AP Detail" onClick={() => setView("ap-detail")} />
          <NavButton active={view === "activity"} icon={<Activity size={18} />} label="Activity" onClick={() => setView("activity")} />
        </nav>
        <div className="runtime-box">
          <span>API</span>
          <code>{apiBase}</code>
          <StatusPill status={liveState === "live" ? "clean" : "info"} label={liveState === "live" ? "Live WS" : "REST fallback"} />
        </div>
      </aside>

      <section className="workspace">
        <header className="topbar">
          <div>
            <p className="eyebrow">Runtime state</p>
            <h1>Passive Evil Twin Monitoring</h1>
          </div>
          <button className="icon-button" onClick={() => void loadDashboard()} title="Refresh dashboard">
            <RefreshCw size={18} />
            <span>Refresh</span>
          </button>
        </header>

        {error && (
          <div className="notice error">
            <AlertTriangle size={18} />
            <span>{error}</span>
          </div>
        )}

        {loading ? (
          <div className="empty-state">Loading runtime state...</div>
        ) : (
          <>
            <section className="metrics-grid" aria-label="WiGuard summary metrics">
              <Metric icon={<Radio />} label="APs" value={stats?.ap_count ?? 0} hint={`Top status: ${statusCopy[topStatus]}`} />
              <Metric icon={<ShieldAlert />} label="Alerts" value={stats?.alert_count ?? 0} hint={`${stats?.raw_event_count ?? 0} raw events`} />
              <Metric icon={<Database />} label="Timeline" value={stats?.timeline_event_count ?? 0} hint={`Schema v${health?.schema_version ?? "?"}`} />
              <div className="metric chart-metric">
                <div className="metric-label">Alert classes</div>
                <ResponsiveContainer width="100%" height={64}>
                  <BarChart data={chartData} margin={{ top: 4, right: 0, bottom: 0, left: -28 }}>
                    <CartesianGrid strokeDasharray="3 3" vertical={false} />
                    <XAxis dataKey="name" tick={{ fontSize: 10 }} />
                    <YAxis allowDecimals={false} tick={{ fontSize: 10 }} />
                    <Tooltip />
                    <Bar dataKey="count" fill="#c2410c" radius={[3, 3, 0, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </section>

            {view === "overview" && (
              <Overview aps={aps} onSelect={(bssid) => { setSelectedBssid(bssid); setView("ap-detail"); }} />
            )}
            {view === "alerts" && (
              <AlertsView
                alerts={alerts}
                selectedAlert={alertDetail}
                alertTimeline={alertTimeline}
                classificationFilter={classificationFilter}
                statusFilter={statusFilter}
                onClassification={setClassificationFilter}
                onStatus={setStatusFilter}
                onSelect={setSelectedAlertKey}
              />
            )}
            {view === "ap-detail" && (
              <APDetailView aps={aps} selectedAp={selectedAp} detail={apDetail} onSelect={setSelectedBssid} />
            )}
            {view === "activity" && <ActivityView timeline={timeline} />}
          </>
        )}
      </section>
    </main>
  );
}

function NavButton({ active, icon, label, onClick }: { active: boolean; icon: ReactNode; label: string; onClick: () => void }) {
  return (
    <button className={`nav-button ${active ? "active" : ""}`} onClick={onClick}>
      {icon}
      <span>{label}</span>
    </button>
  );
}

function Metric({ icon, label, value, hint }: { icon: ReactNode; label: string; value: number; hint: string }) {
  return (
    <div className="metric">
      <div className="metric-icon">{icon}</div>
      <div>
        <div className="metric-label">{label}</div>
        <div className="metric-value">{value}</div>
        <div className="metric-hint">{hint}</div>
      </div>
    </div>
  );
}

function Overview({ aps, onSelect }: { aps: APListItem[]; onSelect: (bssid: string) => void }) {
  return (
    <section className="panel">
      <div className="panel-heading">
        <div>
          <h2>Access points</h2>
        </div>
        <Signal size={20} />
      </div>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Status</th>
              <th>SSID</th>
              <th>BSSID</th>
              <th>Channel</th>
              <th>RSSI</th>
              <th>Frames</th>
              <th>Last alert</th>
            </tr>
          </thead>
          <tbody>
            {[...aps].sort(apSort).map((ap) => (
              <tr key={ap.bssid} onClick={() => onSelect(ap.bssid)}>
                <td><StatusPill status={ap.status} /></td>
                <td className="strong">{ap.ssid || "<hidden>"}</td>
                <td><code>{ap.bssid}</code></td>
                <td>{ap.channels.join(", ") || "-"}</td>
                <td>{formatDbm(ap.avg_rssi_dbm ?? ap.last_rssi_dbm)}</td>
                <td>{ap.total_frames}</td>
                <td>{ap.last_alert ? `${statusCopy[ap.last_alert.classification]} · ${score(ap.last_alert.final_score)}` : "None"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {!aps.length && <div className="empty-state">No AP snapshots in the selected runtime database.</div>}
    </section>
  );
}

function AlertsView(props: {
  alerts: CorrelatedAlert[];
  selectedAlert: CorrelatedAlert | null;
  alertTimeline: TimelineEvent[];
  classificationFilter: string;
  statusFilter: string;
  onClassification: (value: string) => void;
  onStatus: (value: string) => void;
  onSelect: (alertKey: string) => void;
}) {
  return (
    <section className="split">
      <div className="panel">
        <div className="panel-heading">
          <div>
            <h2>Correlated alerts</h2>
          </div>
        </div>
        <div className="filters">
          <select value={props.classificationFilter} onChange={(event) => props.onClassification(event.target.value)}>
            <option value="">All classifications</option>
            <option value="info">Info</option>
            <option value="suspicious">Suspicious</option>
            <option value="evil_twin">Evil Twin</option>
          </select>
          <select value={props.statusFilter} onChange={(event) => props.onStatus(event.target.value)}>
            <option value="">All statuses</option>
            <option value="open">Open</option>
          </select>
        </div>
        <div className="alert-list">
          {props.alerts.map((alert) => (
            <button className="alert-row" key={alert.alert_key} onClick={() => props.onSelect(alert.alert_key)}>
              <StatusPill status={alert.classification} />
              <div>
                <strong>{alert.ssid}</strong>
                <code>{alert.bssid}</code>
                <span>{alert.contributing_modules.join(" + ")}</span>
              </div>
              <b>{score(alert.final_score)}</b>
            </button>
          ))}
        </div>
        {!props.alerts.length && <div className="empty-state">No correlated alerts for the current filter.</div>}
      </div>
      <div className="panel detail-panel">
        <h2>Alert evidence</h2>
        {props.selectedAlert ? (
          <>
            <div className="detail-head">
              <StatusPill status={props.selectedAlert.classification} />
              <strong>{props.selectedAlert.ssid}</strong>
              <code>{props.selectedAlert.bssid}</code>
            </div>
            <p className="explanation">{props.selectedAlert.explanation}</p>
            <div className="signal-list">
              {props.selectedAlert.signal_names.map((signal) => <span key={signal}>{signal}</span>)}
            </div>
            <TimelineList items={props.alertTimeline} />
            <JsonBlock value={props.selectedAlert.payload ?? props.selectedAlert} />
          </>
        ) : (
          <div className="empty-state">No alert selected.</div>
        )}
      </div>
    </section>
  );
}

function APDetailView({ aps, selectedAp, detail, onSelect }: { aps: APListItem[]; selectedAp: APListItem | null; detail: APDetail | null; onSelect: (bssid: string) => void }) {
  return (
    <section className="split">
      <div className="panel compact-list">
        <h2>Known APs</h2>
        {aps.map((ap) => (
          <button className={`ap-choice ${selectedAp?.bssid === ap.bssid ? "selected" : ""}`} key={ap.bssid} onClick={() => onSelect(ap.bssid)}>
            <StatusPill status={ap.status} />
            <div>
              <strong>{ap.ssid || "<hidden>"}</strong>
              <code>{ap.bssid}</code>
            </div>
          </button>
        ))}
      </div>
      <div className="panel detail-panel">
        <h2>AP detail</h2>
        {detail ? (
          <>
            <div className="detail-head">
              <StatusPill status={detail.status} />
              <strong>{String(detail.snapshot.ssid)}</strong>
              <code>{detail.snapshot.bssid}</code>
            </div>
            <div className="facts-grid">
              <Fact label="Channels" value={(detail.snapshot.channels ?? []).join(", ") || "-"} />
              <Fact label="Frames" value={String(detail.snapshot.total_frames ?? "-")} />
              <Fact label="RSSI" value={formatDbm((detail.snapshot.avg_rssi_dbm as number | null) ?? null)} />
              <Fact label="Fingerprint" value={String(detail.snapshot.dominant_ie_fingerprint ?? "-")} />
            </div>
            <h3>Open alerts</h3>
            <div className="mini-list">
              {detail.alerts.map((alert) => (
                <div key={alert.alert_key} className="mini-row">
                  <StatusPill status={alert.classification} />
                  <span>{alert.explanation}</span>
                </div>
              ))}
              {!detail.alerts.length && <span className="muted">No alerts for this AP.</span>}
            </div>
            <JsonBlock value={detail.snapshot.payload ?? detail.snapshot} />
          </>
        ) : (
          <div className="empty-state">No AP selected.</div>
        )}
      </div>
    </section>
  );
}

function ActivityView({ timeline }: { timeline: TimelineEvent[] }) {
  return (
    <section className="panel">
      <div className="panel-heading">
        <div>
          <h2>Live activity</h2>
        </div>
        <Activity size={20} />
      </div>
      <TimelineList items={[...timeline].reverse()} />
    </section>
  );
}

function TimelineList({ items }: { items: TimelineEvent[] }) {
  if (!items.length) return <div className="empty-state">No timeline events yet.</div>;
  return (
    <ol className="timeline">
      {items.map((event) => (
        <li key={event.timeline_id}>
          <span>{formatTime(event.observed_at)}</span>
          <strong>{event.event_type}</strong>
          <p>{event.message}</p>
          {event.bssid && <code>{event.bssid}</code>}
        </li>
      ))}
    </ol>
  );
}

function StatusPill({ status, label }: { status: Classification; label?: string }) {
  return <span className={`status status-${status}`}>{label ?? statusCopy[status]}</span>;
}

function Fact({ label, value }: { label: string; value: string }) {
  return (
    <div className="fact">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function JsonBlock({ value }: { value: unknown }) {
  return <pre className="json-block">{JSON.stringify(value, null, 2)}</pre>;
}

function apSort(a: APListItem, b: APListItem): number {
  return statusRank[b.status] - statusRank[a.status] || a.ssid.localeCompare(b.ssid) || a.bssid.localeCompare(b.bssid);
}

function score(value: number): string {
  return `${Math.round(value * 100)}%`;
}

function formatDbm(value: number | null | undefined): string {
  return value === null || value === undefined ? "-" : `${Math.round(value)} dBm`;
}

function formatTime(epochSeconds: number): string {
  return new Date(epochSeconds * 1000).toLocaleString();
}

function mergeTimeline(current: TimelineEvent[], incoming: TimelineEvent[]): TimelineEvent[] {
  const byId = new Map<number, TimelineEvent>();
  for (const item of [...current, ...incoming]) byId.set(item.timeline_id, item);
  return [...byId.values()].sort((a, b) => a.timeline_id - b.timeline_id);
}

function limitTimeline(items: TimelineEvent[]): TimelineEvent[] {
  return items.slice(-200);
}

function lastTimelineId(items: TimelineEvent[]): number {
  return items.reduce((max, item) => Math.max(max, item.timeline_id), 0);
}
