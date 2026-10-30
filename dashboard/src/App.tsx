import { Activity, KeyRound, LayoutDashboard, Radio, Server, Settings, ShieldAlert, ShieldCheck, Wifi } from "lucide-react";
import type { ReactNode } from "react";
import { useState } from "react";
import { api, apiBase } from "./api";
import { Timeline } from "./components/Timeline";
import { Metric, Notice, Panel, StatusPill } from "./components/ui";
import { useLiveTimeline } from "./hooks/useLiveTimeline";
import { usePolling } from "./hooks/usePolling";
import { age, dateTime } from "./lib/format";
import type { SensorStatus } from "./types";
import { AccessPointView } from "./views/AccessPointView";
import { AlertsView } from "./views/AlertsView";
import { OverviewView } from "./views/OverviewView";
import { SystemView } from "./views/SystemView";

type View = "overview" | "alerts" | "ap" | "activity" | "system";

const NAVIGATION: { view: View; label: string; icon: ReactNode }[] = [
  { view: "overview", label: "Overview", icon: <LayoutDashboard size={18} /> },
  { view: "alerts", label: "Alerts", icon: <ShieldAlert size={18} /> },
  { view: "ap", label: "Access point", icon: <Wifi size={18} /> },
  { view: "activity", label: "Activity", icon: <Activity size={18} /> },
  { view: "system", label: "System", icon: <Settings size={18} /> },
];

export function App() {
  const [view, setView] = useState<View>("overview");
  const [selectedBssid, setSelectedBssid] = useState<string | null>(null);
  const [selectedAlert, setSelectedAlert] = useState<number | null>(null);

  const aps = usePolling("aps", api.accessPoints);
  const stats = usePolling("stats", api.stats);
  const sensor = usePolling("sensor", api.sensor);
  const live = useLiveTimeline();

  const openAp = (bssid: string) => {
    setSelectedBssid(bssid);
    setView("ap");
  };
  const byClass = stats.data?.open_alerts_by_classification ?? {};
  const unreachable = aps.error ?? stats.error;

  return (
    <main className="app-shell">
      <aside className="sidebar" aria-label="Navigation">
        <div className="brand">
          <div className="brand-mark"><ShieldCheck size={20} /></div>
          <div>
            <strong>WiGuard</strong>
            <span>Evil Twin monitor</span>
          </div>
        </div>
        <nav className="nav-list">
          {NAVIGATION.map((item) => (
            <button
              key={item.view}
              className={`nav-button ${view === item.view ? "active" : ""}`}
              onClick={() => setView(item.view)}
              aria-current={view === item.view ? "page" : undefined}
            >
              {item.icon}
              <span>{item.label}</span>
            </button>
          ))}
        </nav>
        <div className="runtime-box">
          <span>API</span>
          <code>{apiBase}</code>
          <StatusPill status={live.state === "live" ? "clean" : "info"} label={live.state === "live" ? "live updates" : "polling"} />
        </div>
      </aside>

      <section className="workspace">
        <header className="topbar">
          <div>
            <p className="eyebrow">Passive monitoring · read-only</p>
            <h1>{NAVIGATION.find((item) => item.view === view)?.label}</h1>
          </div>
        </header>

        {unreachable && <Notice tone="error">Cannot read the WiGuard API at {apiBase}: {unreachable}</Notice>}
        {sensor.data?.state === "stale" && (
          <Notice tone="warning">The sensor stopped writing updates {age(sensor.data.age_seconds)} ago; data may be outdated.</Notice>
        )}
        {sensor.data?.state === "replay" && <Notice tone="info">{sensor.data.detail}</Notice>}

        <section className="metrics-grid" aria-label="Summary">
          <Metric icon={<Radio />} label="Access points" value={stats.data?.access_points ?? "–"} />
          <Metric
            icon={<ShieldAlert />}
            label="Open alerts"
            value={stats.data?.open_alerts ?? "–"}
            hint={`${byClass.evil_twin ?? 0} evil twin · ${byClass.suspicious ?? 0} suspicious · ${byClass.info ?? 0} info`}
          />
          <Metric icon={<Server />} label="Sensor" value={sensor.data?.state ?? "–"} hint={sensorHint(sensor.data)} />
          <Metric
            icon={<KeyRound />}
            label="Trusted profiles"
            value={aps.data?.filter((ap) => ap.trusted).length ?? "–"}
            hint="enrolled APs currently heard"
          />
        </section>

        {view === "overview" && <OverviewView aps={aps.data ?? []} onSelect={openAp} />}
        {view === "alerts" && <AlertsView selectedId={selectedAlert} onSelect={setSelectedAlert} />}
        {view === "ap" && <AccessPointView aps={aps.data ?? []} selected={selectedBssid} onSelect={setSelectedBssid} />}
        {view === "activity" && (
          <Panel title="Activity" sub="Evidence and alert changes as they are recorded.">
            <Timeline entries={live.entries} newestFirst />
          </Panel>
        )}
        {view === "system" && <SystemView sensor={sensor.data} />}
      </section>
    </main>
  );
}

function sensorHint(sensor: SensorStatus | null): string | undefined {
  if (!sensor?.last_update) return undefined;
  if (sensor.state === "replay") return `capture ends ${dateTime(sensor.last_update)}`;
  return `updated ${age(sensor.age_seconds)} ago`;
}
