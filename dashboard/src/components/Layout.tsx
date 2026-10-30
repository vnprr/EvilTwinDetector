import {
  Activity,
  KeyRound,
  LayoutDashboard,
  Radio,
  Server,
  Settings,
  ShieldAlert,
  ShieldCheck,
  Wifi,
} from "lucide-react";
import type { ReactNode } from "react";
import { NavLink, Outlet, useLocation } from "react-router";
import { apiBase } from "../api/client";
import { type LiveState, useLiveTimeline } from "../api/live";
import { useAccessPoints, useSensor, useStats } from "../api/queries";
import type { SensorStatus, TimelineEntry } from "../api/types";
import { age, dateTime } from "../lib/format";
import { Metric, Notice, StatusPill } from "./ui";

const NAVIGATION: { to: string; label: string; icon: ReactNode }[] = [
  { to: "/", label: "Overview", icon: <LayoutDashboard size={18} /> },
  { to: "/alerts", label: "Alerts", icon: <ShieldAlert size={18} /> },
  { to: "/aps", label: "Access point", icon: <Wifi size={18} /> },
  { to: "/activity", label: "Activity", icon: <Activity size={18} /> },
  { to: "/system", label: "System", icon: <Settings size={18} /> },
];

/** Shared with child routes through the router outlet. */
export type LayoutContext = { timeline: TimelineEntry[]; live: LiveState };

export function Layout() {
  const { pathname } = useLocation();
  const stats = useStats();
  const sensor = useSensor();
  const aps = useAccessPoints();
  const live = useLiveTimeline();

  const title = [...NAVIGATION].reverse().find((item) => pathname.startsWith(item.to))?.label;
  const byClass = stats.data?.open_alerts_by_classification ?? {};
  const unreachable = stats.error ?? aps.error;

  return (
    <main className="app-shell">
      <aside className="sidebar" aria-label="Navigation">
        <div className="brand">
          <div className="brand-mark">
            <ShieldCheck size={20} />
          </div>
          <div>
            <strong>WiGuard</strong>
            <span>Evil Twin monitor</span>
          </div>
        </div>
        <nav className="nav-list">
          {NAVIGATION.map((item) => (
            <NavLink key={item.to} to={item.to} end={item.to === "/"} className="nav-button">
              {item.icon}
              <span>{item.label}</span>
            </NavLink>
          ))}
        </nav>
        <div className="runtime-box">
          <span>API</span>
          <code>{apiBase}</code>
          <StatusPill
            status={live.state === "live" ? "clean" : "info"}
            label={live.state === "live" ? "live updates" : "polling"}
          />
        </div>
      </aside>

      <section className="workspace">
        <header className="topbar">
          <p className="eyebrow">Passive monitoring · read-only</p>
          <h1>{title}</h1>
        </header>

        {unreachable && (
          <Notice tone="error">
            Cannot read the WiGuard API at {apiBase}: {unreachable.message}
          </Notice>
        )}
        {sensor.data?.state === "stale" && (
          <Notice tone="warning">
            The sensor stopped writing updates {age(sensor.data.age_seconds)} ago; data may be outdated.
          </Notice>
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
            label="Trusted APs heard"
            value={aps.data?.filter((ap) => ap.trusted).length ?? "–"}
            hint="enrolled profiles on the air"
          />
        </section>

        <Outlet context={{ timeline: live.entries, live: live.state } satisfies LayoutContext} />
      </section>
    </main>
  );
}

function sensorHint(sensor: SensorStatus | undefined): string | undefined {
  if (!sensor?.last_update) return undefined;
  if (sensor.state === "replay") return `capture ends ${dateTime(sensor.last_update)}`;
  return `updated ${age(sensor.age_seconds)} ago`;
}
