import type {
  AccessPoint,
  AccessPointDetail,
  Alert,
  AlertDetail,
  EffectiveConfig,
  Items,
  MetricSample,
  SensorStatus,
  Stats,
  TimelineEntry,
  TrustedProfiles,
} from "./types";

export const apiBase = (import.meta.env.VITE_WIGUARD_API_BASE ?? "http://127.0.0.1:8765").replace(/\/$/, "");

async function get<T>(path: string): Promise<T> {
  const response = await fetch(`${apiBase}${path}`);
  if (!response.ok) {
    let detail = response.statusText;
    try {
      detail = (await response.json()).detail ?? detail;
    } catch {
      // keep the status text
    }
    throw new Error(`${response.status}: ${typeof detail === "string" ? detail : JSON.stringify(detail)}`);
  }
  return (await response.json()) as T;
}

async function items<T>(path: string): Promise<T[]> {
  return (await get<Items<T>>(path)).items;
}

const ap = (bssid: string) => `/api/aps/${encodeURIComponent(bssid)}`;

export type AlertFilter = { status?: string; classification?: string };

export const api = {
  stats: () => get<Stats>("/api/stats"),
  sensor: () => get<SensorStatus>("/api/sensor"),
  config: () => get<EffectiveConfig>("/api/config"),
  trustedProfiles: () => get<TrustedProfiles>("/api/trusted-profiles"),
  accessPoints: () => items<AccessPoint>("/api/aps"),
  accessPoint: (bssid: string) => get<AccessPointDetail>(ap(bssid)),
  metrics: (bssid: string) => items<MetricSample>(`${ap(bssid)}/metrics?limit=500`),
  alerts: (filter: AlertFilter) => {
    const query = new URLSearchParams(Object.entries(filter).filter(([, value]) => value) as [string, string][]);
    return items<Alert>(`/api/alerts${query.size ? `?${query}` : ""}`);
  },
  alert: (id: number) => get<AlertDetail>(`/api/alerts/${id}`),
  timeline: (afterId?: number) => items<TimelineEntry>(`/api/timeline?limit=200${afterId ? `&after_id=${afterId}` : ""}`),
};

export const exportUrl = (name: "alerts" | "aps" | "events") => `${apiBase}/api/export/${name}.csv`;

export function liveUrl(afterId: number): string {
  const url = new URL(`${apiBase}/ws/live`);
  url.protocol = url.protocol === "https:" ? "wss:" : "ws:";
  url.searchParams.set("after_id", String(afterId));
  return url.toString();
}
