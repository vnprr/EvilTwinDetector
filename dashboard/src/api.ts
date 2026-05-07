import type {
  APDetail,
  APListItem,
  CorrelatedAlert,
  DetectionEventRow,
  HealthPayload,
  RuntimeStats,
  TimelineEvent,
} from "./types";

const API_BASE = (import.meta.env.VITE_WIGUARD_API_BASE ?? "http://127.0.0.1:8765").replace(/\/$/, "");

async function request<T>(path: string): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`);
  if (!response.ok) {
    const detail = await response.text();
    throw new Error(`${response.status} ${response.statusText}: ${detail}`);
  }
  return response.json() as Promise<T>;
}

export const apiBase = API_BASE;

export const api = {
  health: () => request<HealthPayload>("/api/health"),
  stats: () => request<RuntimeStats & { state_path: string }>("/api/stats"),
  aps: async () => (await request<{ count: number; items: APListItem[] }>("/api/aps")).items,
  apDetail: (bssid: string) => request<APDetail>(`/api/aps/${encodeURIComponent(bssid)}`),
  apTimeline: async (bssid: string) =>
    (await request<{ count: number; items: TimelineEvent[] }>(`/api/aps/${encodeURIComponent(bssid)}/timeline?limit=200`)).items,
  alerts: async (query = "") =>
    (await request<{ count: number; items: CorrelatedAlert[] }>(`/api/alerts${query}`)).items,
  alertDetail: (alertKey: string) => request<{ alert: CorrelatedAlert; timeline: TimelineEvent[] }>(`/api/alerts/${encodeURIComponent(alertKey)}`),
  events: async (limit = 100) =>
    (await request<{ count: number; items: DetectionEventRow[] }>(`/api/events?limit=${limit}`)).items,
  timeline: async (afterId?: number) => {
    const suffix = afterId && afterId > 0 ? `?after_id=${afterId}&limit=100` : "?limit=100";
    return (await request<{ count: number; items: TimelineEvent[] }>(`/api/timeline${suffix}`)).items;
  },
};

export function liveWebSocketUrl(afterId = 0): string {
  const url = new URL(API_BASE);
  url.protocol = url.protocol === "https:" ? "wss:" : "ws:";
  url.pathname = "/ws/live";
  url.search = `after_id=${afterId}`;
  return url.toString();
}
