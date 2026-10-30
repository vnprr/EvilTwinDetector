import { useQuery } from "@tanstack/react-query";
import { client, unwrap } from "./client";

// One hook per resource. TanStack Query caches, de-duplicates and refreshes them;
// `refetchInterval` keeps the read-only views close to the sensor's flush rate.
const LIVE = 5_000;
const SLOW = 30_000;

export const useStats = () =>
  useQuery({ queryKey: ["stats"], queryFn: () => unwrap(client.GET("/api/stats")), refetchInterval: LIVE });

export const useSensor = () =>
  useQuery({ queryKey: ["sensor"], queryFn: () => unwrap(client.GET("/api/sensor")), refetchInterval: LIVE });

export const useAccessPoints = () =>
  useQuery({ queryKey: ["aps"], queryFn: () => unwrap(client.GET("/api/aps")), refetchInterval: LIVE });

export const useAccessPoint = (bssid: string | undefined) =>
  useQuery({
    queryKey: ["aps", bssid],
    queryFn: () => unwrap(client.GET("/api/aps/{bssid}", { params: { path: { bssid: bssid ?? "" } } })),
    enabled: bssid !== undefined,
    refetchInterval: LIVE,
  });

export const useMetrics = (bssid: string | undefined) =>
  useQuery({
    queryKey: ["aps", bssid, "metrics"],
    queryFn: () =>
      unwrap(
        client.GET("/api/aps/{bssid}/metrics", { params: { path: { bssid: bssid ?? "" }, query: { limit: 500 } } }),
      ),
    enabled: bssid !== undefined,
    refetchInterval: 10_000,
  });

export type AlertFilter = {
  status?: "open" | "resolved";
  classification?: "info" | "suspicious" | "evil_twin";
};

export const useAlerts = (filter: AlertFilter) =>
  useQuery({
    queryKey: ["alerts", filter],
    queryFn: () => unwrap(client.GET("/api/alerts", { params: { query: filter } })),
    refetchInterval: LIVE,
  });

export const useAlert = (id: number | undefined) =>
  useQuery({
    queryKey: ["alerts", id],
    queryFn: () => unwrap(client.GET("/api/alerts/{alert_id}", { params: { path: { alert_id: id ?? 0 } } })),
    enabled: id !== undefined,
    refetchInterval: LIVE,
  });

export const useTrustedProfiles = () =>
  useQuery({
    queryKey: ["trusted-profiles"],
    queryFn: () => unwrap(client.GET("/api/trusted-profiles")),
    refetchInterval: SLOW,
  });

export const useConfig = () =>
  useQuery({ queryKey: ["config"], queryFn: () => unwrap(client.GET("/api/config")), staleTime: Infinity });
