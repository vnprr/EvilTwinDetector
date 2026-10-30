import type { Verdict } from "../types";

export const VERDICT_LABEL: Record<Verdict, string> = {
  clean: "Clean",
  info: "Info",
  suspicious: "Suspicious",
  evil_twin: "Evil Twin",
};

const VERDICT_RANK: Record<Verdict, number> = { clean: 0, info: 1, suspicious: 2, evil_twin: 3 };

export const byVerdict = (a: { status: Verdict }, b: { status: Verdict }) => VERDICT_RANK[b.status] - VERDICT_RANK[a.status];

export const MODULE_LABEL: Record<string, string> = {
  identity_verification: "Identity",
  environment_anomaly: "Environment",
  deauth_storm: "Deauth storm",
};

export const SCORE_HINT =
  "Evidence score 0–100: 1 − Π(1 − weight × strength) over the modules that fired. " +
  "A heuristic ranking, not a calibrated probability.";

/** Scores are shown out of 100, never as a percentage: they are not probabilities. */
export const score = (value: number) => `${Math.round(value * 100)}/100`;

export const ssidLabel = (ssid: string | null | undefined) => ssid || "<hidden>";

export const dbm = (value: number | null | undefined) => (value == null ? "–" : `${Math.round(value)} dBm`);

export const ppm = (value: number | null | undefined) =>
  value == null ? "–" : `${value > 0 ? "+" : ""}${value.toFixed(1)} ppm`;

export const dateTime = (epochSeconds: number) => new Date(epochSeconds * 1000).toLocaleString();

export const clock = (epochSeconds: number) => new Date(epochSeconds * 1000).toLocaleTimeString();

export function age(seconds: number | null | undefined): string {
  if (seconds == null) return "unknown";
  if (seconds < 90) return `${Math.round(seconds)} s`;
  if (seconds < 5400) return `${Math.round(seconds / 60)} min`;
  if (seconds < 172_800) return `${Math.round(seconds / 3600)} h`;
  return `${Math.round(seconds / 86_400)} days`;
}

export const shortHash = (hash: string | null | undefined) => (hash ? `${hash.slice(0, 12)}…` : "–");
