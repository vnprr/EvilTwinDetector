import createClient from "openapi-fetch";
import type { paths } from "./schema";

export const apiBase = (import.meta.env.VITE_WIGUARD_API_BASE ?? "http://127.0.0.1:8765").replace(/\/$/, "");

/** Fully typed client: paths, parameters and responses come from the OpenAPI document. */
export const client = createClient<paths>({ baseUrl: apiBase });

/** Unwrap an openapi-fetch result, turning API errors into exceptions for TanStack Query. */
export async function unwrap<T>(request: Promise<{ data?: T; error?: unknown; response: Response }>): Promise<T> {
  const { data, error, response } = await request;
  if (data === undefined) {
    const detail = (error as { detail?: unknown } | undefined)?.detail;
    throw new Error(`${response.status}: ${typeof detail === "string" ? detail : response.statusText}`);
  }
  return data;
}

export const exportUrl = (name: "alerts" | "aps" | "events") => `${apiBase}/api/export/${name}.csv`;

export function liveUrl(afterId: number): string {
  const url = new URL(`${apiBase}/api/live`);
  url.protocol = url.protocol === "https:" ? "wss:" : "ws:";
  url.searchParams.set("after_id", String(afterId));
  return url.toString();
}
