import { useEffect, useRef, useState } from "react";
import { client, liveUrl, unwrap } from "./client";
import type { TimelineEntry } from "./types";

const KEEP = 300;

export type LiveState = "connecting" | "live" | "polling";

/** Timeline entries pushed over the WebSocket, with REST polling while it is unavailable. */
export function useLiveTimeline(): { entries: TimelineEntry[]; state: LiveState } {
  const [entries, setEntries] = useState<TimelineEntry[]>([]);
  const [state, setState] = useState<LiveState>("connecting");
  const lastId = useRef(0);

  useEffect(() => {
    let closed = false;
    let socket: WebSocket | undefined;

    const merge = (incoming: TimelineEntry[]) => {
      if (!incoming.length) return;
      lastId.current = Math.max(lastId.current, ...incoming.map((entry) => entry.id));
      setEntries((current) => {
        const byId = new Map([...current, ...incoming].map((entry) => [entry.id, entry]));
        return [...byId.values()].sort((a, b) => a.id - b.id).slice(-KEEP);
      });
    };
    const poll = () =>
      unwrap(client.GET("/api/timeline", { params: { query: { after_id: lastId.current || undefined, limit: 200 } } }))
        .then(merge)
        .catch(() => undefined);

    void poll().finally(() => {
      if (closed) return;
      socket = new WebSocket(liveUrl(lastId.current));
      socket.onopen = () => setState("live");
      socket.onmessage = (message) => merge(JSON.parse(message.data) as TimelineEntry[]);
      socket.onclose = () => {
        if (!closed) setState("polling");
      };
    });
    const fallback = window.setInterval(() => {
      if (socket?.readyState !== WebSocket.OPEN) void poll();
    }, 5_000);

    return () => {
      closed = true;
      socket?.close();
      window.clearInterval(fallback);
    };
  }, []);

  return { entries, state };
}
