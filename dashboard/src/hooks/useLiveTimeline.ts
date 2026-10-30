import { useEffect, useRef, useState } from "react";
import { api, liveUrl } from "../api";
import type { TimelineEntry } from "../types";

const KEEP = 300;

export type LiveState = "connecting" | "live" | "polling";

/** Timeline entries pushed over the WebSocket, with REST polling as a fallback. */
export function useLiveTimeline(): { entries: TimelineEntry[]; state: LiveState } {
  const [entries, setEntries] = useState<TimelineEntry[]>([]);
  const [state, setState] = useState<LiveState>("connecting");
  const lastId = useRef(0);

  useEffect(() => {
    let closed = false;
    const merge = (incoming: TimelineEntry[]) => {
      if (!incoming.length) return;
      lastId.current = Math.max(lastId.current, ...incoming.map((entry) => entry.id));
      setEntries((current) => {
        const byId = new Map([...current, ...incoming].map((entry) => [entry.id, entry]));
        return [...byId.values()].sort((a, b) => a.id - b.id).slice(-KEEP);
      });
    };

    let socket: WebSocket | null = null;
    void api
      .timeline()
      .then(merge)
      .catch(() => undefined)
      .finally(() => {
        if (closed) return;
        socket = new WebSocket(liveUrl(lastId.current));
        socket.onopen = () => setState("live");
        socket.onmessage = (message) => merge((JSON.parse(message.data) as { items: TimelineEntry[] }).items);
        socket.onclose = () => !closed && setState("polling");
      });

    const fallback = window.setInterval(() => {
      if (socket?.readyState === WebSocket.OPEN) return;
      setState("polling");
      void api.timeline(lastId.current).then(merge).catch(() => undefined);
    }, 5000);

    return () => {
      closed = true;
      socket?.close();
      window.clearInterval(fallback);
    };
  }, []);

  return { entries, state };
}
