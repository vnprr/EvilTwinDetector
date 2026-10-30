import type { TimelineEntry } from "../api/types";
import { dateTime } from "../lib/format";
import { Empty } from "./ui";

const KIND_LABEL: Record<string, string> = {
  detection: "Evidence",
  alert_opened: "Alert opened",
  alert_escalated: "Escalated",
  alert_resolved: "Resolved",
};

export function Timeline({ entries, newestFirst = false }: { entries: TimelineEntry[]; newestFirst?: boolean }) {
  if (!entries.length) return <Empty>No activity recorded yet.</Empty>;
  const ordered = newestFirst ? [...entries].reverse() : entries;
  return (
    <ol className="timeline">
      {ordered.map((entry) => (
        <li key={entry.id} className={`kind-${entry.kind}`}>
          <div className="timeline-meta">
            <strong>{KIND_LABEL[entry.kind] ?? entry.kind}</strong>
            <time>{dateTime(entry.observed_at)}</time>
            {entry.bssid && <code>{entry.bssid}</code>}
          </div>
          <p>{entry.message}</p>
        </li>
      ))}
    </ol>
  );
}
