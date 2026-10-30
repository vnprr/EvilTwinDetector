import { MODULE_LABEL, ssidLabel } from "../lib/format";
import type { Evidence as EvidenceItem } from "../types";

/** One card per detector: which signals fired, why, and from which AP. */
export function Evidence({ items }: { items: EvidenceItem[] }) {
  return (
    <div className="evidence-list">
      {items.map((item, index) => {
        const linkedFrom = item.context.linked_from as string | undefined;
        return (
          <article className="evidence" key={`${item.module}-${item.bssid}-${index}`}>
            <header>
              <strong>{MODULE_LABEL[item.module] ?? item.module}</strong>
              {linkedFrom && (
                <span className="muted small">
                  observed on same-SSID AP <code>{linkedFrom}</code> ({ssidLabel(item.ssid)})
                </span>
              )}
            </header>
            <ul>
              {item.signals.map((signal) => (
                <li key={signal.name}>
                  <span className={`severity severity-${signal.severity}`}>{signal.severity}</span>
                  <span>
                    {signal.message} <code className="muted small">{signal.name}</code>
                  </span>
                </li>
              ))}
            </ul>
          </article>
        );
      })}
    </div>
  );
}
