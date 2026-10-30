import { Download } from "lucide-react";
import { useState } from "react";
import { api, exportUrl } from "../api";
import { Evidence } from "../components/Evidence";
import { Timeline } from "../components/Timeline";
import { Empty, Fact, Notice, Panel, StatusPill } from "../components/ui";
import { usePolling } from "../hooks/usePolling";
import { dateTime, MODULE_LABEL, SCORE_HINT, score, ssidLabel } from "../lib/format";

export function AlertsView({ selectedId, onSelect }: { selectedId: number | null; onSelect: (id: number) => void }) {
  const [status, setStatus] = useState("open");
  const [classification, setClassification] = useState("");
  const alerts = usePolling(`${status}|${classification}`, () => api.alerts({ status, classification }));
  const detail = usePolling(selectedId === null ? null : String(selectedId), () => api.alert(selectedId ?? 0));

  return (
    <div className="split">
      <Panel
        title="Alerts"
        sub={<span title={SCORE_HINT}>One alert per AP; it stays open while evidence keeps coming.</span>}
        actions={
          <a className="export-button" href={exportUrl("alerts")}>
            <Download size={15} /> CSV
          </a>
        }
      >
        <div className="filters">
          <select value={status} onChange={(event) => setStatus(event.target.value)} aria-label="Status">
            <option value="open">Open</option>
            <option value="resolved">Resolved</option>
            <option value="">All</option>
          </select>
          <select value={classification} onChange={(event) => setClassification(event.target.value)} aria-label="Verdict">
            <option value="">All verdicts</option>
            <option value="evil_twin">Evil Twin</option>
            <option value="suspicious">Suspicious</option>
            <option value="info">Info</option>
          </select>
        </div>
        {alerts.error && <Notice tone="error">{alerts.error}</Notice>}
        <div className="alert-list">
          {(alerts.data ?? []).map((alert) => (
            <button
              key={alert.id}
              className={`alert-row ${alert.id === selectedId ? "selected" : ""}`}
              onClick={() => onSelect(alert.id)}
            >
              <StatusPill status={alert.classification} />
              <div>
                <strong>{ssidLabel(alert.ssid)}</strong>
                <code>{alert.bssid}</code>
                <span>{alert.modules.map((module) => MODULE_LABEL[module] ?? module).join(" + ")}</span>
              </div>
              <b title={SCORE_HINT}>{score(alert.score)}</b>
            </button>
          ))}
        </div>
        {alerts.data?.length === 0 && <Empty>No alerts match the filter.</Empty>}
      </Panel>

      <Panel title="Evidence" className="detail-panel">
        {detail.data ? (
          <>
            <div className="detail-head">
              <StatusPill status={detail.data.alert.classification} />
              <strong>{ssidLabel(detail.data.alert.ssid)}</strong>
              <code>{detail.data.alert.bssid}</code>
              <span className="muted">{detail.data.alert.status}</span>
            </div>
            <p className="explanation">{detail.data.alert.explanation}</p>
            <div className="facts-grid">
              <Fact label="Score" value={score(detail.data.alert.score)} title={SCORE_HINT} />
              <Fact label="Updates" value={detail.data.alert.updates} />
              <Fact label="First seen" value={dateTime(detail.data.alert.first_seen)} />
              <Fact label="Last seen" value={dateTime(detail.data.alert.last_seen)} />
            </div>
            <h3>What each detector found</h3>
            <Evidence items={detail.data.alert.evidence} />
            <h3>Timeline of this AP</h3>
            <Timeline entries={detail.data.timeline} newestFirst />
          </>
        ) : (
          <Empty>Select an alert to see its evidence.</Empty>
        )}
      </Panel>
    </div>
  );
}
