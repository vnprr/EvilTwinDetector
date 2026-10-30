import { Download } from "lucide-react";
import { Link, useParams, useSearchParams } from "react-router";
import { exportUrl } from "../api/client";
import { type AlertFilter, useAlert, useAlerts } from "../api/queries";
import { Evidence } from "../components/Evidence";
import { Timeline } from "../components/Timeline";
import { Empty, Fact, Notice, Panel, StatusPill } from "../components/ui";
import { dateTime, MODULE_LABEL, SCORE_HINT, score, ssidLabel } from "../lib/format";

export function AlertsView() {
  const params = useParams();
  const [search, setSearch] = useSearchParams({ status: "open" });
  const filter: AlertFilter = {
    status: (search.get("status") || undefined) as AlertFilter["status"],
    classification: (search.get("verdict") || undefined) as AlertFilter["classification"],
  };
  const alerts = useAlerts(filter);
  const selectedId = params.alertId ? Number(params.alertId) : undefined;
  const detail = useAlert(selectedId);
  const choose = (key: string) => (value: string) =>
    setSearch((current) => {
      current.set(key, value);
      return current;
    });

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
          <select
            value={search.get("status") ?? ""}
            onChange={(e) => choose("status")(e.target.value)}
            aria-label="Status"
          >
            <option value="open">Open</option>
            <option value="resolved">Resolved</option>
            <option value="">All</option>
          </select>
          <select
            value={search.get("verdict") ?? ""}
            onChange={(e) => choose("verdict")(e.target.value)}
            aria-label="Verdict"
          >
            <option value="">All verdicts</option>
            <option value="evil_twin">Evil Twin</option>
            <option value="suspicious">Suspicious</option>
            <option value="info">Info</option>
          </select>
        </div>
        {alerts.error && <Notice tone="error">{alerts.error.message}</Notice>}
        <div className="alert-list">
          {alerts.data?.map((alert) => (
            <Link
              key={alert.id}
              to={{ pathname: `/alerts/${alert.id}`, search: search.toString() }}
              className={`alert-row ${alert.id === selectedId ? "selected" : ""}`}
            >
              <StatusPill status={alert.classification} />
              <div>
                <strong>{ssidLabel(alert.ssid)}</strong>
                <code>{alert.bssid}</code>
                <span>{alert.modules.map((module) => MODULE_LABEL[module] ?? module).join(" + ")}</span>
              </div>
              <b title={SCORE_HINT}>{score(alert.score)}</b>
            </Link>
          ))}
        </div>
        {alerts.data?.length === 0 && <Empty>No alerts match the filter.</Empty>}
      </Panel>

      <Panel title="Evidence" className="detail-panel">
        {detail.error && <Notice tone="error">{detail.error.message}</Notice>}
        {detail.data ? (
          <>
            <div className="detail-head">
              <StatusPill status={detail.data.alert.classification} />
              <strong>{ssidLabel(detail.data.alert.ssid)}</strong>
              <Link to={`/aps/${detail.data.alert.bssid}`}>
                <code>{detail.data.alert.bssid}</code>
              </Link>
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
          !detail.error && <Empty>Select an alert to see its evidence.</Empty>
        )}
      </Panel>
    </div>
  );
}
