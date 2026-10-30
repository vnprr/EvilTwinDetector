import { NavLink, useParams } from "react-router";
import { useAccessPoint, useAccessPoints, useMetrics } from "../api/queries";
import { Evidence } from "../components/Evidence";
import { TrendChart } from "../components/TrendChart";
import { Empty, Fact, Notice, Panel, RawJson, StatusPill } from "../components/ui";
import { dateTime, dbm, ppm, SCORE_HINT, score, shortHash, ssidLabel } from "../lib/format";

export function AccessPointView() {
  const { bssid } = useParams();
  const { data: aps = [] } = useAccessPoints();
  const detail = useAccessPoint(bssid);
  const metrics = useMetrics(bssid);
  const ap = detail.data?.access_point;

  return (
    <div className="split">
      <Panel title="Access points" className="compact-list">
        {aps.map((item) => (
          <NavLink key={item.bssid} to={`/aps/${item.bssid}`} className="ap-choice">
            <StatusPill status={item.status} />
            <div>
              <strong>{ssidLabel(item.ssid)}</strong>
              <code>{item.bssid}</code>
            </div>
          </NavLink>
        ))}
        {!aps.length && <Empty>No access points yet.</Empty>}
      </Panel>

      <Panel title="Access point" className="detail-panel">
        {detail.error && <Notice tone="error">{detail.error.message}</Notice>}
        {ap && detail.data ? (
          <>
            <div className="detail-head">
              <StatusPill status={ap.status} />
              <strong>{ssidLabel(ap.ssid)}</strong>
              <code>{ap.bssid}</code>
            </div>
            <div className="facts-grid">
              <Fact label="Channels" value={ap.channels.join(", ") || "–"} />
              <Fact label="Frames" value={ap.frames} />
              <Fact label="RSSI" value={`${dbm(ap.avg_rssi_dbm)} ± ${ap.rssi_stddev ?? "–"}`} />
              <Fact label="Clock skew" value={ppm(ap.clock_skew_ppm)} />
              <Fact
                label="IE fingerprint"
                value={shortHash(ap.dominant_ie_fingerprint)}
                title={ap.dominant_ie_fingerprint ?? ""}
              />
              <Fact label="Vendor OUIs" value={ap.vendor_ouis.join(", ") || "–"} />
              <Fact label="First heard" value={dateTime(ap.first_seen)} />
              <Fact label="Last heard" value={dateTime(ap.last_seen)} />
            </div>
            {ap.trusted ? (
              <p className="muted small">Enrolled as a trusted profile: compared against it on every update.</p>
            ) : (
              <Notice tone="info">
                Not a trusted profile. If this is one of your APs, enroll it during a known-good period with{" "}
                <code>wiguard enroll --duration 120 --ssid "{ap.ssid}"</code>.
              </Notice>
            )}
            <h3>Trends</h3>
            <TrendChart title="RSSI" unit="dBm" samples={metrics.data ?? []} series="avg_rssi_dbm" color="#285a84" />
            <TrendChart
              title="Clock skew"
              unit="ppm"
              samples={metrics.data ?? []}
              series="clock_skew_ppm"
              color="#c2410c"
              decimals={2}
            />
            <h3>Alerts</h3>
            {detail.data.alerts.length ? (
              detail.data.alerts.map((alert) => (
                <div key={alert.id} className="ap-alert">
                  <div className="detail-head">
                    <StatusPill status={alert.classification} />
                    <b title={SCORE_HINT}>{score(alert.score)}</b>
                    <span className="muted">
                      {alert.status} · {dateTime(alert.first_seen)}
                    </span>
                  </div>
                  <p className="explanation">{alert.explanation}</p>
                  {alert.status === "open" && <Evidence items={alert.evidence} />}
                </div>
              ))
            ) : (
              <p className="muted">No alerts for this AP.</p>
            )}
            <RawJson label="Full feature summary (JSON)" value={detail.data.summary} />
          </>
        ) : (
          !detail.error && <Empty>Select an access point.</Empty>
        )}
      </Panel>
    </div>
  );
}
