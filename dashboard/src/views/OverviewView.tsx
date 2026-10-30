import { Check } from "lucide-react";
import { useNavigate } from "react-router";
import { useAccessPoints } from "../api/queries";
import { Empty, Panel, StatusPill } from "../components/ui";
import { byVerdict, dbm, ppm, ssidLabel } from "../lib/format";

export function OverviewView() {
  const navigate = useNavigate();
  const { data: aps = [] } = useAccessPoints();
  const sorted = [...aps].sort(
    (a, b) => byVerdict(a, b) || a.ssid.localeCompare(b.ssid) || a.bssid.localeCompare(b.bssid),
  );

  return (
    <Panel title="Access points" sub="Every AP heard by the sensor, most serious verdict first.">
      {sorted.length ? (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Status</th>
                <th>SSID</th>
                <th>BSSID</th>
                <th>Channel</th>
                <th>RSSI</th>
                <th>Clock skew</th>
                <th>Frames</th>
                <th title="Enrolled as a trusted profile">Trusted</th>
              </tr>
            </thead>
            <tbody>
              {sorted.map((ap) => (
                <tr key={ap.bssid} onClick={() => navigate(`/aps/${ap.bssid}`)}>
                  <td>
                    <StatusPill status={ap.status} />
                  </td>
                  <td className="strong">{ssidLabel(ap.ssid)}</td>
                  <td>
                    <code>{ap.bssid}</code>
                  </td>
                  <td>{ap.channels.join(", ") || "–"}</td>
                  <td>{dbm(ap.avg_rssi_dbm)}</td>
                  <td>{ppm(ap.clock_skew_ppm)}</td>
                  <td>{ap.frames}</td>
                  <td>{ap.trusted && <Check size={16} aria-label="trusted" />}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <Empty>No access points in this database yet.</Empty>
      )}
    </Panel>
  );
}
