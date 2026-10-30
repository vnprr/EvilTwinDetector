import { Download } from "lucide-react";
import { exportUrl } from "../api/client";
import { useConfig, useSensor, useTrustedProfiles } from "../api/queries";
import type { EffectiveConfig, SensorStatus, Verdict } from "../api/types";
import { Empty, Fact, Notice, Panel, StatusPill } from "../components/ui";
import { age, dateTime, MODULE_LABEL, ppm, ssidLabel } from "../lib/format";

const SENSOR_PILL: Record<SensorStatus["state"], Verdict> = {
  online: "clean",
  replay: "info",
  unknown: "info",
  stale: "suspicious",
};

export function SystemView() {
  const { data: sensor } = useSensor();
  const profiles = useTrustedProfiles();
  const config = useConfig();
  const status = sensor?.status ?? {};
  const frames = (status.frames ?? {}) as Record<string, number>;

  return (
    <div className="split">
      <div className="stack">
        <Panel title="Sensor">
          {sensor ? (
            <>
              <div className="detail-head">
                <StatusPill status={SENSOR_PILL[sensor.state]} label={sensor.state} />
                {sensor.state !== "replay" && sensor.age_seconds != null && (
                  <span className="muted">last update {age(sensor.age_seconds)} ago</span>
                )}
              </div>
              <p className="explanation">{sensor.detail}</p>
              <div className="facts-grid">
                {sensor.state === "replay" ? (
                  <>
                    <Fact label="Capture file" value={String(status.source ?? "–")} />
                    <Fact label="Update step" value={`${status.step_seconds ?? "–"} s of capture time`} />
                    <Fact label="Beacons" value={String(frames.beacons ?? "–")} />
                    <Fact label="Deauth/disassoc frames" value={String(frames.disruption ?? "–")} />
                  </>
                ) : (
                  <>
                    <Fact label="Capture interface" value={String(status.interface ?? "–")} />
                    <Fact label="Protected interface" value={String(status.internal_interface ?? "–")} />
                    <Fact label="Channels" value={Array.isArray(status.channels) ? status.channels.length : "–"} />
                    <Fact label="Beacons" value={String(frames.beacons ?? "–")} />
                  </>
                )}
                <Fact label="Trusted profiles loaded" value={String(status.trusted_profiles ?? "–")} />
                <Fact label="Config" value={String(status.config_source ?? "built-in defaults")} />
              </div>
            </>
          ) : (
            <Empty>Sensor status unavailable.</Empty>
          )}
        </Panel>

        <Panel title="Trusted profiles" sub={profiles.data?.path}>
          {profiles.data?.error && <Notice tone="error">{profiles.data.error}</Notice>}
          {profiles.data?.profiles.length ? (
            <div className="mini-list">
              {profiles.data.profiles.map((profile) => (
                <div key={profile.bssid} className="mini-row">
                  <code>{profile.bssid}</code>
                  <span>
                    {ssidLabel(profile.ssid)} · {profile.frames} frames · {ppm(profile.clock_skew_ppm)} · enrolled{" "}
                    {dateTime(profile.enrolled_at)}
                  </span>
                </div>
              ))}
            </div>
          ) : (
            <p className="muted">
              Nothing enrolled: identity checks are off. Record your own APs during a known-good period with{" "}
              <code>wiguard enroll --duration 120</code>.
            </p>
          )}
        </Panel>
      </div>

      <Panel
        title="Detection settings"
        sub="The values the detectors run with (read-only; change them in config.yaml)."
        className="detail-panel"
        actions={
          <div className="export-row">
            {(["alerts", "aps", "events"] as const).map((name) => (
              <a key={name} className="export-button" href={exportUrl(name)}>
                <Download size={15} /> {name}
              </a>
            ))}
          </div>
        }
      >
        {config.data ? <ConfigSummary config={config.data} /> : <Empty>Configuration unavailable.</Empty>}
      </Panel>
    </div>
  );
}

function ConfigSummary({ config }: { config: EffectiveConfig }) {
  const { correlation, ...detectors } = config.settings.detection;
  return (
    <>
      <p className="muted small">Source: {config.source_path ?? "built-in defaults"}</p>
      <h3>Correlation</h3>
      <p className="muted small">
        score = 1 − Π(1 − weight × strength); strength is 1.0 / 0.6 / 0.3 for high / medium / low signals.
      </p>
      <div className="facts-grid">
        {Object.entries(correlation.module_weights ?? {}).map(([module, weight]) => (
          <Fact key={module} label={`${MODULE_LABEL[module] ?? module} weight`} value={weight} />
        ))}
        <Fact label="Suspicious from" value={correlation.suspicious_threshold} />
        <Fact label="Evil Twin from" value={correlation.evil_twin_threshold} />
      </div>
      {Object.entries(detectors).map(([name, values]) => (
        <section key={name}>
          <h3>{name.replaceAll("_", " ")}</h3>
          <div className="facts-grid">
            {Object.entries(values).map(([key, value]) => (
              <Fact key={key} label={key.replaceAll("_", " ")} value={String(value)} />
            ))}
          </div>
        </section>
      ))}
    </>
  );
}
