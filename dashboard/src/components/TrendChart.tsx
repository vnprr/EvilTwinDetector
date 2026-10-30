import { CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import type { MetricSample } from "../api/types";
import { clock, dateTime } from "../lib/format";

type Series = "avg_rssi_dbm" | "clock_skew_ppm";

export function TrendChart({
  title,
  unit,
  samples,
  series,
  color,
  decimals = 0,
}: {
  title: string;
  unit: string;
  samples: MetricSample[];
  series: Series;
  color: string;
  decimals?: number;
}) {
  const points = samples.filter((sample) => sample[series] != null);
  if (points.length < 2) {
    return (
      <p className="muted small">
        {title}: not enough history yet ({points.length} sample{points.length === 1 ? "" : "s"}).
      </p>
    );
  }
  return (
    <figure className="trend">
      <figcaption>
        {title} <span className="muted">({unit})</span>
      </figcaption>
      <ResponsiveContainer width="100%" height={130}>
        <LineChart data={points} margin={{ top: 4, right: 8, bottom: 0, left: -12 }}>
          <CartesianGrid strokeDasharray="3 3" vertical={false} />
          <XAxis dataKey="observed_at" tickFormatter={clock} tick={{ fontSize: 10 }} minTickGap={40} />
          <YAxis
            tick={{ fontSize: 10 }}
            width={58}
            domain={["auto", "auto"]}
            tickFormatter={(value: number) => value.toFixed(decimals)}
          />
          <Tooltip labelFormatter={(value) => dateTime(Number(value))} />
          <Line type="monotone" dataKey={series} stroke={color} dot={false} strokeWidth={2} isAnimationActive={false} />
        </LineChart>
      </ResponsiveContainer>
    </figure>
  );
}
