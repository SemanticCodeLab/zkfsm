// Hand-written SVG line chart: y axis with nice ticks, time x axis, legend.
import { lerp, linePath, shortNum, yScale } from "./scale";

export interface Series {
  label: string;
  values: (number | null)[];
  color?: number; // 1..4 -> --chart-N
}

const W = 600;
const H = 180;
const PAD = { l: 44, r: 10, t: 10, b: 22 };

function clock(t: number): string {
  const d = new Date(t);
  return `${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}:${String(d.getSeconds()).padStart(2, "0")}`;
}

export function LineChart({ title, times, series, unit = "", format = shortNum }: { title: string; times: number[]; series: Series[]; unit?: string; format?: (v: number) => string }) {
  let max = 0;
  for (const s of series) for (const v of s.values) if (v !== null && Number.isFinite(v) && v > max) max = v;
  const y = yScale(max);
  const n = times.length;
  const x0 = PAD.l;
  const x1 = W - PAD.r;
  const yb = H - PAD.b;
  const xAt = (i: number) => (n <= 1 ? x1 : lerp(i, 0, n - 1, x0, x1));
  const yAt = (v: number) => lerp(v, 0, y.max, yb, PAD.t);
  const latest = series.map((s) => {
    for (let i = s.values.length - 1; i >= 0; i--) if (s.values[i] !== null) return s.values[i] as number;
    return null;
  });
  const summary = series.map((s, i) => `${s.label} ${latest[i] === null ? "no data" : `${format(latest[i]!)}${unit}`}`).join(", ");
  return (
    <figure class="ops-chart">
      <figcaption class="ops-chart-head">
        <span class="ops-chart-title">{title}</span>
        <ul class="ops-legend">
          {series.map((s, i) => (
            <li key={s.label}>
              <span class={`ops-swatch c${s.color ?? i + 1}`} aria-hidden="true" />
              {s.label}
              <strong>{latest[i] === null ? "-" : `${format(latest[i]!)}${unit}`}</strong>
            </li>
          ))}
        </ul>
      </figcaption>
      <svg class="chart" viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none" role="img" aria-label={`${title}: ${n < 2 ? "collecting samples" : `latest ${summary}`}`}>
        {y.ticks.map((t) => (
          <g key={t}>
            <line class="axis ops-grid" x1={x0} x2={x1} y1={yAt(t)} y2={yAt(t)} />
            <text x={x0 - 6} y={yAt(t) + 4} text-anchor="end">
              {format(t)}
            </text>
          </g>
        ))}
        <line class="axis" x1={x0} x2={x0} y1={PAD.t} y2={yb} />
        {n > 1 && (
          <>
            <text x={x0} y={H - 6} text-anchor="start">
              {clock(times[0])}
            </text>
            <text x={x1} y={H - 6} text-anchor="end">
              {clock(times[n - 1])}
            </text>
          </>
        )}
        {series.map((s, i) => (
          <path key={s.label} class={`ops-line c${s.color ?? i + 1}`} d={linePath(s.values.map((v, j) => ({ x: xAt(j), y: v === null ? null : yAt(v) })))} vector-effect="non-scaling-stroke" />
        ))}
        {n < 2 && (
          <text x={W / 2} y={H / 2} text-anchor="middle">
            Collecting samples…
          </text>
        )}
      </svg>
    </figure>
  );
}
