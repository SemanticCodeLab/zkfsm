// Axis scaling for the hand-written SVG charts.

/** A "nice" step (1, 2, 5 x 10^n) close to range / ticks. */
export function niceStep(range: number, ticks: number): number {
  if (!(range > 0) || !(ticks > 0)) return 1;
  const raw = range / ticks;
  const mag = Math.pow(10, Math.floor(Math.log10(raw)));
  const n = raw / mag;
  const f = n <= 1 ? 1 : n <= 2 ? 2 : n <= 5 ? 5 : 10;
  return f * mag;
}

/** Y domain from 0 to a nice maximum covering `max`, plus its ticks. */
export function yScale(max: number, ticks = 4): { max: number; ticks: number[] } {
  const m = Number.isFinite(max) && max > 0 ? max : 1;
  const step = niceStep(m, ticks);
  const top = Math.ceil(m / step - 1e-9) * step;
  const out: number[] = [];
  for (let v = 0; v <= top + step / 2; v += step) out.push(Number(v.toPrecision(12)));
  return { max: top, ticks: out };
}

/** Maps a value from [d0,d1] to [r0,r1]; a zero-width domain maps to r0. */
export function lerp(v: number, d0: number, d1: number, r0: number, r1: number): number {
  return d1 === d0 ? r0 : r0 + ((v - d0) / (d1 - d0)) * (r1 - r0);
}

export interface XY {
  x: number;
  y: number | null;
}

/** SVG path data; null values break the line into segments. */
export function linePath(points: XY[]): string {
  let d = "";
  let pen = false;
  for (const p of points) {
    if (p.y === null || !Number.isFinite(p.y)) {
      pen = false;
      continue;
    }
    d += `${pen ? "L" : "M"}${p.x.toFixed(1)},${p.y.toFixed(1)}`;
    pen = true;
  }
  return d;
}

/** Compact tick label: 1.5k, 2M, 0.25. */
export function shortNum(v: number): string {
  const a = Math.abs(v);
  if (a >= 1e9) return `${+(v / 1e9).toFixed(1)}G`;
  if (a >= 1e6) return `${+(v / 1e6).toFixed(1)}M`;
  if (a >= 1e3) return `${+(v / 1e3).toFixed(1)}k`;
  if (a === 0) return "0";
  if (a < 0.01) return v.toExponential(0);
  return `${+v.toFixed(2)}`;
}
