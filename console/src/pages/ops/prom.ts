// Prometheus text exposition parser and the rate math used by the live charts.

export interface Sample {
  name: string;
  labels: Record<string, string>;
  value: number;
}

export interface Family {
  name: string;
  type: string;
  help: string;
  samples: Sample[];
}

function parseValue(s: string): number {
  if (s === "+Inf" || s === "Inf") return Infinity;
  if (s === "-Inf") return -Infinity;
  if (s === "NaN") return NaN;
  return Number(s);
}

function parseLabels(s: string): Record<string, string> {
  const out: Record<string, string> = {};
  const re = /\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*"((?:[^"\\]|\\.)*)"\s*,?/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(s))) out[m[1]] = m[2].replace(/\\(.)/g, (_, c) => (c === "n" ? "\n" : c));
  return out;
}

/** Parses the text format into samples; malformed lines are skipped. */
export function parseSamples(text: string): Sample[] {
  const out: Sample[] = [];
  for (const raw of text.split("\n")) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const m = /^([a-zA-Z_:][a-zA-Z0-9_:]*)(\{(.*)\})?\s+(\S+)/.exec(line);
    if (!m) continue;
    const value = parseValue(m[4]);
    if (Number.isNaN(value) && m[4] !== "NaN") continue;
    out.push({ name: m[1], labels: m[3] ? parseLabels(m[3]) : {}, value });
  }
  return out;
}

const suffixes = ["_bucket", "_sum", "_count"];

/** Groups samples into families using the # TYPE / # HELP comments. */
export function parseFamilies(text: string): Family[] {
  const fams = new Map<string, Family>();
  const get = (name: string) => {
    let f = fams.get(name);
    if (!f) fams.set(name, (f = { name, type: "untyped", help: "", samples: [] }));
    return f;
  };
  for (const raw of text.split("\n")) {
    const m = /^#\s*(TYPE|HELP)\s+(\S+)\s*(.*)$/.exec(raw.trim());
    if (m) {
      const f = get(m[2]);
      if (m[1] === "TYPE") f.type = m[3].trim();
      else f.help = m[3].trim();
    }
  }
  for (const s of parseSamples(text)) {
    let fam = fams.get(s.name);
    if (!fam) {
      const base = suffixes.find((x) => s.name.endsWith(x));
      const parent = base && fams.get(s.name.slice(0, -base.length));
      fam = parent && (parent.type === "histogram" || parent.type === "summary") ? parent : get(s.name);
    }
    fam.samples.push(s);
  }
  return [...fams.values()];
}

/** Sum of every sample named `name` whose labels match `where`. */
export function total(samples: Sample[], name: string, where: Record<string, string> = {}): number {
  let sum = 0;
  for (const s of samples) {
    if (s.name !== name) continue;
    if (Object.entries(where).every(([k, v]) => s.labels[k] === v)) sum += s.value;
  }
  return sum;
}

/** Per-second rate of a counter; a reset (cur < prev) counts from zero. */
export function rate(prev: number, cur: number, seconds: number): number {
  if (!(seconds > 0)) return 0;
  const d = cur >= prev ? cur - prev : cur;
  return d / seconds;
}

/** Mean latency over an interval from histogram _sum/_count deltas, in seconds. */
export function avgLatency(prevSum: number, prevCount: number, sum: number, count: number): number | null {
  const dc = count >= prevCount ? count - prevCount : count;
  const ds = sum >= prevSum && count >= prevCount ? sum - prevSum : sum;
  return dc > 0 ? ds / dc : null;
}

export interface Snapshot {
  t: number; // ms
  samples: Sample[];
}

export const statusClasses = ["2xx", "3xx", "4xx", "5xx"] as const;

export interface Point {
  t: number;
  rates: Record<string, number>;
  inflight: number;
  latencyMs: number | null;
}

const REQ = "zkfsm_requests_total";
const DUR = "zkfsm_request_duration_seconds";

/** One chart point from two consecutive snapshots. */
export function derive(prev: Snapshot, cur: Snapshot): Point {
  const dt = (cur.t - prev.t) / 1000;
  const rates: Record<string, number> = {};
  for (const c of statusClasses) rates[c] = rate(total(prev.samples, REQ, { code: c }), total(cur.samples, REQ, { code: c }), dt);
  const lat = avgLatency(total(prev.samples, `${DUR}_sum`), total(prev.samples, `${DUR}_count`), total(cur.samples, `${DUR}_sum`), total(cur.samples, `${DUR}_count`));
  return { t: cur.t, rates, inflight: total(cur.samples, "zkfsm_requests_inflight"), latencyMs: lat === null ? null : lat * 1000 };
}

/** Appends `p`, keeping at most `max` points. */
export function pushBounded<T>(list: T[], p: T, max: number): T[] {
  const out = [...list, p];
  return out.length > max ? out.slice(out.length - max) : out;
}

export function labelText(labels: Record<string, string>): string {
  const e = Object.entries(labels);
  return e.length ? `{${e.map(([k, v]) => `${k}="${v}"`).join(",")}}` : "";
}
