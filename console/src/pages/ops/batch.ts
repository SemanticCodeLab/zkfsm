// Batch job status shapes (the admin status-job reply) reduced to table rows.

export interface JobItem {
  id: string;
  type: string;
  user?: string;
  started?: string;
  elapsed?: number; // nanoseconds
}

export interface JobMetric {
  jobID: string;
  jobType: string;
  startTime?: string;
  lastUpdate?: string;
  retryAttempts?: number;
  complete?: boolean;
  failed?: boolean;
  status?: string;
  replicate?: Record<string, unknown>;
  keyrotate?: Record<string, unknown>;
  expired?: Record<string, unknown>;
}

export type JobState = "running" | "complete" | "failed";

export function jobState(m: JobMetric | undefined): JobState {
  if (!m) return "running";
  if (m.failed || m.status === "failed") return "failed";
  return m.complete || m.status === "complete" ? "complete" : "running";
}

export const stateKind = (s: JobState): "ok" | "warn" | "error" => (s === "complete" ? "ok" : s === "failed" ? "error" : "warn");

/** "objectsFailed" -> "Objects failed". */
export function labelOf(key: string): string {
  const words = key.replace(/([a-z0-9])([A-Z])/g, "$1 $2").toLowerCase();
  return words.charAt(0).toUpperCase() + words.slice(1);
}

/** Progress counters of whichever job type the metric carries. */
export function progressRows(m: JobMetric): [string, string][] {
  const detail = m.replicate ?? m.keyrotate ?? m.expired ?? {};
  const rows: [string, string][] = [];
  for (const [k, v] of Object.entries(detail)) {
    if (v === null || v === undefined || v === "" || typeof v === "object") continue;
    rows.push([labelOf(k), typeof v === "number" ? v.toLocaleString("en-US") : String(v)]);
  }
  return rows;
}

/** Bucket named in a job definition, for the list (first `bucket:` line). */
export function jobBucket(yaml: string): string {
  const m = /^\s*bucket:\s*("?)([^"#\n]+?)\1\s*(#.*)?$/m.exec(yaml);
  return m ? m[2].trim() : "";
}

/** Template placeholders left in a definition, which the server would reject or misread. */
export function placeholders(yaml: string): string[] {
  const found = new Set<string>();
  for (const line of yaml.split("\n")) {
    if (/^\s*#/.test(line)) continue;
    const m = /:\s*"?(BUCKET|PREFIX|NAME\*?|ACCESS-KEY|SECRET-KEY|ENDPOINT|KEY-ID)"?\s*(#.*)?$/.exec(line);
    if (m) found.add(m[1]);
  }
  return [...found];
}
