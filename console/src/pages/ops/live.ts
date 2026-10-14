// Live admin streams (trace, server log): newline-delimited JSON read through the
// console proxy, which signs with the session; the browser holds no credentials.
import { ADMIN, s3 } from "../../lib/api";

/** madmin trace type bits. */
export const TRACE_TYPES: [string, string, number][] = [
  ["s3", "S3", 1 << 2],
  ["internal", "Internal", 1 << 3],
  ["storage", "Storage", 1 << 1],
  ["os", "OS", 1 << 0],
  ["scanner", "Scanner", 1 << 4],
  ["healing", "Healing", 1 << 6],
  ["ilm", "ILM", 1 << 14],
  ["kms", "KMS", 1 << 15],
  ["batch-replication", "Batch replication", 1 << 7],
  ["batch-keyrotation", "Batch key rotation", 1 << 8],
  ["batch-expire", "Batch expire", 1 << 9],
  ["replication-resync", "Replication resync", 1 << 11],
  ["ftp", "FTP", 1 << 13],
];

export function typeName(bit: number): string {
  return TRACE_TYPES.find((t) => t[2] === bit)?.[1] ?? String(bit);
}

/** Fixed-capacity buffer: the oldest entries drop first. */
export class Ring<T> {
  private items: T[] = [];
  dropped = 0;
  constructor(public readonly cap: number) {}
  push(...xs: T[]) {
    this.items.push(...xs);
    const over = this.items.length - this.cap;
    if (over > 0) {
      this.items.splice(0, over);
      this.dropped += over;
    }
  }
  clear() {
    this.items = [];
    this.dropped = 0;
  }
  get size() {
    return this.items.length;
  }
  toArray(): T[] {
    return this.items.slice();
  }
}

/** Splits a chunked byte stream into complete trimmed lines; keeps the tail. */
export class LineSplitter {
  private rest = "";
  feed(chunk: string): string[] {
    const parts = (this.rest + chunk).split("\n");
    this.rest = parts.pop() ?? "";
    return parts.map((l) => l.trim()).filter(Boolean);
  }
}

export interface TraceFilter {
  types: string[];
  errorsOnly: boolean;
  /** Minimum duration in milliseconds; 0 for all. */
  thresholdMs: number;
}

export function traceQuery(f: TraceFilter): Record<string, string> {
  const q: Record<string, string> = {};
  for (const t of f.types.length ? f.types : ["s3"]) q[t] = "true";
  if (f.errorsOnly) q.err = "true";
  if (f.thresholdMs > 0) q.threshold = `${f.thresholdMs}ms`;
  return q;
}

export interface TraceRow {
  time: string;
  type: string;
  node: string;
  api: string;
  method: string;
  path: string;
  status: number;
  durMs: number;
  error: string;
}

/** Reduces a madmin TraceInfo to display fields; headers are never kept. */
export function parseTrace(line: string): TraceRow | null {
  let t: Record<string, any>;
  try {
    t = JSON.parse(line);
  } catch {
    return null;
  }
  if (!t || typeof t !== "object" || !("funcname" in t)) return null;
  const req = t.http?.request ?? {};
  const status = Number(t.http?.response?.statuscode ?? 0);
  return {
    time: String(t.time ?? ""),
    type: typeName(Number(t.type)),
    node: String(t.nodename ?? ""),
    api: String(t.funcname ?? ""),
    method: String(req.method ?? ""),
    path: String(t.path ?? ""),
    status,
    durMs: Number(t.dur ?? 0) / 1e6,
    error: String(t.error ?? ""),
  };
}

export const LOG_LEVELS = ["ERROR", "WARNING", "INFO", "DEBUG"] as const;
export type LogLevel = (typeof LOG_LEVELS)[number];

export interface LogRow {
  time: string;
  level: LogLevel;
  node: string;
  message: string;
}

export function parseLog(line: string): LogRow | null {
  let t: Record<string, any>;
  try {
    t = JSON.parse(line);
  } catch {
    return null;
  }
  if (!t || typeof t !== "object" || typeof t.message !== "string") return null;
  const lv = String(t.level ?? "INFO").toUpperCase();
  return { time: String(t.time ?? ""), level: (LOG_LEVELS as readonly string[]).includes(lv) ? (lv as LogLevel) : "INFO", node: String(t.node ?? ""), message: t.message };
}

/** True when `level` is at least as severe as `min`. */
export function atLeast(level: LogLevel, min: LogLevel): boolean {
  return LOG_LEVELS.indexOf(level) <= LOG_LEVELS.indexOf(min);
}

/**
 * Reads an admin stream until `signal` aborts, calling `onLines` per chunk.
 * Resolves when the stream ends; rejects on HTTP errors.
 */
export async function follow(op: string, query: Record<string, string>, onLines: (lines: string[]) => void, signal: AbortSignal): Promise<void> {
  const res = await s3(`${ADMIN}${op}`, { query, signal });
  const reader = res.body?.getReader();
  if (!reader) return;
  const dec = new TextDecoder();
  const split = new LineSplitter();
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      const lines = split.feed(dec.decode(value, { stream: true }));
      if (lines.length) onLines(lines);
    }
  } catch (e) {
    if (!signal.aborted) throw e;
  }
}
