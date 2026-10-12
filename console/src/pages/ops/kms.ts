// KMS admin helpers: metrics rows, re-key page totals, and saving a text download.

export interface KmsMetrics {
  backend?: string;
  operations?: Record<string, { requests: number; errors: number; latency_sum_us: number }>;
  keys?: { enabled: number; disabled: number };
  reconfigurations?: number;
  rekeyed_objects?: number;
}

export interface OpRow {
  name: string;
  requests: number;
  errors: number;
  meanMs: number | null;
}

/** Operations that were called at least once, busiest first. */
export function opRows(m: KmsMetrics | undefined): OpRow[] {
  return Object.entries(m?.operations ?? {})
    .filter(([, v]) => v.requests > 0)
    .map(([k, v]) => ({ name: k.replace(/_/g, " "), requests: v.requests, errors: v.errors, meanMs: v.requests ? v.latency_sum_us / v.requests / 1000 : null }))
    .sort((a, b) => b.requests - a.requests || a.name.localeCompare(b.name));
}

export interface RekeyPage {
  scanned: number;
  rekeyed: number;
  skipped: number;
  failed: number;
  "first-error"?: string | null;
  truncated?: boolean;
  "next-marker"?: string | null;
  "next-version-marker"?: string | null;
}

export function rekeySummary(pages: RekeyPage[]) {
  const sum = { scanned: 0, rekeyed: 0, skipped: 0, failed: 0, firstError: null as string | null };
  for (const p of pages) {
    sum.scanned += p.scanned || 0;
    sum.rekeyed += p.rekeyed || 0;
    sum.skipped += p.skipped || 0;
    sum.failed += p.failed || 0;
    sum.firstError ??= p["first-error"] || null;
  }
  return sum;
}

/** Offers `text` as a file download (blob URL; allowed by the page CSP). */
export function saveText(name: string, text: string, type = "application/json") {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
