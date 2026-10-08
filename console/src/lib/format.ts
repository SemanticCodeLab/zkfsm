export function bytes(n: number | undefined | null): string {
  if (n === undefined || n === null || !isFinite(n)) return "-";
  const units = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
  let i = 0;
  let v = n;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${i === 0 ? v : v.toFixed(v < 10 ? 2 : 1)} ${units[i]}`;
}

export function date(s: string | number | Date | undefined | null): string {
  if (!s) return "-";
  const d = s instanceof Date ? s : new Date(s);
  return isNaN(d.getTime()) ? String(s) : d.toLocaleString();
}

export function duration(sec: number): string {
  const d = Math.floor(sec / 86400);
  const h = Math.floor((sec % 86400) / 3600);
  const m = Math.floor((sec % 3600) / 60);
  if (d) return `${d}d ${h}h`;
  if (h) return `${h}h ${m}m`;
  return `${m}m ${Math.floor(sec % 60)}s`;
}

export function pct(part: number, total: number): number {
  return total > 0 ? Math.min(100, Math.max(0, (part / total) * 100)) : 0;
}

/** Bucket names per the S3 naming rules. */
export function validBucketName(n: string): string | null {
  if (n.length < 3 || n.length > 63) return "Must be 3 to 63 characters.";
  if (!/^[a-z0-9][a-z0-9.-]*[a-z0-9]$/.test(n)) return "Lowercase letters, digits, '.' and '-'; start and end with a letter or digit.";
  if (n.includes("..")) return "No consecutive dots.";
  if (/^\d+\.\d+\.\d+\.\d+$/.test(n)) return "Must not look like an IP address.";
  return null;
}
