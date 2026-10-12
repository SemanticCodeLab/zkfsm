// Shared bits for the operations pages.
import { ComponentChildren } from "preact";
import { ApiError, ClusterInfo } from "../../lib/api";

/** Live /api/v1/cluster fields not yet in the shared ClusterInfo type. */
export type ClusterInfoX = Omit<ClusterInfo, "heal" | "drives"> & {
  drives: (ClusterInfo["drives"][number] & { set?: number })[];
  heal: { running: boolean; lastScan: string | null; passes?: number; scanned: number; healed: number; failed: number; lost?: number } | null;
};

/** The server does not implement or has not configured this feature. */
export function isUnavailable(e: unknown): boolean {
  return e instanceof ApiError && (e.status === 501 || e.status === 404 || e.code === "NotImplemented" || /NotConfigured$/.test(e.code));
}

export function errText(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

export function Unavailable({ title, children }: { title: string; children?: ComponentChildren }) {
  return (
    <div class="notice" role="note">
      <strong>{title}</strong>
      {children && <div class="ops-note-body">{children}</div>}
    </div>
  );
}

export function driveKind(state: string): "ok" | "warn" | "error" {
  return state === "ok" ? "ok" : state === "offline" || state === "missing" ? "error" : "warn";
}
