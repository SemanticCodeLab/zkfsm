// Pool decommission and rebalance: the madmin v4 admin API, read through the proxy.
import { s3 } from "../../lib/api";

export const ADMIN4 = "/minio/admin/v4";

export interface DecomInfo {
  startTime: string;
  startSize: number;
  totalSize: number;
  currentSize: number;
  complete: boolean;
  failed: boolean;
  canceled: boolean;
  objectsDecommissioned: number;
  objectsDecommissionedFailed: number;
  bytesDecommissioned: number;
  bytesDecommissionedFailed: number;
}

export interface PoolStatus {
  id: number;
  cmdline: string;
  lastUpdate: string;
  decommissionInfo: DecomInfo;
}

export interface RebalancePool {
  id: number;
  status: string;
  used: number;
  progress: { objects: number; versions: number; bytes: number; elapsed: number; eta: number; bucket?: string; object?: string };
}

export interface RebalanceStatus {
  ID: string;
  stoppedAt: string;
  pools: RebalancePool[];
}

export type PoolState = "active" | "draining" | "decommissioned" | "failed" | "canceled";

const ZERO = "0001-01-01T00:00:00Z";

/** What the pool is doing, from its decommission record. */
export function poolState(p: PoolStatus): PoolState {
  const d = p.decommissionInfo;
  if (d.complete) return "decommissioned";
  if (d.failed) return "failed";
  if (d.canceled) return "canceled";
  if (d.startTime && d.startTime !== ZERO) return "draining";
  return "active";
}

/** Used fraction 0..1; currentSize is the free space. */
export function poolUsed(p: PoolStatus): number {
  const d = p.decommissionInfo;
  if (!d.totalSize) return 0;
  return Math.min(1, Math.max(0, (d.totalSize - d.currentSize) / d.totalSize));
}

/** Drain progress 0..1: how much of the used space at the start has left. */
export function drainProgress(p: PoolStatus): number {
  const d = p.decommissionInfo;
  if (d.complete) return 1;
  const usedAtStart = d.totalSize - d.startSize;
  if (usedAtStart <= 0) return 0;
  return Math.min(1, Math.max(0, d.bytesDecommissioned / usedAtStart));
}

/** True while a rebalance runs; right after a start no pool has a status yet. */
export function rebalanceRunning(r: RebalanceStatus | null): boolean {
  if (!r || isStopped(r)) return false;
  return r.pools.some((p) => p.status === "Started") || r.pools.every((p) => !p.status);
}

function isStopped(r: RebalanceStatus): boolean {
  return !!r.stoppedAt && r.stoppedAt !== ZERO;
}

/** One-word rebalance state for a badge. */
export function rebalanceState(r: RebalanceStatus | null): string {
  if (!r) return "not started";
  if (rebalanceRunning(r)) return "running";
  const s = r.pools.find((p) => p.status)?.status;
  return (s || "idle").toLowerCase();
}

async function js<T>(path: string, method = "GET", query?: Record<string, string>): Promise<T> {
  const res = await s3(`${ADMIN4}${path}`, { method, query });
  const text = await res.text();
  return (text ? JSON.parse(text) : null) as T;
}

export const pools = {
  list: () => js<PoolStatus[]>("/pools/list"),
  status: (pool: string) => js<PoolStatus>("/pools/status", "GET", { pool }),
  decommission: (pool: string) => js<null>("/pools/decommission", "POST", { pool }),
  cancel: (pool: string) => js<null>("/pools/cancel", "POST", { pool }),
  rebalanceStart: () => js<{ id: string }>("/rebalance/start", "POST"),
  rebalanceStop: () => js<null>("/rebalance/stop", "POST"),
  /** Null when no rebalance has ever run. */
  rebalanceStatus: () =>
    js<RebalanceStatus>("/rebalance/status").catch((e: { code?: string }) => {
      if (e?.code === "XMinioAdminRebalanceNotStarted") return null;
      throw e;
    }),
};
