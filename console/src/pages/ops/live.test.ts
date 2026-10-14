import { afterEach, describe, expect, it, vi } from "vitest";
import { atLeast, follow, LineSplitter, parseLog, parseTrace, Ring, traceQuery } from "./live";
import { drainProgress, poolState, PoolStatus, poolUsed, rebalanceRunning, rebalanceState } from "./pools";

describe("bounded ring", () => {
  it("drops the oldest entries past capacity", () => {
    const r = new Ring<number>(3);
    r.push(1, 2);
    r.push(3, 4, 5);
    expect(r.toArray()).toEqual([3, 4, 5]);
    expect(r.dropped).toBe(2);
    r.clear();
    expect(r.size).toBe(0);
    expect(r.dropped).toBe(0);
  });
});

describe("line splitter", () => {
  it("joins partial chunks and skips keep-alive whitespace", () => {
    const s = new LineSplitter();
    expect(s.feed('{"a":')).toEqual([]);
    expect(s.feed('1}\n  \n {"b":2}')).toEqual(['{"a":1}']);
    expect(s.feed("\n ")).toEqual(['{"b":2}']);
  });
});

describe("trace", () => {
  it("builds the server-side filter query", () => {
    expect(traceQuery({ types: [], errorsOnly: false, thresholdMs: 0 })).toEqual({ s3: "true" });
    expect(traceQuery({ types: ["s3", "storage"], errorsOnly: true, thresholdMs: 250 })).toEqual({ s3: "true", storage: "true", err: "true", threshold: "250ms" });
  });
  it("keeps summary fields and never headers", () => {
    const line = JSON.stringify({
      type: 4,
      nodename: "n1",
      funcname: "s3.PutObject",
      time: "2026-10-14T10:00:00.5Z",
      path: "/b/k",
      dur: 2_500_000,
      http: { request: { method: "PUT", headers: { Authorization: ["secret"] } }, response: { statuscode: 200 } },
    });
    const r = parseTrace(line)!;
    expect(r).toMatchObject({ type: "S3", api: "s3.PutObject", method: "PUT", path: "/b/k", status: 200, durMs: 2.5, node: "n1" });
    expect(JSON.stringify(r)).not.toContain("secret");
    expect(parseTrace("not json")).toBeNull();
    expect(parseTrace('{"x":1}')).toBeNull();
  });
  it("reads internal spans without http", () => {
    expect(parseTrace('{"type":2,"funcname":"storage.put","path":"data/ab","dur":1000,"error":"boom"}')).toMatchObject({ type: "Storage", status: 0, error: "boom", durMs: 0.001 });
  });
});

describe("logs", () => {
  it("parses entries and filters by level", () => {
    expect(parseLog('{"level":"WARNING","time":"t","message":"disk slow","node":"n2"}')).toEqual({ level: "WARNING", time: "t", message: "disk slow", node: "n2" });
    expect(parseLog('{"level":"weird","message":"m"}')!.level).toBe("INFO");
    expect(parseLog("{}")).toBeNull();
    expect(atLeast("ERROR", "WARNING")).toBe(true);
    expect(atLeast("INFO", "WARNING")).toBe(false);
    expect(atLeast("DEBUG", "DEBUG")).toBe(true);
  });
});

describe("follow", () => {
  afterEach(() => vi.unstubAllGlobals());
  it("streams lines through the proxy with the session cookie only", async () => {
    const enc = new TextEncoder();
    const body = new ReadableStream({
      start(c) {
        c.enqueue(enc.encode('{"funcname":"a"}\n {"func'));
        c.enqueue(enc.encode('name":"b"}\n'));
        c.close();
      },
    });
    const fetchMock = vi.fn(async () => new Response(body, { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);
    const got: string[] = [];
    await follow("/trace", { s3: "true", err: "true" }, (l) => got.push(...l), new AbortController().signal);
    expect(got).toEqual(['{"funcname":"a"}', '{"funcname":"b"}']);
    const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe("/api/v1/s3/minio/admin/v3/trace?s3=true&err=true");
    expect(init.credentials).toBe("same-origin");
    expect(JSON.stringify(init.headers)).not.toMatch(/authorization|secret/i);
  });
});

const pool = (d: Partial<PoolStatus["decommissionInfo"]>): PoolStatus => ({
  id: 0,
  cmdline: "http://h{1...4}/d{1...4}",
  lastUpdate: "",
  decommissionInfo: { startTime: "0001-01-01T00:00:00Z", startSize: 600, totalSize: 1000, currentSize: 600, complete: false, failed: false, canceled: false, objectsDecommissioned: 0, objectsDecommissionedFailed: 0, bytesDecommissioned: 0, bytesDecommissionedFailed: 0, ...d },
});

describe("pools", () => {
  it("derives state, usage and drain progress", () => {
    expect(poolState(pool({}))).toBe("active");
    expect(poolState(pool({ startTime: "2026-10-14T10:00:00Z" }))).toBe("draining");
    expect(poolState(pool({ startTime: "2026-10-14T10:00:00Z", canceled: true }))).toBe("canceled");
    expect(poolState(pool({ complete: true }))).toBe("decommissioned");
    expect(poolState(pool({ failed: true }))).toBe("failed");
    expect(poolUsed(pool({}))).toBeCloseTo(0.4);
    expect(poolUsed(pool({ totalSize: 0 }))).toBe(0);
    expect(drainProgress(pool({ bytesDecommissioned: 100 }))).toBeCloseTo(0.25);
    expect(drainProgress(pool({ complete: true }))).toBe(1);
  });
  it("reads rebalance status", () => {
    const p = (status: string) => ({ id: 0, status, used: 0.5, progress: { objects: 1, versions: 1, bytes: 1, elapsed: 1, eta: 0 } });
    expect(rebalanceState(null)).toBe("not started");
    expect(rebalanceRunning({ ID: "x", stoppedAt: "0001-01-01T00:00:00Z", pools: [p("Started"), p("")] })).toBe(true);
    expect(rebalanceState({ ID: "x", stoppedAt: "2026-10-14T10:00:00Z", pools: [p("Stopped")] })).toBe("stopped");
    expect(rebalanceState({ ID: "x", stoppedAt: "0001-01-01T00:00:00Z", pools: [p("Completed")] })).toBe("completed");
  });
});
