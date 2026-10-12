import { describe, expect, it } from "vitest";
import { jobBucket, jobState, labelOf, placeholders, progressRows, stateKind } from "./batch";
import { currentFields, IcebergMetadata, fieldsError, partitionText, snapshotRows, tableBody, typeText, validName } from "./tables";
import { opRows, rekeySummary } from "./kms";
import { lambdaArn } from "./configkv";

describe("batch jobs", () => {
  it("derives the job state", () => {
    expect(jobState(undefined)).toBe("running");
    expect(jobState({ jobID: "a", jobType: "expire" })).toBe("running");
    expect(jobState({ jobID: "a", jobType: "expire", complete: true, status: "complete" })).toBe("complete");
    expect(jobState({ jobID: "a", jobType: "expire", complete: true, failed: true })).toBe("failed");
    expect(stateKind("failed")).toBe("error");
    expect(stateKind("running")).toBe("warn");
  });
  it("lists the counters of the job type", () => {
    const rows = progressRows({ jobID: "a", jobType: "expire", expired: { lastBucket: "b", lastObject: "", objects: 1200, objectsFailed: 0, nested: {} } });
    expect(rows).toEqual([
      ["Last bucket", "b"],
      ["Objects", "1,200"],
      ["Objects failed", "0"],
    ]);
    expect(progressRows({ jobID: "a", jobType: "x" })).toEqual([]);
    expect(labelOf("bytesTransferred")).toBe("Bytes transferred");
  });
  it("reads definitions", () => {
    const yaml = 'expire:\n  apiVersion: v1\n  bucket: BUCKET\n  prefix: PREFIX # optional\n  # bucket: NAME\n  rules:\n    - name: "NAME*"\n';
    expect(jobBucket(yaml)).toBe("BUCKET");
    expect(jobBucket('x:\n  bucket: "logs" # c\n')).toBe("logs");
    expect(jobBucket("x: 1")).toBe("");
    expect(placeholders(yaml)).toEqual(["BUCKET", "PREFIX", "NAME*"]);
    expect(placeholders("expire:\n  bucket: logs\n")).toEqual([]);
  });
});

describe("tables", () => {
  const meta: IcebergMetadata = {
    "current-schema-id": 1,
    schemas: [
      { "schema-id": 0, fields: [{ id: 1, name: "a", type: "long" }] },
      { "schema-id": 1, fields: [{ id: 1, name: "a", type: "long" }, { id: 2, name: "b", type: { type: "list", element: "string" } }] },
    ],
    "default-spec-id": 0,
    "partition-specs": [{ "spec-id": 0, fields: [{ name: "a", transform: "bucket[4]" }] }],
    "current-snapshot-id": 7,
    snapshots: [
      { "snapshot-id": 5, "timestamp-ms": 1000, summary: { operation: "append", "total-records": "3" } },
      { "snapshot-id": 7, "timestamp-ms": 2000, summary: { operation: "overwrite" } },
    ],
  };
  it("validates names and columns", () => {
    expect(validName("sales_2024")).toBeNull();
    expect(validName("Sales")).not.toBeNull();
    expect(validName("a-b")).not.toBeNull();
    expect(fieldsError([{ name: " ", type: "long" }])).toMatch(/at least one/);
    expect(fieldsError([{ name: "a", type: "long" }, { name: "a ", type: "int" }])).toMatch(/unique/);
    expect(fieldsError([{ name: "a", type: "long" }])).toBeNull();
  });
  it("builds the create body", () => {
    expect(tableBody("t", [{ name: " id ", type: "long", required: true }, { name: "", type: "string" }])).toEqual({
      name: "t",
      format: "ICEBERG",
      metadata: { iceberg: { schema: { fields: [{ name: "id", type: "long", required: true }] } } },
    });
  });
  it("reads iceberg metadata", () => {
    expect(currentFields(meta).map((f) => f.name)).toEqual(["a", "b"]);
    expect(currentFields(undefined)).toEqual([]);
    expect(typeText({ type: "list", element: "string" })).toBe("list<string>");
    expect(typeText({ type: "map", key: "string", value: { type: "struct", fields: [1, 2] } })).toBe("map<string, struct<2 fields>>");
    expect(partitionText(meta)).toBe("bucket[4](a)");
    expect(partitionText({})).toBe("unpartitioned");
    const snaps = snapshotRows(meta);
    expect(snaps.map((s) => s.id)).toEqual(["7", "5"]);
    expect(snaps[0].current).toBe(true);
    expect(snaps[1]).toMatchObject({ operation: "append", records: "3", current: false });
  });
});

describe("kms", () => {
  it("keeps called operations, busiest first", () => {
    const rows = opRows({ operations: { list_keys: { requests: 2, errors: 0, latency_sum_us: 3000 }, create_key: { requests: 0, errors: 0, latency_sum_us: 0 }, key_status: { requests: 5, errors: 1, latency_sum_us: 500 } } });
    expect(rows.map((r) => r.name)).toEqual(["key status", "list keys"]);
    expect(rows[1].meanMs).toBe(1.5);
    expect(opRows(undefined)).toEqual([]);
  });
  it("sums re-key pages", () => {
    const s = rekeySummary([
      { scanned: 10, rekeyed: 4, skipped: 6, failed: 0, "first-error": null },
      { scanned: 5, rekeyed: 1, skipped: 3, failed: 1, "first-error": "KeyDisabled" },
    ]);
    expect(s).toEqual({ scanned: 15, rekeyed: 5, skipped: 9, failed: 1, firstError: "KeyDisabled" });
  });
});

describe("lambda targets", () => {
  it("builds the function ARN", () => {
    expect(lambdaArn("fn1")).toBe("arn:minio:s3-object-lambda::fn1:webhook");
    expect(lambdaArn("_")).toBe("arn:minio:s3-object-lambda:::webhook");
  });
});
