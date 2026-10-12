// S3 Tables: calls through the console's s3tables mount, and Iceberg metadata views.
import { ApiError, CallOpts, json, s3 } from "../../lib/api";

export interface TableBucket {
  arn: string;
  name: string;
  createdAt?: string;
  ownerAccountId?: string;
}
export interface Namespace {
  namespace: string[];
  createdAt?: string;
  createdBy?: string;
}
export interface TableSummary {
  namespace: string[];
  name: string;
  tableARN: string;
  createdAt?: string;
  modifiedAt?: string;
}
export interface TableInfo extends TableSummary {
  versionToken: string;
  metadataLocation?: string;
  warehouseLocation?: string;
  createdBy?: string;
  modifiedBy?: string;
  format?: string;
}
export interface SchemaField {
  id?: number;
  name: string;
  type: unknown;
  required?: boolean;
  doc?: string;
}
export interface IcebergMetadata {
  "format-version"?: number;
  "table-uuid"?: string;
  location?: string;
  "current-schema-id"?: number;
  schemas?: { "schema-id"?: number; fields?: SchemaField[] }[];
  "current-snapshot-id"?: number;
  snapshots?: { "snapshot-id": number; "timestamp-ms"?: number; summary?: Record<string, string>; "manifest-list"?: string }[];
  "partition-specs"?: { "spec-id"?: number; fields?: { name: string; transform: string }[] }[];
  "default-spec-id"?: number;
  properties?: Record<string, string>;
}

const seg = encodeURIComponent;

/** Control-plane call; the server answers errors as `{"message": ...}`. */
export async function tables<T = unknown>(path: string, opts: CallOpts = {}): Promise<T> {
  const headers = opts.body ? { "content-type": "application/json", ...(opts.headers || {}) } : opts.headers;
  return json<T>(`/api/v1/tables${path}`, { ...opts, headers });
}

export const api = {
  buckets: async () => (await tables<{ tableBuckets: TableBucket[] }>("/buckets")).tableBuckets ?? [],
  createBucket: (name: string) => tables("/buckets", { method: "PUT", body: JSON.stringify({ name }) }),
  deleteBucket: (b: string) => tables(`/buckets/${seg(b)}`, { method: "DELETE" }),
  namespaces: async (b: string) => (await tables<{ namespaces: Namespace[] }>(`/namespaces/${seg(b)}`)).namespaces ?? [],
  createNamespace: (b: string, ns: string) => tables(`/namespaces/${seg(b)}`, { method: "PUT", body: JSON.stringify({ namespace: [ns] }) }),
  deleteNamespace: (b: string, ns: string) => tables(`/namespaces/${seg(b)}/${seg(ns)}`, { method: "DELETE" }),
  tables: async (b: string) => (await tables<{ tables: TableSummary[] }>(`/tables/${seg(b)}`)).tables ?? [],
  table: (b: string, ns: string, t: string) => tables<TableInfo>(`/tables/${seg(b)}/${seg(ns)}/${seg(t)}`),
  createTable: (b: string, ns: string, name: string, fields: SchemaField[]) => tables(`/tables/${seg(b)}/${seg(ns)}`, { method: "PUT", body: JSON.stringify(tableBody(name, fields)) }),
  deleteTable: (b: string, ns: string, t: string) => tables(`/tables/${seg(b)}/${seg(ns)}/${seg(t)}`, { method: "DELETE" }),
  policy: async (b: string) => {
    try {
      return (await tables<{ resourcePolicy: string }>(`/buckets/${seg(b)}/policy`)).resourcePolicy;
    } catch (e) {
      if (e instanceof ApiError && e.status === 404) return "";
      throw e;
    }
  },
  putPolicy: (b: string, doc: string) => tables(`/buckets/${seg(b)}/policy`, { method: "PUT", body: JSON.stringify({ resourcePolicy: doc }) }),
  deletePolicy: (b: string) => tables(`/buckets/${seg(b)}/policy`, { method: "DELETE" }),
  /** Current metadata through the Iceberg REST catalog. */
  metadata: async (b: string, ns: string, t: string) => {
    const res = await s3(`/iceberg/v1/${seg(b)}/namespaces/${seg(ns)}/tables/${seg(t)}`);
    return (JSON.parse(await res.text()) as { metadata: IcebergMetadata }).metadata;
  },
};

/** Namespace and table names: lowercase letters, digits and underscores. */
export function validName(n: string): string | null {
  if (!n) return null;
  if (n.length > 255) return "At most 255 characters.";
  return /^[a-z0-9_]+$/.test(n) ? null : "Lowercase letters, digits and '_' only.";
}

export const primitiveTypes = ["boolean", "int", "long", "float", "double", "decimal(38,10)", "date", "time", "timestamp", "timestamptz", "string", "uuid", "binary"];

export function tableBody(name: string, fields: SchemaField[]) {
  return {
    name,
    format: "ICEBERG",
    metadata: { iceberg: { schema: { fields: fields.filter((f) => f.name.trim()).map((f) => ({ name: f.name.trim(), type: f.type, required: !!f.required })) } } },
  };
}

/** Why the column list cannot be sent, or null. */
export function fieldsError(fields: SchemaField[]): string | null {
  const names = fields.map((f) => f.name.trim()).filter(Boolean);
  if (!names.length) return "Add at least one column.";
  return new Set(names).size === names.length ? null : "Column names must be unique.";
}

/** Iceberg type as text; nested types are summarised. */
export function typeText(t: unknown): string {
  if (typeof t === "string") return t;
  if (t && typeof t === "object") {
    const o = t as { type?: string; element?: unknown; key?: unknown; value?: unknown; fields?: unknown[] };
    if (o.type === "list") return `list<${typeText(o.element)}>`;
    if (o.type === "map") return `map<${typeText(o.key)}, ${typeText(o.value)}>`;
    if (o.type === "struct") return `struct<${(o.fields ?? []).length} fields>`;
    return o.type ?? "?";
  }
  return "?";
}

export function currentFields(m: IcebergMetadata | undefined): SchemaField[] {
  const schemas = m?.schemas ?? [];
  return (schemas.find((s) => s["schema-id"] === m?.["current-schema-id"]) ?? schemas[schemas.length - 1])?.fields ?? [];
}

export function partitionText(m: IcebergMetadata | undefined): string {
  const specs = m?.["partition-specs"] ?? [];
  const spec = specs.find((s) => s["spec-id"] === m?.["default-spec-id"]) ?? specs[specs.length - 1];
  const f = spec?.fields ?? [];
  return f.length ? f.map((x) => `${x.transform}(${x.name})`).join(", ") : "unpartitioned";
}

/** Snapshots, newest first. */
export function snapshotRows(m: IcebergMetadata | undefined) {
  return [...(m?.snapshots ?? [])]
    .sort((a, b) => (b["timestamp-ms"] ?? 0) - (a["timestamp-ms"] ?? 0))
    .map((s) => ({
      id: String(s["snapshot-id"]),
      time: s["timestamp-ms"] ? new Date(s["timestamp-ms"]).toISOString() : "",
      operation: s.summary?.operation ?? "-",
      records: s.summary?.["total-records"] ?? "-",
      current: s["snapshot-id"] === m?.["current-snapshot-id"],
    }));
}
