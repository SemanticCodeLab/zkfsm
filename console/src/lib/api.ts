// Console API client. Every call goes to the console server on the same origin;
// S3 and admin calls go through /api/v1/s3/<path>, signed server-side with the session.

export class ApiError extends Error {
  constructor(
    public status: number,
    public code: string,
    message: string,
  ) {
    super(message);
  }
}

export const CSRF_HEADER = "x-console-csrf";
export const ADMIN = "/minio/admin/v3";
export const KMS = "/minio/kms/v1";

export interface Session {
  user: string;
  accessKey: string;
  expires: string; // ISO time
  provider: string; // "password" | "openid:<name>"
}

export interface LoginMethods {
  password: boolean;
  openid: { name: string; label: string }[];
}

let onUnauthorized: () => void = () => {};
export function setUnauthorizedHandler(fn: () => void) {
  onUnauthorized = fn;
}

export interface CallOpts {
  method?: string;
  query?: Record<string, string | number | boolean | undefined | null>;
  headers?: Record<string, string>;
  body?: BodyInit | null;
  /** Admin bodies the server expects encrypted with the session secret. */
  encrypt?: boolean;
  signal?: AbortSignal;
}

export function qs(query?: CallOpts["query"]): string {
  if (!query) return "";
  const parts: string[] = [];
  for (const [k, v] of Object.entries(query)) {
    if (v === undefined || v === null || v === false) continue;
    parts.push(v === true || v === "" ? encodeURIComponent(k) : `${encodeURIComponent(k)}=${encodeURIComponent(String(v))}`);
  }
  return parts.length ? `?${parts.join("&")}` : "";
}

/** Encodes an object key path, keeping '/' separators. */
export function encodeKey(key: string): string {
  return key.split("/").map(encodeURIComponent).join("/");
}

async function errorFrom(res: Response): Promise<ApiError> {
  const text = await res.text().catch(() => "");
  let code = String(res.status);
  let msg = text || res.statusText;
  const xm = /<Code>([^<]*)<\/Code>[\s\S]*?<Message>([^<]*)<\/Message>/.exec(text);
  if (xm) {
    code = xm[1];
    msg = xm[2];
  } else {
    try {
      const j = JSON.parse(text);
      code = j.Code || j.code || code;
      msg = j.Message || j.message || j.error || msg;
    } catch {
      /* plain text */
    }
  }
  return new ApiError(res.status, code, msg);
}

/** Raw fetch against the console server. Throws ApiError on non-2xx. */
export async function raw(path: string, opts: CallOpts = {}): Promise<Response> {
  const method = opts.method || "GET";
  const headers: Record<string, string> = { ...(opts.headers || {}) };
  if (method !== "GET" && method !== "HEAD") headers[CSRF_HEADER] = "1";
  if (opts.encrypt) headers["x-console-encrypt"] = "1";
  const res = await fetch(path + qs(opts.query), {
    method,
    headers,
    body: opts.body ?? undefined,
    credentials: "same-origin",
    signal: opts.signal,
  });
  if (res.status === 401) onUnauthorized();
  if (!res.ok) throw await errorFrom(res);
  return res;
}

/** S3 or admin call through the signing proxy. `path` starts with '/'. */
export function s3(path: string, opts: CallOpts = {}): Promise<Response> {
  return raw(`/api/v1/s3${path}`, opts);
}

export async function s3Text(path: string, opts: CallOpts = {}): Promise<string> {
  return (await s3(path, opts)).text();
}

export async function s3Xml(path: string, opts: CallOpts = {}): Promise<Document> {
  return new DOMParser().parseFromString(await s3Text(path, opts), "application/xml");
}

/** Admin API JSON call; responses encrypted by the server are decrypted by the proxy. */
export async function admin<T = unknown>(op: string, opts: CallOpts = {}): Promise<T> {
  const res = await s3(`${ADMIN}${op}`, opts);
  const text = await res.text();
  return (text ? JSON.parse(text) : null) as T;
}

export async function json<T = unknown>(path: string, opts: CallOpts = {}): Promise<T> {
  const res = await raw(path, opts);
  const text = await res.text();
  return (text ? JSON.parse(text) : null) as T;
}

export const session = {
  methods: () => json<LoginMethods>("/api/v1/login/methods"),
  current: () => json<Session>("/api/v1/session"),
  login: (accessKey: string, secretKey: string) =>
    json<Session>("/api/v1/login", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ accessKey, secretKey }),
    }),
  logout: () => raw("/api/v1/logout", { method: "POST" }),
  openidStart: (name: string) => `/api/v1/oidc/start?provider=${encodeURIComponent(name)}`,
};

export interface Drive {
  path: string;
  pool: number;
  state: "ok" | "offline" | "missing" | "corrupt" | string;
  totalBytes: number;
  freeBytes: number;
}
export interface ClusterInfo {
  mode: "single" | "cluster";
  protection: string;
  uptimeSeconds: number;
  version: string;
  region: string;
  nodes: { address: string; state: string }[];
  pools: { index: number; drives: number; online: number; setSize: number }[];
  drives: Drive[];
  capacity: { totalBytes: number; freeBytes: number; usedBytes: number };
  usage: { buckets: number; objects: number; bytes: number };
  heal: { running: boolean; lastScan: string | null; scanned: number; healed: number; failed: number } | null;
  features: Record<string, boolean>; // e.g. kms, siteReplication, openid, ldap, tiering, events
}

export const cluster = {
  info: () => json<ClusterInfo>("/api/v1/cluster"),
  /** Prometheus text exposition of the server metrics. */
  metrics: () => raw("/api/v1/metrics").then((r) => r.text()),
};

export function presign(bucket: string, key: string, expiresSeconds: number, versionId?: string) {
  return json<{ url: string; expires: string }>("/api/v1/presign", {
    query: { bucket, key, expires: expiresSeconds, versionId },
  });
}

/** Direct download URL served by the proxy (same origin, uses the session cookie). */
export function downloadUrl(bucket: string, key: string, versionId?: string): string {
  return `/api/v1/s3/${encodeURIComponent(bucket)}/${encodeKey(key)}${qs({ versionId, "x-console-download": "1" })}`;
}
