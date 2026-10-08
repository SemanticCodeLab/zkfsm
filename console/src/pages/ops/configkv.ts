// The admin config-kv line format: `subsys[:id] key=value key="v w" ...`.

export interface KvEntry {
  subsys: string;
  id: string; // "_" when the target has no id
  kvs: [string, string][];
}

export const DEFAULT_ID = "_";

function unquote(v: string): string {
  return v.length >= 2 && v.startsWith('"') && v.endsWith('"') ? v.slice(1, -1) : v;
}

/** Parses one line; values may be quoted and contain spaces. */
export function parseLine(line: string): KvEntry | null {
  const t = line.trim();
  if (!t || t.startsWith("#")) return null;
  const sp = t.search(/\s/);
  const head = sp < 0 ? t : t.slice(0, sp);
  const rest = sp < 0 ? "" : t.slice(sp);
  const c = head.indexOf(":");
  const entry: KvEntry = { subsys: c < 0 ? head : head.slice(0, c), id: c < 0 ? DEFAULT_ID : head.slice(c + 1), kvs: [] };
  const re = /\s+([A-Za-z0-9_]+)=("(?:[^"]*)"|\S*)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(rest))) entry.kvs.push([m[1], unquote(m[2])]);
  return entry;
}

export function parseConfig(text: string): KvEntry[] {
  return text
    .split("\n")
    .map(parseLine)
    .filter((e): e is KvEntry => e !== null);
}

/** Target name as written in a config line. */
export function targetKey(subsys: string, id: string): string {
  return id && id !== DEFAULT_ID ? `${subsys}:${id}` : subsys;
}

export function formatValue(v: string): string {
  return v === "" || /[\s"]/.test(v) ? `"${v.replace(/"/g, "")}"` : v;
}

/** Renders a line; empty values are dropped unless `keepEmpty`. */
export function formatLine(e: KvEntry, keepEmpty = false): string {
  const parts = [targetKey(e.subsys, e.id)];
  for (const [k, v] of e.kvs) if (keepEmpty || v !== "") parts.push(`${k}=${formatValue(v)}`);
  return parts.join(" ");
}

export function get(e: KvEntry, key: string): string {
  return e.kvs.find(([k]) => k === key)?.[1] ?? "";
}

export function enabled(e: KvEntry): boolean {
  const v = get(e, "enable");
  return v === "" || v === "on" || v === "true";
}

/** True for the placeholder the server returns for an unconfigured subsystem. */
export function isPlaceholder(e: KvEntry): boolean {
  return e.id === DEFAULT_ID && !enabled(e) && e.kvs.every(([k, v]) => k === "enable" || v === "");
}

/** Notification ARN as the server builds it; audit targets have none. */
export function arnFor(region: string, id: string, arnType: string): string {
  return arnType ? `arn:minio:sqs:${region}:${id}:${arnType}` : "";
}

export const validId = (id: string) => /^[A-Za-z0-9_.-]{1,64}$/.test(id);

/** Target kinds the server supports (src/events/kinds.zig). */
export const targetKinds: { type: string; arn: string; label: string }[] = [
  { type: "webhook", arn: "webhook", label: "Webhook" },
  { type: "kafka", arn: "kafka", label: "Kafka" },
  { type: "amqp", arn: "amqp", label: "AMQP" },
  { type: "mqtt", arn: "mqtt", label: "MQTT" },
  { type: "nats", arn: "nats", label: "NATS" },
  { type: "nsq", arn: "nsq", label: "NSQ" },
  { type: "redis", arn: "redis", label: "Redis" },
  { type: "postgres", arn: "postgresql", label: "PostgreSQL" },
  { type: "mysql", arn: "mysql", label: "MySQL" },
  { type: "elasticsearch", arn: "elasticsearch", label: "Elasticsearch" },
  { type: "pulsar", arn: "pulsar", label: "Pulsar" },
];

const secretKeys = new Set(["password", "sasl_password", "auth_token", "token", "client_key", "client_tls_key", "connection_string", "dsn_string", "url", "secret_key"]);
export const isSecretKey = (k: string) => secretKeys.has(k);
