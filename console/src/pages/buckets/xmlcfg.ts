// Pure builders/parsers for bucket configuration XML documents.
import { doc, XmlObj } from "../../lib/xml";

// Local DOM helpers: the shared ones rely on `instanceof Document` and
// getElementsByTagNameNS("*"), which happy-dom does not support.
type Node_ = Element | Document | null | undefined;
export function root(d: Node_): Element | null {
  if (!d) return null;
  return d.nodeType === 9 ? (d as Document).documentElement : (d as Element);
}
export function children(d: Node_, name: string): Element[] {
  const r = root(d);
  return r ? Array.from(r.children).filter((c) => c.localName === name) : [];
}
export function all(d: Node_, name: string): Element[] {
  const r = root(d);
  return r ? Array.from(r.getElementsByTagName("*")).filter((c) => c.localName === name) : [];
}
export function text(d: Node_, name: string): string {
  return children(d, name)[0]?.textContent ?? "";
}
export function parseTagSet(d: Node_): Record<string, string> {
  const out: Record<string, string> = {};
  for (const t of all(d, "Tag")) out[text(t, "Key")] = text(t, "Value");
  return out;
}


export function parseXml(s: string): Document {
  return new DOMParser().parseFromString(s, "application/xml");
}

function child(el: Element | Document | null | undefined, name: string): Element | null {
  if (!el) return null;
  return children(el, name)[0] ?? null;
}

function num(s: string): number | undefined {
  if (s.trim() === "") return undefined;
  const n = Number(s);
  return isFinite(n) ? n : undefined;
}

export type Tags = [string, string][];

function tagsOf(el: Element | null): Tags {
  if (!el) return [];
  return all(el, "Tag").map((t) => [text(t, "Key"), text(t, "Value")] as [string, string]);
}

/** Filter element shared by lifecycle and replication: Prefix, single Tag, or And. */
function filterObj(prefix: string, tags: Tags): XmlObj {
  const tagEls = tags.map(([Key, Value]) => ({ Key, Value }));
  if (tags.length === 0) return { Prefix: prefix };
  if (tags.length === 1 && !prefix) return { Tag: tagEls[0] };
  return { And: { Prefix: prefix || undefined, Tag: tagEls } };
}

function parseFilter(rule: Element): { prefix: string; tags: Tags } {
  const f = child(rule, "Filter");
  if (!f) return { prefix: text(rule, "Prefix"), tags: [] };
  const scope = child(f, "And") ?? f;
  return { prefix: text(scope, "Prefix"), tags: tagsOf(scope) };
}

// ---- lifecycle ----

export interface LifecycleRule {
  id: string;
  enabled: boolean;
  prefix: string;
  tags: Tags;
  expirationDays?: number;
  expiredDeleteMarker?: boolean;
  noncurrentDays?: number;
  newerNoncurrent?: number;
  abortDays?: number;
  transitionDays?: number;
  transitionTier?: string;
  noncurrentTransitionDays?: number;
  noncurrentTransitionTier?: string;
}

export function emptyLifecycleRule(): LifecycleRule {
  return { id: "", enabled: true, prefix: "", tags: [] };
}

export function lifecycleXml(rules: LifecycleRule[]): string {
  return doc("LifecycleConfiguration", {
    Rule: rules.map((r) => ({
      ID: r.id || undefined,
      Filter: filterObj(r.prefix, r.tags),
      Status: r.enabled ? "Enabled" : "Disabled",
      Transition: r.transitionTier && r.transitionDays !== undefined ? { Days: r.transitionDays, StorageClass: r.transitionTier } : undefined,
      NoncurrentVersionTransition:
        r.noncurrentTransitionTier && r.noncurrentTransitionDays !== undefined ? { NoncurrentDays: r.noncurrentTransitionDays, StorageClass: r.noncurrentTransitionTier } : undefined,
      Expiration:
        r.expirationDays !== undefined || r.expiredDeleteMarker
          ? { Days: r.expirationDays, ExpiredObjectDeleteMarker: r.expiredDeleteMarker && r.expirationDays === undefined ? "true" : undefined }
          : undefined,
      NoncurrentVersionExpiration: r.noncurrentDays !== undefined ? { NoncurrentDays: r.noncurrentDays, NewerNoncurrentVersions: r.newerNoncurrent } : undefined,
      AbortIncompleteMultipartUpload: r.abortDays !== undefined ? { DaysAfterInitiation: r.abortDays } : undefined,
    })),
  });
}

export function parseLifecycle(d: Document): LifecycleRule[] {
  return children(d, "Rule").map((r) => {
    const { prefix, tags } = parseFilter(r);
    const exp = child(r, "Expiration");
    const nve = child(r, "NoncurrentVersionExpiration");
    const ab = child(r, "AbortIncompleteMultipartUpload");
    const tr = child(r, "Transition");
    const ntr = child(r, "NoncurrentVersionTransition");
    return {
      id: text(r, "ID"),
      enabled: text(r, "Status") === "Enabled",
      prefix,
      tags,
      expirationDays: exp ? num(text(exp, "Days")) : undefined,
      expiredDeleteMarker: exp ? text(exp, "ExpiredObjectDeleteMarker") === "true" || undefined : undefined,
      noncurrentDays: nve ? num(text(nve, "NoncurrentDays")) : undefined,
      newerNoncurrent: nve ? num(text(nve, "NewerNoncurrentVersions")) : undefined,
      abortDays: ab ? num(text(ab, "DaysAfterInitiation")) : undefined,
      transitionDays: tr ? num(text(tr, "Days")) : undefined,
      transitionTier: tr ? text(tr, "StorageClass") || undefined : undefined,
      noncurrentTransitionDays: ntr ? num(text(ntr, "NoncurrentDays")) : undefined,
      noncurrentTransitionTier: ntr ? text(ntr, "StorageClass") || undefined : undefined,
    };
  });
}

// ---- replication ----

export interface ReplicationRule {
  id: string;
  enabled: boolean;
  priority: number;
  prefix: string;
  tags: Tags;
  destArn: string;
  storageClass: string;
  deleteMarkers: boolean;
  deletes: boolean;
  existing: boolean;
}

const st = (b: boolean) => ({ Status: b ? "Enabled" : "Disabled" });

export function replicationXml(rules: ReplicationRule[], role = ""): string {
  return doc("ReplicationConfiguration", {
    Role: role || undefined,
    Rule: rules.map((r) => ({
      ID: r.id || undefined,
      Status: r.enabled ? "Enabled" : "Disabled",
      Priority: r.priority,
      DeleteMarkerReplication: st(r.deleteMarkers),
      DeleteReplication: st(r.deletes),
      Filter: filterObj(r.prefix, r.tags),
      Destination: { Bucket: r.destArn, StorageClass: r.storageClass || undefined },
      ExistingObjectReplication: st(r.existing),
    })),
  });
}

export function parseReplication(d: Document): { role: string; rules: ReplicationRule[] } {
  const enabled = (r: Element, n: string) => text(child(r, n), "Status") === "Enabled";
  return {
    role: text(d, "Role"),
    rules: children(d, "Rule").map((r) => {
      const { prefix, tags } = parseFilter(r);
      const dest = child(r, "Destination");
      return {
        id: text(r, "ID"),
        enabled: text(r, "Status") === "Enabled",
        priority: num(text(r, "Priority")) ?? 0,
        prefix,
        tags,
        destArn: text(dest, "Bucket"),
        storageClass: text(dest, "StorageClass"),
        deleteMarkers: enabled(r, "DeleteMarkerReplication"),
        deletes: enabled(r, "DeleteReplication"),
        existing: enabled(r, "ExistingObjectReplication"),
      };
    }),
  };
}

// ---- CORS ----

export interface CorsRule {
  id: string;
  origins: string[];
  methods: string[];
  headers: string[];
  expose: string[];
  maxAge?: number;
}

export function corsXml(rules: CorsRule[]): string {
  return doc("CORSConfiguration", {
    CORSRule: rules.map((r) => ({
      ID: r.id || undefined,
      AllowedHeader: r.headers,
      AllowedMethod: r.methods,
      AllowedOrigin: r.origins,
      ExposeHeader: r.expose,
      MaxAgeSeconds: r.maxAge,
    })),
  });
}

export function parseCors(d: Document): CorsRule[] {
  const list = (r: Element, n: string) => children(r, n).map((e) => e.textContent ?? "");
  return children(d, "CORSRule").map((r) => ({
    id: text(r, "ID"),
    origins: list(r, "AllowedOrigin"),
    methods: list(r, "AllowedMethod"),
    headers: list(r, "AllowedHeader"),
    expose: list(r, "ExposeHeader"),
    maxAge: num(text(r, "MaxAgeSeconds")),
  }));
}

// ---- notifications ----

export type NotifyKind = "Queue" | "Topic" | "CloudFunction";
export interface NotifyRule {
  kind: NotifyKind;
  id: string;
  arn: string;
  events: string[];
  prefix: string;
  suffix: string;
}

export const EVENT_TYPES = [
  "s3:ObjectCreated:*",
  "s3:ObjectCreated:Put",
  "s3:ObjectCreated:Copy",
  "s3:ObjectCreated:CompleteMultipartUpload",
  "s3:ObjectRemoved:*",
  "s3:ObjectRemoved:Delete",
  "s3:ObjectRemoved:DeleteMarkerCreated",
  "s3:ObjectAccessed:*",
  "s3:ObjectAccessed:Get",
  "s3:ObjectAccessed:Head",
  "s3:ObjectRestore:*",
  "s3:ObjectTransition:*",
  "s3:Replication:*",
  "s3:ObjectLockRetention:*",
];

export function notificationXml(rules: NotifyRule[]): string {
  const cfg = (r: NotifyRule) => {
    const fr = [r.prefix && { Name: "prefix", Value: r.prefix }, r.suffix && { Name: "suffix", Value: r.suffix }].filter(Boolean) as XmlObj[];
    return { Id: r.id || undefined, [r.kind]: r.arn, Event: r.events, Filter: fr.length ? { S3Key: { FilterRule: fr } } : undefined };
  };
  const of = (k: NotifyKind) => rules.filter((r) => r.kind === k).map(cfg);
  return doc("NotificationConfiguration", {
    QueueConfiguration: of("Queue"),
    TopicConfiguration: of("Topic"),
    CloudFunctionConfiguration: of("CloudFunction"),
  });
}

export function parseNotification(d: Document): NotifyRule[] {
  const out: NotifyRule[] = [];
  for (const kind of ["Queue", "Topic", "CloudFunction"] as NotifyKind[]) {
    for (const c of children(d, `${kind}Configuration`)) {
      let prefix = "";
      let suffix = "";
      for (const fr of all(c, "FilterRule")) {
        const n = text(fr, "Name").toLowerCase();
        if (n === "prefix") prefix = text(fr, "Value");
        if (n === "suffix") suffix = text(fr, "Value");
      }
      out.push({ kind, id: text(c, "Id"), arn: text(c, kind), events: children(c, "Event").map((e) => e.textContent ?? ""), prefix, suffix });
    }
  }
  return out;
}

/** Notification target ARNs from `get-config-kv` text output; only enabled targets. */
export function arnsFromConfigKv(textOut: string, region: string): string[] {
  const out: string[] = [];
  for (const line of textOut.split("\n")) {
    const m = /^notify_([a-z]+)(?::(\S+))?\s(.*)$/.exec(line.trim());
    if (!m || !/(^|\s)enable="?on"?(\s|$)/.test(m[3])) continue;
    const type = m[1] === "postgres" ? "postgresql" : m[1];
    out.push(`arn:minio:sqs:${region}:${m[2] ?? "_"}:${type}`);
  }
  return out;
}

// ---- small single-document configs ----

export interface Encryption {
  algo: "" | "AES256" | "aws:kms";
  keyId: string;
}

export function encryptionXml(e: Encryption): string {
  return doc("ServerSideEncryptionConfiguration", {
    Rule: { ApplyServerSideEncryptionByDefault: { SSEAlgorithm: e.algo, KMSMasterKeyID: e.algo === "aws:kms" && e.keyId ? e.keyId : undefined } },
  });
}

export function parseEncryption(d: Document): Encryption {
  const def = all(d, "ApplyServerSideEncryptionByDefault")[0];
  const algo = text(def, "SSEAlgorithm");
  return { algo: algo === "AES256" || algo === "aws:kms" ? algo : "", keyId: text(def, "KMSMasterKeyID") };
}

export interface LockConfig {
  enabled: boolean;
  mode: "" | "GOVERNANCE" | "COMPLIANCE";
  days?: number;
  years?: number;
}

export function lockXml(l: LockConfig): string {
  return doc("ObjectLockConfiguration", {
    ObjectLockEnabled: "Enabled",
    Rule: l.mode ? { DefaultRetention: { Mode: l.mode, Days: l.days, Years: l.days === undefined ? l.years : undefined } } : undefined,
  });
}

export function parseLock(d: Document): LockConfig {
  const dr = all(d, "DefaultRetention")[0];
  const mode = text(dr, "Mode");
  return {
    enabled: text(d, "ObjectLockEnabled") === "Enabled",
    mode: mode === "GOVERNANCE" || mode === "COMPLIANCE" ? mode : "",
    days: num(text(dr, "Days")),
    years: num(text(dr, "Years")),
  };
}

export interface Website {
  index: string;
  error: string;
}

export function websiteXml(w: Website): string {
  return doc("WebsiteConfiguration", { IndexDocument: { Suffix: w.index }, ErrorDocument: w.error ? { Key: w.error } : undefined });
}

export function parseWebsite(d: Document): Website {
  return { index: text(child(d, "IndexDocument"), "Suffix"), error: text(child(d, "ErrorDocument"), "Key") };
}

export function versioningXml(status: "Enabled" | "Suspended"): string {
  return doc("VersioningConfiguration", { Status: status });
}

export function retentionXml(mode: "GOVERNANCE" | "COMPLIANCE", until: Date): string {
  return doc("Retention", { Mode: mode, RetainUntilDate: until.toISOString() });
}

export function legalHoldXml(on: boolean): string {
  return doc("LegalHold", { Status: on ? "ON" : "OFF" });
}

/** Pretty-prints XML for the raw views; leaf elements stay on one line. */
export function prettyXml(s: string): string {
  const tokens = s.replace(/>\s+</g, "><").match(/<[^>]+>|[^<]+/g) || [];
  const lines: string[] = [];
  let depth = 0;
  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i];
    if (t.startsWith("</")) {
      depth = Math.max(0, depth - 1);
      lines.push("  ".repeat(depth) + t);
    } else if (t.startsWith("<?") || t.endsWith("/>")) {
      lines.push("  ".repeat(depth) + t);
    } else if (t.startsWith("<")) {
      const txt = tokens[i + 1];
      if (txt && !txt.startsWith("<") && tokens[i + 2]?.startsWith("</")) {
        lines.push("  ".repeat(depth) + t + txt + tokens[i + 2]);
        i += 2;
      } else if (txt?.startsWith("</")) {
        lines.push("  ".repeat(depth) + t + txt);
        i += 1;
      } else {
        lines.push("  ".repeat(depth) + t);
        depth++;
      }
    } else if (t.trim()) lines.push("  ".repeat(depth) + t.trim());
  }
  return lines.join("\n");
}
