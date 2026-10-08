import { describe, expect, it } from "vitest";
import {
  arnsFromConfigKv,
  corsXml,
  encryptionXml,
  LifecycleRule,
  lifecycleXml,
  lockXml,
  notificationXml,
  parseCors,
  parseEncryption,
  parseLifecycle,
  parseLock,
  parseNotification,
  parseReplication,
  parseWebsite,
  parseXml,
  prettyXml,
  ReplicationRule,
  replicationXml,
  websiteXml,
} from "./xmlcfg";

const rt = <T>(build: (x: T) => string, parse: (d: Document) => T, x: T) => parse(parseXml(build(x)));

describe("lifecycle", () => {
  const rules: LifecycleRule[] = [
    { id: "logs", enabled: true, prefix: "logs/", tags: [], expirationDays: 30, abortDays: 7 },
    { id: "tagged", enabled: false, prefix: "", tags: [["env", "dev"]], noncurrentDays: 10, newerNoncurrent: 2 },
    { id: "cold", enabled: true, prefix: "data/", tags: [["a", "1"], ["b", "x&y"]], transitionDays: 90, transitionTier: "COLD", noncurrentTransitionDays: 5, noncurrentTransitionTier: "COLD" },
    { id: "dm", enabled: true, prefix: "", tags: [], expiredDeleteMarker: true },
  ];
  it("round-trips", () => {
    const back = parseLifecycle(parseXml(lifecycleXml(rules)));
    const norm = (r: LifecycleRule) => Object.fromEntries(Object.entries(r).filter(([, v]) => v !== undefined));
    expect(back.map(norm)).toEqual(rules.map(norm));
  });
  it("uses the right filter shapes", () => {
    const x = lifecycleXml(rules);
    expect(x).toContain("<Filter><Prefix>logs/</Prefix></Filter>");
    expect(x).toContain("<Filter><Tag><Key>env</Key><Value>dev</Value></Tag></Filter>");
    expect(x).toContain("<And><Prefix>data/</Prefix><Tag>");
    expect(x).toContain("x&amp;y");
    expect(x).toContain("<ExpiredObjectDeleteMarker>true</ExpiredObjectDeleteMarker>");
  });
  it("parses legacy rule-level prefix", () => {
    const d = parseXml("<LifecycleConfiguration><Rule><ID>a</ID><Prefix>p/</Prefix><Status>Enabled</Status><Expiration><Days>1</Days></Expiration></Rule></LifecycleConfiguration>");
    expect(parseLifecycle(d)[0]).toMatchObject({ id: "a", prefix: "p/", enabled: true, expirationDays: 1 });
  });
});

describe("replication", () => {
  it("round-trips", () => {
    const rules: ReplicationRule[] = [
      { id: "r1", enabled: true, priority: 1, prefix: "a/", tags: [], destArn: "arn:minio:replication::x:dst", storageClass: "", deleteMarkers: true, deletes: false, existing: true },
      { id: "r2", enabled: false, priority: 2, prefix: "", tags: [["k", "v"]], destArn: "arn:minio:replication::y:dst", storageClass: "STANDARD", deleteMarkers: false, deletes: true, existing: false },
    ];
    const x = replicationXml(rules, "role");
    expect(x).toContain("<Destination><Bucket>arn:minio:replication::x:dst</Bucket></Destination>");
    expect(parseReplication(parseXml(x))).toEqual({ role: "role", rules });
  });
});

describe("cors", () => {
  it("round-trips repeated elements", () => {
    const rules = [{ id: "c", origins: ["https://a.example", "*"], methods: ["GET", "PUT"], headers: ["*"], expose: ["ETag"], maxAge: 300 }];
    const x = corsXml(rules);
    expect(x).toContain("<AllowedMethod>GET</AllowedMethod><AllowedMethod>PUT</AllowedMethod>");
    expect(parseCors(parseXml(x))).toEqual(rules);
  });
});

describe("notifications", () => {
  it("round-trips with filters", () => {
    const rules = [
      { kind: "Queue" as const, id: "1", arn: "arn:minio:sqs::1:webhook", events: ["s3:ObjectCreated:*"], prefix: "in/", suffix: ".jpg" },
      { kind: "Topic" as const, id: "", arn: "arn:minio:sqs::k:kafka", events: ["s3:ObjectRemoved:*", "s3:ObjectAccessed:Get"], prefix: "", suffix: "" },
    ];
    const x = notificationXml(rules);
    expect(x).toContain("<Queue>arn:minio:sqs::1:webhook</Queue>");
    expect(parseNotification(parseXml(x))).toEqual(rules);
  });
  it("derives ARNs from enabled targets", () => {
    const out = 'notify_webhook:one enable=on endpoint=http://x\nnotify_webhook:two enable=off endpoint=""\nnotify_postgres enable=on table=t\n';
    expect(arnsFromConfigKv(out, "us-east-1")).toEqual(["arn:minio:sqs:us-east-1:one:webhook", "arn:minio:sqs:us-east-1:_:postgresql"]);
  });
});

describe("single documents", () => {
  it("encryption", () => {
    expect(rt(encryptionXml, parseEncryption, { algo: "aws:kms", keyId: "k1" })).toEqual({ algo: "aws:kms", keyId: "k1" });
    expect(encryptionXml({ algo: "AES256", keyId: "ignored" })).not.toContain("KMSMasterKeyID");
  });
  it("object lock", () => {
    expect(rt(lockXml, parseLock, { enabled: true, mode: "GOVERNANCE", days: 5 })).toEqual({ enabled: true, mode: "GOVERNANCE", days: 5, years: undefined });
    expect(lockXml({ enabled: true, mode: "" })).not.toContain("<Rule>");
  });
  it("website", () => {
    expect(rt(websiteXml, parseWebsite, { index: "index.html", error: "404.html" })).toEqual({ index: "index.html", error: "404.html" });
  });
  it("pretty prints", () => {
    expect(prettyXml("<a><b>1</b><c><d>x</d></c></a>")).toBe("<a>\n  <b>1</b>\n  <c>\n    <d>x</d>\n  </c>\n</a>");
  });
});
