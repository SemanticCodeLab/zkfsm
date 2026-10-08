// Bucket detail tabs with a single document each: summary, versioning, lock, quota, policy, tags, encryption, website.
import { useEffect, useState } from "preact/hooks";
import { admin, cluster, s3, s3Text, s3Xml } from "../../lib/api";
import { tagsXml } from "../../lib/xml";
import { bytes } from "../../lib/format";
import { Badge, Button, Card, JsonEditor, KeyValue, Progress, Select, TextInput, toast, toastError, useAsync } from "../../components/ui";
import { joinBytes, numOrUndef, optional, PairsEditor, QuotaInput, Section, splitBytes, strOf } from "./common";
import { setQuota } from "./ops";
import { parseTagSet, text, encryptionXml, Encryption, lockXml, LockConfig, parseEncryption, parseLock, parseWebsite, versioningXml, websiteXml } from "./xmlcfg";

export const bpath = (b: string) => `/${encodeURIComponent(b)}`;

export interface Quota {
  quota: number;
  usage?: number;
  objects?: number;
}

export const loadVersioning = async (b: string) => text(await s3Xml(bpath(b), { query: { versioning: true } }), "Status") || "Off";
export const loadLock = (b: string) => optional(async () => parseLock(await s3Xml(bpath(b), { query: { "object-lock": true } })));
export const loadQuota = (b: string) => optional(() => admin<Quota>("/get-bucket-quota", { query: { bucket: b } }));

async function run(fn: () => Promise<unknown>, ok: string, after?: () => void) {
  try {
    await fn();
    toast(ok);
    after?.();
  } catch (e) {
    toastError(e);
  }
}

export function SummaryTab({ bucket }: { bucket: string }) {
  const loc = useAsync(async () => (await s3Xml(bpath(bucket), { query: { location: true } })).documentElement?.textContent?.trim() || "", [bucket]);
  const ver = useAsync(() => loadVersioning(bucket), [bucket]);
  const lock = useAsync(() => loadLock(bucket).catch(() => null), [bucket]);
  const quota = useAsync(() => loadQuota(bucket).catch(() => null), [bucket]);
  const region = useAsync(() => cluster.info().then((c) => c.region).catch(() => ""), []);
  const q = quota.data;
  return (
    <div class="grid-2">
      <Card title="Overview">
        <KeyValue
          rows={[
            ["Name", <span class="mono">{bucket}</span>],
            ["Region", loc.error ? "-" : loc.data === undefined ? "…" : loc.data || region.data || "default"],
            ["Versioning", ver.error ? "-" : ver.data === undefined ? "…" : <Badge kind={ver.data === "Enabled" ? "ok" : ver.data === "Suspended" ? "warn" : "default"}>{ver.data}</Badge>],
            ["Object lock", lock.data === undefined ? "…" : lock.data?.enabled ? <Badge kind="ok">Enabled</Badge> : "Disabled"],
            ["Default retention", lock.data?.mode ? `${lock.data.mode} ${lock.data.days ? `${lock.data.days} days` : `${lock.data.years} years`}` : "-"],
          ]}
        />
      </Card>
      <Card title="Usage">
        {quota.data === undefined ? (
          <div class="loading">Loading…</div>
        ) : q ? (
          <>
            <KeyValue
              rows={[
                ["Used", bytes(q.usage)],
                ["Objects", String(q.objects ?? "-")],
                ["Hard quota", bytes(q.quota)],
              ]}
            />
            <Progress value={q.quota ? Math.min(100, ((q.usage || 0) / q.quota) * 100) : 0} label="Quota used" />
          </>
        ) : (
          <p class="hint">No quota configured; usage is reported with a quota.</p>
        )}
      </Card>
    </div>
  );
}

export function VersioningTab({ bucket, onChange }: { bucket: string; onChange?: () => void }) {
  const st = useAsync(() => loadVersioning(bucket), [bucket]);
  const lock = useAsync(() => loadLock(bucket).catch(() => null), [bucket]);
  const set = (s: "Enabled" | "Suspended") =>
    run(() => s3(bpath(bucket), { method: "PUT", query: { versioning: true }, body: versioningXml(s) }), `Versioning ${s.toLowerCase()}`, () => {
      st.reload();
      onChange?.();
    });
  return (
    <Card title="Versioning">
      <Section state={st}>
        {() => (
          <>
            <p>
              Current state: <Badge kind={st.data === "Enabled" ? "ok" : st.data === "Suspended" ? "warn" : "default"}>{st.data}</Badge>
            </p>
            <p class="hint">Versioning keeps every version of an object. Suspending stops creating new versions but keeps existing ones.</p>
            {lock.data?.enabled && <div class="notice">Object lock is enabled; versioning cannot be suspended.</div>}
            <div class="bk-buttons">
              <Button variant="primary" disabled={st.data === "Enabled"} onClick={() => set("Enabled")}>
                Enable versioning
              </Button>
              <Button disabled={st.data !== "Enabled" || !!lock.data?.enabled} onClick={() => set("Suspended")}>
                Suspend versioning
              </Button>
            </div>
          </>
        )}
      </Section>
    </Card>
  );
}

export function LockTab({ bucket }: { bucket: string }) {
  const st = useAsync(() => loadLock(bucket), [bucket]);
  const [cfg, setCfg] = useState<LockConfig | null>(null);
  const [unit, setUnit] = useState<"days" | "years">("days");
  const [amount, setAmount] = useState("");
  useEffect(() => {
    if (!st.data) return;
    setCfg(st.data);
    setUnit(st.data.years !== undefined ? "years" : "days");
    setAmount(strOf(st.data.days ?? st.data.years));
  }, [st.data]);
  const save = () => {
    if (!cfg) return;
    const n = numOrUndef(amount);
    if (cfg.mode && !n) return toast("Retention period must be a positive number", "error");
    const next: LockConfig = { ...cfg, days: cfg.mode && unit === "days" ? n : undefined, years: cfg.mode && unit === "years" ? n : undefined };
    run(() => s3(bpath(bucket), { method: "PUT", query: { "object-lock": true }, body: lockXml(next) }), "Object lock configuration saved", st.reload);
  };
  return (
    <Card title="Object lock">
      <Section state={st}>
        {() =>
          !st.data?.enabled || !cfg ? (
            <div class="notice">Object lock is not enabled on this bucket. It can only be enabled when the bucket is created.</div>
          ) : (
            <>
              <p class="hint">Default retention applies to new object versions that do not set their own retention.</p>
              <Select
                label="Default retention mode"
                value={cfg.mode}
                onChange={(v) => setCfg({ ...cfg, mode: v as LockConfig["mode"] })}
                options={[
                  ["", "None"],
                  ["GOVERNANCE", "Governance"],
                  ["COMPLIANCE", "Compliance"],
                ]}
              />
              {cfg.mode && (
                <div class="row">
                  <TextInput label="Retention period" type="number" min="1" value={amount} onInput={setAmount} />
                  <Select label="Period unit" value={unit} onChange={(v) => setUnit(v as "days" | "years")} options={[["days", "Days"], ["years", "Years"]]} />
                </div>
              )}
              {cfg.mode === "COMPLIANCE" && <div class="notice notice-warn">Compliance retention cannot be shortened or removed by any user, including root.</div>}
              <Button variant="primary" onClick={save}>
                Save
              </Button>
            </>
          )
        }
      </Section>
    </Card>
  );
}

export function QuotaTab({ bucket }: { bucket: string }) {
  const st = useAsync(() => loadQuota(bucket), [bucket]);
  const [v, setV] = useState("");
  const [u, setU] = useState("GiB");
  useEffect(() => {
    if (st.data === undefined) return;
    const s = splitBytes(st.data?.quota || 0);
    setV(s.value);
    setU(s.unit);
  }, [st.data]);
  return (
    <Card title="Quota">
      <Section state={st}>
        {() => (
          <>
            <p class="hint">A hard quota rejects writes once the bucket reaches the limit.</p>
            {st.data && (
              <KeyValue
                rows={[
                  ["Current quota", bytes(st.data.quota)],
                  ["Used", bytes(st.data.usage)],
                ]}
              />
            )}
            <QuotaInput label="Hard quota" value={v} unit={u} onValue={setV} onUnit={setU} />
            <div class="bk-buttons">
              <Button variant="primary" onClick={() => run(() => setQuota(bucket, joinBytes(v, u)), "Quota saved", st.reload)}>
                Save
              </Button>
              <Button disabled={!st.data} onClick={() => run(() => setQuota(bucket, 0), "Quota removed", st.reload)}>
                Remove quota
              </Button>
            </div>
          </>
        )}
      </Section>
    </Card>
  );
}

function policyPreset(bucket: string, kind: "private" | "public-read" | "public-read-write"): string {
  if (kind === "private") return "";
  const read = ["s3:GetObject"];
  const write = ["s3:PutObject", "s3:DeleteObject", "s3:AbortMultipartUpload", "s3:ListMultipartUploadParts"];
  const bucketActs = kind === "public-read" ? ["s3:GetBucketLocation", "s3:ListBucket"] : ["s3:GetBucketLocation", "s3:ListBucket", "s3:ListBucketMultipartUploads"];
  return JSON.stringify(
    {
      Version: "2012-10-17",
      Statement: [
        { Effect: "Allow", Principal: { AWS: ["*"] }, Action: bucketActs, Resource: [`arn:aws:s3:::${bucket}`] },
        { Effect: "Allow", Principal: { AWS: ["*"] }, Action: kind === "public-read" ? read : [...read, ...write], Resource: [`arn:aws:s3:::${bucket}/*`] },
      ],
    },
    null,
    2,
  );
}

export function PolicyTab({ bucket }: { bucket: string }) {
  const st = useAsync(() => optional(() => s3Text(bpath(bucket), { query: { policy: true } })), [bucket]);
  const [val, setVal] = useState("");
  useEffect(() => {
    if (st.data === undefined) return;
    try {
      setVal(st.data ? JSON.stringify(JSON.parse(st.data), null, 2) : "");
    } catch {
      setVal(st.data || "");
    }
  }, [st.data]);
  let valid = true;
  try {
    if (val.trim()) JSON.parse(val);
  } catch {
    valid = false;
  }
  const save = () =>
    val.trim()
      ? run(() => s3(bpath(bucket), { method: "PUT", query: { policy: true }, headers: { "content-type": "application/json" }, body: val }), "Bucket policy saved", st.reload)
      : run(() => s3(bpath(bucket), { method: "DELETE", query: { policy: true } }), "Bucket policy removed", st.reload);
  return (
    <Card title="Bucket policy" actions={<Badge kind={st.data ? "warn" : "default"}>{st.data === undefined ? "…" : st.data ? "Custom" : "Private"}</Badge>}>
      <Section state={st}>
        {() => (
          <>
            <div class="bk-buttons">
              <span class="hint">Presets:</span>
              <Button small onClick={() => setVal(policyPreset(bucket, "private"))}>
                Private
              </Button>
              <Button small onClick={() => setVal(policyPreset(bucket, "public-read"))}>
                Public read
              </Button>
              <Button small onClick={() => setVal(policyPreset(bucket, "public-read-write"))}>
                Public read/write
              </Button>
            </div>
            <JsonEditor label="Policy JSON" value={val} onChange={setVal} rows={18} />
            <div class="bk-buttons">
              <Button variant="primary" disabled={!valid} onClick={save}>
                Save policy
              </Button>
              <Button variant="danger" disabled={!st.data} onClick={() => run(() => s3(bpath(bucket), { method: "DELETE", query: { policy: true } }), "Bucket policy removed", st.reload)}>
                Delete policy
              </Button>
            </div>
          </>
        )}
      </Section>
    </Card>
  );
}

export function TagsTab({ bucket }: { bucket: string }) {
  const st = useAsync(() => optional(async () => parseTagSet(await s3Xml(bpath(bucket), { query: { tagging: true } }))), [bucket]);
  const [pairs, setPairs] = useState<[string, string][]>([]);
  useEffect(() => {
    if (st.data !== undefined) setPairs(Object.entries(st.data || {}));
  }, [st.data]);
  const save = () => {
    const clean = pairs.filter(([k]) => k.trim());
    if (!clean.length) return run(() => s3(bpath(bucket), { method: "DELETE", query: { tagging: true } }), "Tags removed", st.reload);
    run(() => s3(bpath(bucket), { method: "PUT", query: { tagging: true }, body: tagsXml(Object.fromEntries(clean)) }), "Tags saved", st.reload);
  };
  return (
    <Card title="Bucket tags">
      <Section state={st}>
        {() => (
          <>
            <PairsEditor pairs={pairs} onChange={setPairs} />
            <div class="bk-buttons">
              <Button variant="primary" onClick={save}>
                Save tags
              </Button>
            </div>
          </>
        )}
      </Section>
    </Card>
  );
}

export function EncryptionTab({ bucket }: { bucket: string }) {
  const st = useAsync(() => optional(async () => parseEncryption(await s3Xml(bpath(bucket), { query: { encryption: true } }))), [bucket]);
  const [e, setE] = useState<Encryption>({ algo: "", keyId: "" });
  useEffect(() => {
    if (st.data !== undefined) setE(st.data || { algo: "", keyId: "" });
  }, [st.data]);
  const save = () =>
    e.algo
      ? run(() => s3(bpath(bucket), { method: "PUT", query: { encryption: true }, body: encryptionXml(e) }), "Encryption saved", st.reload)
      : run(() => s3(bpath(bucket), { method: "DELETE", query: { encryption: true } }), "Default encryption removed", st.reload);
  return (
    <Card title="Default encryption">
      <Section state={st}>
        {() => (
          <>
            <p class="hint">New objects without their own encryption headers are encrypted with this setting.</p>
            <Select
              label="Encryption type"
              value={e.algo}
              onChange={(v) => setE({ ...e, algo: v as Encryption["algo"] })}
              options={[
                ["", "None"],
                ["AES256", "SSE-S3 (server-managed keys)"],
                ["aws:kms", "SSE-KMS (KMS key)"],
              ]}
            />
            {e.algo === "aws:kms" && <TextInput label="KMS key ID" value={e.keyId} onInput={(v) => setE({ ...e, keyId: v })} hint="Leave empty to use the default KMS key." />}
            <Button variant="primary" onClick={save}>
              Save
            </Button>
          </>
        )}
      </Section>
    </Card>
  );
}

export function WebsiteTab({ bucket }: { bucket: string }) {
  const st = useAsync(() => optional(async () => parseWebsite(await s3Xml(bpath(bucket), { query: { website: true } }))), [bucket]);
  const [w, setW] = useState({ index: "index.html", error: "" });
  useEffect(() => {
    if (st.data) setW(st.data);
  }, [st.data]);
  return (
    <Card title="Static website" actions={<Badge kind={st.data ? "ok" : "default"}>{st.data === undefined ? "…" : st.data ? "Enabled" : "Disabled"}</Badge>}>
      <Section state={st}>
        {() => (
          <>
            <p class="hint">Serves the bucket as a website. Objects must be readable anonymously (see the Policy tab).</p>
            <div class="row">
              <TextInput label="Index document" value={w.index} onInput={(v) => setW({ ...w, index: v })} />
              <TextInput label="Error document" value={w.error} onInput={(v) => setW({ ...w, error: v })} />
            </div>
            <div class="bk-buttons">
              <Button variant="primary" disabled={!w.index.trim()} onClick={() => run(() => s3(bpath(bucket), { method: "PUT", query: { website: true }, body: websiteXml(w) }), "Website configuration saved", st.reload)}>
                Save
              </Button>
              <Button variant="danger" disabled={!st.data} onClick={() => run(() => s3(bpath(bucket), { method: "DELETE", query: { website: true } }), "Website disabled", st.reload)}>
                Disable website
              </Button>
            </div>
          </>
        )}
      </Section>
    </Card>
  );
}

export { run };
