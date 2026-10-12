// Bucket detail tabs holding rule lists: lifecycle, replication, CORS, events.
import { ComponentChildren } from "preact";
import { useState } from "preact/hooks";
import { admin, ADMIN, cluster, s3, s3Text } from "../../lib/api";
import { Badge, Button, Card, Confirm, Empty, Modal, Select, TextInput, Toggle, toast, toastError, useAsync } from "../../components/ui";
import { ListInput, numOrUndef, optional, PairsEditor, Section, strOf } from "./common";
import { bpath } from "./TabsSimple";
import {
  CorsRule,
  corsXml,
  emptyLifecycleRule,
  EVENT_TYPES,
  LifecycleRule,
  lifecycleXml,
  NotifyKind,
  NotifyRule,
  notificationXml,
  arnsFromConfigKv,
  parseCors,
  parseLifecycle,
  parseNotification,
  parseReplication,
  parseXml,
  prettyXml,
  ReplicationRule,
  replicationXml,
} from "./xmlcfg";

/** Loads a subresource as raw XML text (null when not configured). */
function useRaw(bucket: string, sub: string) {
  return useAsync(() => optional(() => s3Text(bpath(bucket), { query: { [sub]: true } })), [bucket, sub]);
}

async function saveDoc(bucket: string, sub: string, body: string | null) {
  if (body === null) await s3(bpath(bucket), { method: "DELETE", query: { [sub]: true } });
  else await s3(bpath(bucket), { method: "PUT", query: { [sub]: true }, headers: { "content-type": "application/xml" }, body });
}

function RawXml({ xml }: { xml: string | null | undefined }) {
  const [open, setOpen] = useState(false);
  return (
    <div class="bk-raw">
      <Button small variant="ghost" aria-expanded={open} onClick={() => setOpen(!open)}>
        {open ? "Hide XML" : "View XML"}
      </Button>
      {open && <pre class="mono bk-pre">{xml ? prettyXml(xml) : "(not configured)"}</pre>}
    </div>
  );
}

/** Generic rule-list card: table, add/edit modal, delete confirm, raw XML. */
function RuleList<R>({
  title,
  intro,
  raw,
  rules,
  columns,
  row,
  blank,
  editor,
  save,
  addLabel,
}: {
  title: string;
  intro: ComponentChildren;
  raw: string | null | undefined;
  rules: R[];
  columns: string[];
  row: (r: R) => ComponentChildren[];
  blank: () => R;
  editor: (r: R, set: (r: R) => void) => ComponentChildren;
  save: (rules: R[]) => Promise<void>;
  addLabel: string;
}) {
  const [edit, setEdit] = useState<{ i: number; r: R } | null>(null);
  const [del, setDel] = useState<number | null>(null);
  const [busy, setBusy] = useState(false);
  const commit = async () => {
    if (!edit) return;
    setBusy(true);
    try {
      const next = edit.i < 0 ? [...rules, edit.r] : rules.map((x, i) => (i === edit.i ? edit.r : x));
      await save(next);
      setEdit(null);
    } catch (e) {
      toastError(e);
    } finally {
      setBusy(false);
    }
  };
  return (
    <Card
      title={title}
      actions={
        <Button variant="primary" onClick={() => setEdit({ i: -1, r: blank() })}>
          {addLabel}
        </Button>
      }
    >
      <p class="hint">{intro}</p>
      {rules.length === 0 ? (
        <Empty>No rules configured.</Empty>
      ) : (
        <table>
          <thead>
            <tr>
              {columns.map((c) => (
                <th key={c}>{c}</th>
              ))}
              <th class="bk-actions-col">
                <span class="sr-only">Actions</span>
              </th>
            </tr>
          </thead>
          <tbody>
            {rules.map((r, i) => (
              <tr key={i}>
                {row(r).map((c, j) => (
                  <td key={j}>{c}</td>
                ))}
                <td class="bk-actions-col">
                  <Button small aria-label={`Edit rule ${i + 1}`} onClick={() => setEdit({ i, r: structuredClone(r) })}>
                    Edit
                  </Button>
                  <Button small variant="ghost" aria-label={`Delete rule ${i + 1}`} onClick={() => setDel(i)}>
                    Delete
                  </Button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <RawXml xml={raw} />
      {edit && (
        <Modal
          wide
          title={edit.i < 0 ? addLabel : "Edit rule"}
          onClose={() => setEdit(null)}
          footer={
            <>
              <Button onClick={() => setEdit(null)}>Cancel</Button>
              <Button variant="primary" disabled={busy} onClick={commit}>
                Save
              </Button>
            </>
          }
        >
          {editor(edit.r, (r) => setEdit({ ...edit, r }))}
        </Modal>
      )}
      {del !== null && <Confirm title="Delete rule" message={`Delete rule ${del + 1}?`} onConfirm={() => save(rules.filter((_, i) => i !== del))} onClose={() => setDel(null)} />}
    </Card>
  );
}

const filterText = (prefix: string, tags: [string, string][]) =>
  [prefix && `prefix ${prefix}`, ...tags.map(([k, v]) => `${k}=${v}`)].filter(Boolean).join(", ") || "whole bucket";

// ---- lifecycle ----

export function LifecycleTab({ bucket }: { bucket: string }) {
  const raw = useRaw(bucket, "lifecycle");
  const tiers = useAsync(() => admin<{ Name: string }[]>("/tier").then((t) => (t || []).map((x) => x.Name)).catch(() => [] as string[]), []);
  const tierOpts: [string, string][] = [["", "None"], ...(tiers.data || []).map((t) => [t, t] as [string, string])];
  return (
    <Section state={raw}>
      {() => (
        <RuleList<LifecycleRule>
          title="Lifecycle rules"
          intro="Expire or transition objects automatically. Transitions move data to a remote tier."
          raw={raw.data}
          rules={raw.data ? parseLifecycle(parseXml(raw.data)) : []}
          columns={["ID", "Status", "Filter", "Behavior"]}
          addLabel="Add lifecycle rule"
          blank={emptyLifecycleRule}
          row={(r) => [
            <span class="mono">{r.id || "-"}</span>,
            <Badge kind={r.enabled ? "ok" : "default"}>{r.enabled ? "Enabled" : "Disabled"}</Badge>,
            filterText(r.prefix, r.tags),
            <span class="bk-small">
              {[
                r.expirationDays !== undefined && `expire after ${r.expirationDays}d`,
                r.expiredDeleteMarker && "remove expired delete markers",
                r.noncurrentDays !== undefined && `noncurrent expire after ${r.noncurrentDays}d`,
                r.transitionTier && `to ${r.transitionTier} after ${r.transitionDays}d`,
                r.noncurrentTransitionTier && `noncurrent to ${r.noncurrentTransitionTier} after ${r.noncurrentTransitionDays}d`,
                r.abortDays !== undefined && `abort uploads after ${r.abortDays}d`,
              ]
                .filter(Boolean)
                .join("; ") || "-"}
            </span>,
          ]}
          save={async (rules) => {
            await saveDoc(bucket, "lifecycle", rules.length ? lifecycleXml(rules) : null);
            toast("Lifecycle saved");
            raw.reload();
          }}
          editor={(r, set) => (
            <>
              <div class="row">
                <TextInput label="Rule ID" value={r.id} onInput={(v) => set({ ...r, id: v })} />
                <TextInput label="Prefix" value={r.prefix} onInput={(v) => set({ ...r, prefix: v })} />
              </div>
              <Toggle label="Enabled" checked={r.enabled} onChange={(v) => set({ ...r, enabled: v })} />
              <h3 class="bk-h3">Tag filter</h3>
              <PairsEditor pairs={r.tags} onChange={(tags) => set({ ...r, tags })} />
              <h3 class="bk-h3">Expiration</h3>
              <div class="row">
                <TextInput label="Expire current versions after (days)" type="number" min="1" value={strOf(r.expirationDays)} onInput={(v) => set({ ...r, expirationDays: numOrUndef(v) })} />
                <TextInput label="Expire noncurrent versions after (days)" type="number" min="1" value={strOf(r.noncurrentDays)} onInput={(v) => set({ ...r, noncurrentDays: numOrUndef(v) })} />
                <TextInput label="Keep newer noncurrent versions" type="number" min="0" value={strOf(r.newerNoncurrent)} onInput={(v) => set({ ...r, newerNoncurrent: numOrUndef(v) })} />
              </div>
              <Toggle label="Remove expired delete markers" checked={!!r.expiredDeleteMarker} onChange={(v) => set({ ...r, expiredDeleteMarker: v || undefined })} />
              <TextInput label="Abort incomplete multipart uploads after (days)" type="number" min="1" value={strOf(r.abortDays)} onInput={(v) => set({ ...r, abortDays: numOrUndef(v) })} />
              <h3 class="bk-h3">Transition</h3>
              {tiers.data && tiers.data.length === 0 && <p class="hint">No remote tiers are configured; add one under Tiers to enable transitions.</p>}
              <div class="row">
                <Select label="Transition to tier" value={r.transitionTier || ""} onChange={(v) => set({ ...r, transitionTier: v || undefined })} options={tierOpts} />
                <TextInput label="Transition after (days)" type="number" min="0" value={strOf(r.transitionDays)} onInput={(v) => set({ ...r, transitionDays: numOrUndef(v) })} />
              </div>
              <div class="row">
                <Select label="Transition noncurrent to tier" value={r.noncurrentTransitionTier || ""} onChange={(v) => set({ ...r, noncurrentTransitionTier: v || undefined })} options={tierOpts} />
                <TextInput label="Noncurrent transition after (days)" type="number" min="0" value={strOf(r.noncurrentTransitionDays)} onInput={(v) => set({ ...r, noncurrentTransitionDays: numOrUndef(v) })} />
              </div>
            </>
          )}
        />
      )}
    </Section>
  );
}

// ---- replication ----

interface RemoteTarget {
  arn: string;
  endpoint: string;
  targetbucket: string;
  isOnline?: boolean;
}

export function ReplicationTab({ bucket }: { bucket: string }) {
  const raw = useRaw(bucket, "replication");
  const targets = useAsync(() => admin<RemoteTarget[]>("/list-remote-targets", { query: { bucket } }).then((t) => t || []), [bucket]);
  const [adding, setAdding] = useState(false);
  const parsed = raw.data ? parseReplication(parseXml(raw.data)) : { role: "", rules: [] };
  const arnOpts: [string, string][] = [["", "Select a remote target"], ...(targets.data || []).map((t) => [t.arn, `${t.endpoint}/${t.targetbucket}`] as [string, string])];
  return (
    <>
      <Section state={raw}>
        {() => (
          <RuleList<ReplicationRule>
            title="Replication rules"
            intro="Replicate new objects to a remote bucket. Both buckets need versioning enabled."
            raw={raw.data}
            rules={parsed.rules}
            columns={["ID", "Status", "Priority", "Filter", "Destination"]}
            addLabel="Add replication rule"
            blank={() => ({ id: "", enabled: true, priority: parsed.rules.length + 1, prefix: "", tags: [], destArn: targets.data?.[0]?.arn || "", storageClass: "", deleteMarkers: true, deletes: true, existing: false })}
            row={(r) => [
              <span class="mono">{r.id || "-"}</span>,
              <Badge kind={r.enabled ? "ok" : "default"}>{r.enabled ? "Enabled" : "Disabled"}</Badge>,
              String(r.priority),
              filterText(r.prefix, r.tags),
              <span class="mono bk-small">{r.destArn}</span>,
            ]}
            save={async (rules) => {
              await saveDoc(bucket, "replication", rules.length ? replicationXml(rules, parsed.role) : null);
              toast("Replication saved");
              raw.reload();
            }}
            editor={(r, set) => (
              <>
                <div class="row">
                  <TextInput label="Rule ID" value={r.id} onInput={(v) => set({ ...r, id: v })} />
                  <TextInput label="Priority" type="number" min="0" value={String(r.priority)} onInput={(v) => set({ ...r, priority: numOrUndef(v) ?? 0 })} />
                </div>
                <Select label="Destination" value={r.destArn} onChange={(v) => set({ ...r, destArn: v })} options={r.destArn && !arnOpts.some(([a]) => a === r.destArn) ? [...arnOpts, [r.destArn, r.destArn]] : arnOpts} />
                <div class="row">
                  <TextInput label="Prefix" value={r.prefix} onInput={(v) => set({ ...r, prefix: v })} />
                  <TextInput label="Storage class" value={r.storageClass} onInput={(v) => set({ ...r, storageClass: v })} />
                </div>
                <PairsEditor pairs={r.tags} onChange={(tags) => set({ ...r, tags })} />
                <div class="bk-stack">
                  <Toggle label="Enabled" checked={r.enabled} onChange={(v) => set({ ...r, enabled: v })} />
                  <Toggle label="Replicate delete markers" checked={r.deleteMarkers} onChange={(v) => set({ ...r, deleteMarkers: v })} />
                  <Toggle label="Replicate version deletes" checked={r.deletes} onChange={(v) => set({ ...r, deletes: v })} />
                  <Toggle label="Replicate existing objects" checked={r.existing} onChange={(v) => set({ ...r, existing: v })} />
                </div>
              </>
            )}
          />
        )}
      </Section>
      <Card title="Remote targets" actions={<Button onClick={() => setAdding(true)}>Add remote target</Button>}>
        <Section state={targets}>
          {() =>
            targets.data!.length === 0 ? (
              <Empty>No remote targets. Add one before creating replication rules.</Empty>
            ) : (
              <table>
                <thead>
                  <tr>
                    <th>Endpoint</th>
                    <th>Bucket</th>
                    <th>ARN</th>
                    <th>Status</th>
                    <th class="bk-actions-col">
                      <span class="sr-only">Actions</span>
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {targets.data!.map((t) => (
                    <tr key={t.arn}>
                      <td class="mono">{t.endpoint}</td>
                      <td class="mono">{t.targetbucket}</td>
                      <td class="mono bk-small">{t.arn}</td>
                      <td>
                        <Badge kind={t.isOnline === false ? "error" : "ok"}>{t.isOnline === false ? "Offline" : "Online"}</Badge>
                      </td>
                      <td class="bk-actions-col">
                        <Button
                          small
                          variant="ghost"
                          aria-label={`Remove target ${t.arn}`}
                          onClick={() =>
                            admin("/remove-remote-target", { method: "DELETE", query: { bucket, arn: t.arn } }).then(
                              () => (toast("Remote target removed"), targets.reload()),
                              toastError,
                            )
                          }
                        >
                          Remove
                        </Button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )
          }
        </Section>
      </Card>
      {adding && <AddTarget bucket={bucket} onClose={() => setAdding(false)} onDone={targets.reload} />}
    </>
  );
}

function AddTarget({ bucket, onClose, onDone }: { bucket: string; onClose: () => void; onDone: () => void }) {
  const [f, setF] = useState({ endpoint: "", secure: true, targetbucket: "", accessKey: "", secretKey: "", region: "", sync: false, bandwidth: "" });
  const [busy, setBusy] = useState(false);
  const set = (p: Partial<typeof f>) => setF({ ...f, ...p });
  const go = async () => {
    setBusy(true);
    try {
      const body = {
        sourcebucket: bucket,
        endpoint: f.endpoint.replace(/^https?:\/\//, "").replace(/\/+$/, ""),
        secure: f.secure,
        targetbucket: f.targetbucket,
        credentials: { accessKey: f.accessKey, secretKey: f.secretKey },
        region: f.region,
        path: "auto",
        api: "s3v4",
        type: "replication",
        replicationSync: f.sync,
        bandwidthlimit: (numOrUndef(f.bandwidth) || 0) * 1024 * 1024,
      };
      const arn = await admin<string>("/set-remote-target", { method: "PUT", query: { bucket }, body: JSON.stringify(body), encrypt: true });
      toast(`Remote target added${arn ? `: ${arn}` : ""}`);
      onDone();
      onClose();
    } catch (e) {
      toastError(e);
    } finally {
      setBusy(false);
    }
  };
  return (
    <Modal
      title="Add remote target"
      onClose={onClose}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" disabled={busy || !f.endpoint || !f.targetbucket || !f.accessKey} onClick={go}>
            Add
          </Button>
        </>
      }
    >
      <p class="hint">The remote bucket must exist and have versioning enabled.</p>
      <TextInput label="Endpoint (host:port)" value={f.endpoint} onInput={(v) => set({ endpoint: v })} placeholder="replica.example.com:9000" />
      <Toggle label="Use TLS" checked={f.secure} onChange={(v) => set({ secure: v })} />
      <div class="row">
        <TextInput label="Target bucket" value={f.targetbucket} onInput={(v) => set({ targetbucket: v })} />
        <TextInput label="Region" value={f.region} onInput={(v) => set({ region: v })} />
      </div>
      <div class="row">
        <TextInput label="Access key" value={f.accessKey} onInput={(v) => set({ accessKey: v })} autocomplete="off" />
        <TextInput label="Secret key" type="password" value={f.secretKey} onInput={(v) => set({ secretKey: v })} autocomplete="new-password" />
      </div>
      <div class="row">
        <TextInput label="Bandwidth limit (MiB/s)" type="number" min="0" value={f.bandwidth} onInput={(v) => set({ bandwidth: v })} hint="Empty for unlimited." />
      </div>
      <Toggle label="Synchronous replication" checked={f.sync} onChange={(v) => set({ sync: v })} />
    </Modal>
  );
}

// ---- CORS ----

export function CorsTab({ bucket }: { bucket: string }) {
  const raw = useRaw(bucket, "cors");
  const METHODS = ["GET", "PUT", "POST", "DELETE", "HEAD"];
  return (
    <Section state={raw}>
      {() => (
        <RuleList<CorsRule>
          title="CORS rules"
          intro="Allow browsers on other origins to call this bucket."
          raw={raw.data}
          rules={raw.data ? parseCors(parseXml(raw.data)) : []}
          columns={["ID", "Origins", "Methods", "Headers", "Max age"]}
          addLabel="Add CORS rule"
          blank={() => ({ id: "", origins: ["*"], methods: ["GET"], headers: [], expose: [], maxAge: undefined })}
          row={(r) => [<span class="mono">{r.id || "-"}</span>, r.origins.join(", "), r.methods.join(", "), r.headers.join(", ") || "-", r.maxAge === undefined ? "-" : `${r.maxAge}s`]}
          save={async (rules) => {
            await saveDoc(bucket, "cors", rules.length ? corsXml(rules) : null);
            toast("CORS saved");
            raw.reload();
          }}
          editor={(r, set) => (
            <>
              <TextInput label="Rule ID" value={r.id} onInput={(v) => set({ ...r, id: v })} />
              <ListInput label="Allowed origins" value={r.origins} onChange={(v) => set({ ...r, origins: v })} hint="Comma separated; * for any." />
              <fieldset class="bk-fieldset">
                <legend>Allowed methods</legend>
                {METHODS.map((m) => (
                  <label key={m} class="bk-check">
                    <input type="checkbox" checked={r.methods.includes(m)} onChange={(e) => set({ ...r, methods: (e.target as HTMLInputElement).checked ? [...r.methods, m] : r.methods.filter((x) => x !== m) })} />
                    {m}
                  </label>
                ))}
              </fieldset>
              <ListInput label="Allowed headers" value={r.headers} onChange={(v) => set({ ...r, headers: v })} />
              <ListInput label="Expose headers" value={r.expose} onChange={(v) => set({ ...r, expose: v })} />
              <TextInput label="Max age (seconds)" type="number" min="0" value={strOf(r.maxAge)} onInput={(v) => set({ ...r, maxAge: numOrUndef(v) })} />
            </>
          )}
        />
      )}
    </Section>
  );
}

// ---- events ----

const NOTIFY_SUBSYS = ["webhook", "kafka", "nats", "mqtt", "redis", "postgres", "mysql", "amqp", "elasticsearch", "nsq", "pulsar"];

async function eventArns(): Promise<string[]> {
  const region = await cluster.info().then((c) => c.region || "", () => "");
  const outs = await Promise.all(NOTIFY_SUBSYS.map((s) => s3Text(`${ADMIN}/get-config-kv`, { query: { key: `notify_${s}` } }).catch(() => "")));
  return outs.flatMap((t) => arnsFromConfigKv(t, region));
}

export function EventsTab({ bucket }: { bucket: string }) {
  const raw = useRaw(bucket, "notification");
  const arns = useAsync(eventArns, []);
  return (
    <Section state={raw}>
      {() => {
        const rules = raw.data ? parseNotification(parseXml(raw.data)) : [];
        const known = Array.from(new Set([...(arns.data || []), ...rules.map((r) => r.arn)]));
        return (
          <RuleList<NotifyRule>
            title="Event notifications"
            intro="Send bucket events to configured notification targets (see Events in the sidebar)."
            raw={raw.data}
            rules={rules}
            columns={["Target ARN", "Events", "Prefix", "Suffix"]}
            addLabel="Add event rule"
            blank={() => ({ kind: "Queue" as NotifyKind, id: "", arn: known[0] || "", events: ["s3:ObjectCreated:*"], prefix: "", suffix: "" })}
            row={(r) => [<span class="mono bk-small">{r.arn}</span>, r.events.join(", "), r.prefix || "-", r.suffix || "-"]}
            save={async (next) => {
              await saveDoc(bucket, "notification", notificationXml(next));
              toast("Event notifications saved");
              raw.reload();
            }}
            editor={(r, set) => (
              <>
                <TextInput label="Target ARN" value={r.arn} onInput={(v) => set({ ...r, arn: v })} {...{ list: "bk-arns" }} placeholder="arn:minio:sqs::id:webhook" hint={known.length ? undefined : "No enabled notification targets were found."} />
                <datalist id="bk-arns">
                  {known.map((a) => (
                    <option key={a} value={a} />
                  ))}
                </datalist>
                <fieldset class="bk-fieldset">
                  <legend>Events</legend>
                  {EVENT_TYPES.map((ev) => (
                    <label key={ev} class="bk-check">
                      <input type="checkbox" checked={r.events.includes(ev)} onChange={(e) => set({ ...r, events: (e.target as HTMLInputElement).checked ? [...r.events, ev] : r.events.filter((x) => x !== ev) })} />
                      <span class="mono">{ev}</span>
                    </label>
                  ))}
                </fieldset>
                <div class="row">
                  <TextInput label="Prefix filter" value={r.prefix} onInput={(v) => set({ ...r, prefix: v })} />
                  <TextInput label="Suffix filter" value={r.suffix} onInput={(v) => set({ ...r, suffix: v })} />
                </div>
              </>
            )}
          />
        );
      }}
    </Section>
  );
}
