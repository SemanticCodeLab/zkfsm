import { useState } from "preact/hooks";
import { cluster } from "../lib/api";
import { navigate, useRoute } from "../lib/router";
import { Badge, Button, Card, Confirm, Empty, Loading, Modal, PageHeader, Select, Tabs, TextInput, Toggle, toast, toastError, useAsync } from "../components/ui";
import { arnFor, DEFAULT_ID, enabled, formatLine, get, isPlaceholder, isSecretKey, KvEntry, targetKey, targetKinds, validId } from "./ops/configkv";
import { auditSubsystems, delConfig, getConfig, helpConfig, notifySubsystems, setConfig } from "./ops/configApi";
import { isUnavailable } from "./ops/common";
import "./ops/ops.css";

const kindOf = (subsys: string) => targetKinds.find((k) => subsys.endsWith(`_${k.type}`))!;
const summaryKeys = ["endpoint", "brokers", "url", "address", "host", "nsqd_address", "server", "topic", "exchange", "index", "table", "key"];

function summary(e: KvEntry): string {
  const parts: string[] = [];
  for (const k of summaryKeys) {
    const v = get(e, k);
    if (v && !isSecretKey(k)) parts.push(k === "endpoint" || k === "brokers" || k === "address" || k === "host" ? v : `${k}=${v}`);
    if (parts.length === 2) break;
  }
  return parts.join(" ") || "-";
}

async function loadAll(subs: string[]): Promise<{ subsys: string; entries: KvEntry[]; error?: string }[]> {
  return Promise.all(
    subs.map((s) =>
      getConfig(s).then(
        (entries) => ({ subsys: s, entries: entries.filter((e) => !isPlaceholder(e)) }),
        (e) => ({ subsys: s, entries: [], error: isUnavailable(e) ? undefined : (e as Error).message }),
      ),
    ),
  );
}

function TargetForm({ audit, existing, onClose, onDone }: { audit: boolean; existing?: KvEntry; onClose: () => void; onDone: () => void }) {
  const subs = audit ? auditSubsystems : notifySubsystems;
  const [subsys, setSubsys] = useState(existing?.subsys ?? subs[0]);
  const [id, setId] = useState(existing ? (existing.id === DEFAULT_ID ? "" : existing.id) : "");
  const [on, setOn] = useState(existing ? enabled(existing) : true);
  const [vals, setVals] = useState<Record<string, string>>(() => Object.fromEntries((existing?.kvs ?? []).filter(([k]) => !isSecretKey(k)).map(([k, v]) => [k, v])));
  const [busy, setBusy] = useState(false);
  const help = useAsync(() => helpConfig(subsys), [subsys]);
  const idErr = id && !validId(id) ? "Letters, digits, '.', '_' and '-' (max 64)." : null;
  const submit = async () => {
    const kvs: [string, string][] = [["enable", on ? "on" : "off"]];
    for (const k of help.data?.keysHelp ?? []) if (k.key !== "enable" && vals[k.key] !== undefined && !(existing && isSecretKey(k.key) && vals[k.key] === "")) kvs.push([k.key, vals[k.key]]);
    setBusy(true);
    try {
      await setConfig(formatLine({ subsys, id: id || DEFAULT_ID, kvs }));
      toast(`Target ${targetKey(subsys, id || DEFAULT_ID)} saved`);
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
      wide
      title={existing ? `Edit ${targetKey(existing.subsys, existing.id)}` : audit ? "Add audit target" : "Add notification target"}
      onClose={onClose}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" onClick={submit} disabled={busy || !!idErr || !help.data}>
            Save
          </Button>
        </>
      }
    >
      <div class="row">
        {existing ? (
          <TextInput label="Type" value={kindOf(subsys).label} onInput={() => {}} readOnly />
        ) : (
          <Select label="Type" value={subsys} onChange={(v) => (setSubsys(v), setVals({}))} options={subs.map((s) => [s, kindOf(s).label] as [string, string])} />
        )}
        <TextInput label="Identifier" value={id} onInput={setId} error={idErr} readOnly={!!existing} hint={audit ? "Optional name for this target." : "Part of the ARN used in bucket notification rules."} />
      </div>
      <Toggle label="Enabled" checked={on} onChange={setOn} />
      <Loading state={help}>
        {() => (
          <div class="row">
            {help.data!.keysHelp
              .filter((k) => k.key !== "enable")
              .map((k) => (
                <TextInput
                  key={k.key}
                  label={k.key}
                  type={isSecretKey(k.key) ? "password" : "text"}
                  autocomplete={isSecretKey(k.key) ? "new-password" : "off"}
                  value={vals[k.key] ?? ""}
                  onInput={(v) => setVals({ ...vals, [k.key]: v })}
                  hint={isSecretKey(k.key) && existing ? "Leave blank to keep the current value." : k.description || undefined}
                />
              ))}
          </div>
        )}
      </Loading>
      <p class="hint">The server validates the settings before saving; a target that cannot be reached is rejected.</p>
    </Modal>
  );
}

function TargetsTab({ audit }: { audit: boolean }) {
  const subs = audit ? auditSubsystems : notifySubsystems;
  const data = useAsync(() => loadAll(subs), [audit]);
  const info = useAsync(() => cluster.info());
  const [form, setForm] = useState<{ existing?: KvEntry } | null>(null);
  const [removing, setRemoving] = useState<KvEntry | null>(null);
  const region = info.data?.region ?? "";
  const rows = (data.data ?? []).flatMap((g) => g.entries);
  const failed = (data.data ?? []).filter((g) => g.error);
  return (
    <Card
      title={audit ? "Audit targets" : "Notification targets"}
      actions={
        <>
          <Button small onClick={data.reload}>
            Refresh
          </Button>
          <Button small variant="primary" onClick={() => setForm({})}>
            {audit ? "Add audit target" : "Add target"}
          </Button>
        </>
      }
    >
      <p class="hint">{audit ? "Every API request is logged to each enabled audit target." : "Buckets send events to these targets through notification rules that reference the target ARN."}</p>
      <Loading state={data}>
        {() =>
          rows.length ? (
            <table>
              <thead>
                <tr>
                  <th scope="col">Type</th>
                  <th scope="col">Identifier</th>
                  <th scope="col">State</th>
                  <th scope="col">Destination</th>
                  {!audit && <th scope="col">ARN</th>}
                  <th scope="col">
                    <span class="sr-only">Actions</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {rows.map((e) => {
                  const k = kindOf(e.subsys);
                  return (
                    <tr key={targetKey(e.subsys, e.id)}>
                      <td>{k.label}</td>
                      <td>{e.id === DEFAULT_ID ? <span class="hint">default</span> : e.id}</td>
                      <td>
                        <Badge kind={enabled(e) ? "ok" : "default"}>{enabled(e) ? "enabled" : "disabled"}</Badge>
                      </td>
                      <td class="ops-mono">{summary(e)}</td>
                      {!audit && <td class="ops-mono">{arnFor(region, e.id, k.arn)}</td>}
                      <td>
                        <div class="actions">
                          <Button small onClick={() => setForm({ existing: e })}>
                            Edit
                          </Button>
                          <Button small variant="danger" onClick={() => setRemoving(e)} aria-label={`Remove ${targetKey(e.subsys, e.id)}`}>
                            Remove
                          </Button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          ) : (
            <Empty>No {audit ? "audit" : "notification"} targets configured.</Empty>
          )
        }
      </Loading>
      {failed.length > 0 && (
        <div class="notice notice-warn" role="alert">
          Could not read {failed.map((g) => g.subsys).join(", ")}: {failed[0].error}
        </div>
      )}
      {form && <TargetForm audit={audit} existing={form.existing} onClose={() => setForm(null)} onDone={data.reload} />}
      {removing && (
        <Confirm
          title="Remove target"
          message={
            <>
              Remove <strong>{targetKey(removing.subsys, removing.id)}</strong>?{!audit && " Notification rules that reference its ARN stop delivering."}
            </>
          }
          confirmLabel="Remove"
          onConfirm={async () => {
            await delConfig(targetKey(removing.subsys, removing.id));
            toast("Target removed");
            data.reload();
          }}
          onClose={() => setRemoving(null)}
        />
      )}
    </Card>
  );
}

const tabs: [string, string][] = [
  ["notify", "Notification targets"],
  ["audit", "Audit targets"],
];

export function Events() {
  const route = useRoute();
  const tab = route.params.get("tab") === "audit" ? "audit" : "notify";
  return (
    <>
      <PageHeader title="Events" />
      <Tabs tabs={tabs} active={tab} onChange={(k) => navigate("/events", { tab: k })} />
      <div role="tabpanel" aria-label={tab === "audit" ? "Audit targets" : "Notification targets"}>
        <TargetsTab key={tab} audit={tab === "audit"} />
      </div>
    </>
  );
}
