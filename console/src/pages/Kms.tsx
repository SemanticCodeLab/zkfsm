import type preact from "preact";
import { useState } from "preact/hooks";
import { json, KMS } from "../lib/api";
import { date } from "../lib/format";
import { Badge, Button, Card, Empty, KeyValue, Loading, Modal, PageHeader, Select, TextInput, Toggle, toast, toastError, useAsync } from "../components/ui";
import { PairsEditor } from "./buckets/common";
import { KmsMetrics, opRows, RekeyPage, rekeySummary, saveText } from "./ops/kms";
import { isUnavailable, Unavailable } from "./ops/common";
import "./ops/ops.css";

interface KmsStatus {
  name?: string;
  "default-key-id"?: string;
  state?: { Version?: string; KeyStoreReachable?: boolean; KeystoreAvailable?: boolean };
}
interface KeyItem {
  name: string;
  createdAt?: string;
  createdBy?: string;
  state?: "enabled" | "disabled" | string;
  version?: number;
}
interface KmsConfig {
  backend?: string;
  "default-key-id"?: string;
  dir?: string;
  vault?: { addr?: string; engine?: string; namespace?: string } | null;
  "kms-api"?: { region?: string; endpoint?: string } | null;
}
interface KeyStatus {
  "key-id": string;
  "encryption-error"?: string;
  "decryption-error"?: string;
}

const kms = <T,>(op: string, opts: Parameters<typeof json>[1] = {}) => json<T>(`/api/v1/s3${KMS}${op}`, opts);

const validKey = (k: string) => (/^[A-Za-z0-9_-][A-Za-z0-9_.-]{0,127}$/.test(k) ? null : "Up to 128 letters, digits, '.', '_' and '-'; must not start with '.'.");

function CreateKey({ onClose, onDone }: { onClose: () => void; onDone: () => void }) {
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);
  const err = name ? validKey(name) : null;
  const submit = async (e: Event) => {
    e.preventDefault();
    setBusy(true);
    try {
      await kms("/key/create", { method: "POST", query: { "key-id": name } });
      toast(`Key ${name} created`);
      onDone();
      onClose();
    } catch (x) {
      toastError(x);
    } finally {
      setBusy(false);
    }
  };
  return (
    <Modal
      title="Create key"
      onClose={onClose}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" type="submit" disabled={busy || !name || !!err} onClick={submit}>
            Create
          </Button>
        </>
      }
    >
      <form onSubmit={submit}>
        <TextInput label="Key name" value={name} onInput={setName} error={err} autofocus hint="Used as the key ID for SSE-KMS." />
      </form>
    </Modal>
  );
}

function StatusModal({ id, onClose }: { id: string; onClose: () => void }) {
  const st = useAsync(() => kms<KeyStatus>("/key/status", { query: { "key-id": id } }), [id]);
  return (
    <Modal title={`Key status: ${id}`} onClose={onClose} footer={<Button onClick={onClose}>Close</Button>}>
      <Loading state={st}>
        {() => {
          const s = st.data!;
          const bad = s["encryption-error"] || s["decryption-error"];
          return (
            <KeyValue
              rows={[
                ["Key", s["key-id"]],
                ["Encryption", s["encryption-error"] ? <Badge kind="error">{s["encryption-error"]}</Badge> : <Badge kind="ok">ok</Badge>],
                ["Decryption", s["decryption-error"] ? <Badge kind="error">{s["decryption-error"]}</Badge> : bad ? "-" : <Badge kind="ok">ok</Badge>],
              ]}
            />
          );
        }}
      </Loading>
    </Modal>
  );
}

function TagsModal({ id, onClose }: { id: string; onClose: () => void }) {
  const cur = useAsync(() => kms<{ tags?: Record<string, string> }>("/key/tags", { query: { "key-id": id } }), [id]);
  const [pairs, setPairs] = useState<[string, string][] | null>(null);
  const [busy, setBusy] = useState(false);
  const rows = pairs ?? Object.entries(cur.data?.tags ?? {});
  const save = async () => {
    setBusy(true);
    try {
      const tags = Object.fromEntries(rows.filter(([k]) => k.trim()));
      if (Object.keys(tags).length) await kms("/key/tags", { method: "PUT", query: { "key-id": id }, headers: { "content-type": "application/json" }, body: JSON.stringify({ tags }) });
      else await kms("/key/tags", { method: "DELETE", query: { "key-id": id } });
      toast(`Tags of ${id} saved`);
      onClose();
    } catch (e) {
      toastError(e);
    } finally {
      setBusy(false);
    }
  };
  return (
    <Modal
      title={`Key tags: ${id}`}
      onClose={onClose}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" onClick={save} disabled={busy || !cur.data}>
            Save
          </Button>
        </>
      }
    >
      <Loading state={cur}>{() => <PairsEditor pairs={rows} onChange={setPairs} />}</Loading>
    </Modal>
  );
}

function DeleteKey({ id, onClose, onDone }: { id: string; onClose: () => void; onDone: () => void }) {
  const [force, setForce] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const run = async () => {
    setBusy(true);
    setErr(null);
    try {
      await kms("/key/delete", { method: "DELETE", query: { "key-id": id, force: force ? "true" : undefined } });
      toast(`Key ${id} deleted`);
      onDone();
      onClose();
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  return (
    <Modal
      title="Delete key"
      onClose={onClose}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="danger" onClick={run} disabled={busy}>
            Delete
          </Button>
        </>
      }
    >
      <p>
        Delete <strong>{id}</strong>? Objects sealed under a deleted key cannot be read again.
      </p>
      <Toggle label="Delete even if the key is still in use" checked={force} onChange={setForce} />
      {err && (
        <div class="notice notice-error" role="alert">
          {err}
        </div>
      )}
    </Modal>
  );
}

function Rekey({ keys, onClose }: { keys: string[]; onClose: () => void }) {
  const [bucket, setBucket] = useState("");
  const [prefix, setPrefix] = useState("");
  const [to, setTo] = useState(keys[0] ?? "");
  const [from, setFrom] = useState("");
  const [busy, setBusy] = useState(false);
  const [pages, setPages] = useState<RekeyPage[]>([]);
  const run = async () => {
    setBusy(true);
    setPages([]);
    try {
      let marker: string | undefined;
      let vmarker: string | undefined;
      const all: RekeyPage[] = [];
      // One page per call; follow the markers until the listing ends.
      for (let i = 0; i < 10_000; i++) {
        const p = await kms<RekeyPage>("/key/rekey", { method: "POST", query: { bucket, prefix: prefix || undefined, "key-id": to, "from-key-id": from || undefined, marker, "version-marker": vmarker } });
        all.push(p);
        setPages([...all]);
        if (!p.truncated || !p["next-marker"]) break;
        marker = p["next-marker"];
        vmarker = p["next-version-marker"] || undefined;
      }
      toast("Re-key finished");
    } catch (e) {
      toastError(e);
    } finally {
      setBusy(false);
    }
  };
  const sum = rekeySummary(pages);
  return (
    <Modal
      wide
      title="Re-key objects"
      onClose={onClose}
      footer={
        <>
          <Button onClick={onClose}>Close</Button>
          <Button variant="primary" onClick={run} disabled={busy || !bucket || !to}>
            {busy ? "Re-keying…" : "Re-key"}
          </Button>
        </>
      }
    >
      <p class="hint">Re-seals the data keys of encrypted objects under another key. Object data is not rewritten.</p>
      <div class="row">
        <TextInput label="Bucket" value={bucket} onInput={setBucket} autofocus />
        <TextInput label="Prefix" value={prefix} onInput={setPrefix} hint="Optional" />
      </div>
      <div class="row">
        <Select label="New key" value={to} onChange={setTo} options={keys} />
        <Select label="Only objects sealed under" value={from} onChange={setFrom} options={[["", "Any key"], ...keys.map((k) => [k, k] as [string, string])]} />
      </div>
      {pages.length > 0 && (
        <KeyValue
          rows={[
            ["Scanned", sum.scanned],
            ["Re-keyed", sum.rekeyed],
            ["Skipped", sum.skipped],
            ["Failed", sum.failed ? <Badge kind="error">{sum.failed}</Badge> : 0],
            ...(sum.firstError ? ([["First error", sum.firstError]] as [string, string][]) : []),
          ]}
        />
      )}
    </Modal>
  );
}

function BackendCard() {
  const cfg = useAsync(() => kms<KmsConfig>("/config"));
  const metrics = useAsync(() => kms<KmsMetrics>("/metrics"));
  const [busy, setBusy] = useState(false);
  const backup = async () => {
    setBusy(true);
    try {
      const doc = await kms<unknown>("/backup", { method: "POST" });
      saveText(`kms-backup-${new Date().toISOString().slice(0, 10)}.json`, JSON.stringify(doc, null, 2));
    } catch (e) {
      toastError(e);
    } finally {
      setBusy(false);
    }
  };
  if (cfg.error && isUnavailable(cfg.error)) return null;
  const ops = opRows(metrics.data);
  return (
    <Card
      title="Backend"
      actions={
        <Button small onClick={backup} disabled={busy}>
          Download key manifest
        </Button>
      }
    >
      <Loading state={cfg}>
        {() => {
          const c = cfg.data!;
          return (
            <KeyValue
              rows={[
                ["Type", c.backend || "-"],
                ...(c.dir ? ([["Key directory", <span class="ops-mono">{c.dir}</span>]] as [string, preact.ComponentChildren][]) : []),
                ...(c.vault ? ([["Vault", `${c.vault.addr || "-"} (${c.vault.engine || "transit"})`]] as [string, string][]) : []),
                ...(c["kms-api"] ? ([["Key service", `${c["kms-api"].endpoint || c["kms-api"].region || "-"}`]] as [string, string][]) : []),
                ["Re-keyed objects", metrics.data?.rekeyed_objects ?? "-"],
              ]}
            />
          );
        }}
      </Loading>
      {ops.length > 0 && (
        <table>
          <caption class="sr-only">KMS operations</caption>
          <thead>
            <tr>
              <th scope="col">Operation</th>
              <th scope="col" class="num">Requests</th>
              <th scope="col" class="num">Errors</th>
              <th scope="col" class="num">Mean latency</th>
            </tr>
          </thead>
          <tbody>
            {ops.map((o) => (
              <tr key={o.name}>
                <td>{o.name}</td>
                <td class="ops-num">{o.requests}</td>
                <td class="ops-num">{o.errors}</td>
                <td class="ops-num">{o.meanMs === null ? "-" : `${o.meanMs.toFixed(2)} ms`}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <p class="hint">The manifest lists every key with a digest. Sealed key material and backend changes are done with the admin API.</p>
    </Card>
  );
}

export function Kms() {
  const status = useAsync(() => kms<KmsStatus>("/status"));
  const keys = useAsync(() => kms<KeyItem[]>("/key/list", { query: { pattern: "*" } }));
  const [filter, setFilter] = useState("");
  const [creating, setCreating] = useState(false);
  const [checking, setChecking] = useState<string | null>(null);
  const [rotating, setRotating] = useState<string | null>(null);
  const [tagging, setTagging] = useState<string | null>(null);
  const [deleting, setDeleting] = useState<string | null>(null);
  const [rekeying, setRekeying] = useState(false);
  const setState = async (id: string, on: boolean) => {
    try {
      await kms(on ? "/key/enable" : "/key/disable", { method: "POST", query: { "key-id": id } });
      toast(`Key ${id} ${on ? "enabled" : "disabled"}`);
      keys.reload();
    } catch (e) {
      toastError(e);
    }
  };
  const rotate = async (id: string) => {
    setRotating(id);
    try {
      await kms("/key/rotate", { method: "POST", query: { "key-id": id } });
      toast(`Key ${id} rotated`);
      keys.reload();
    } catch (e) {
      toastError(e);
    } finally {
      setRotating(null);
    }
  };
  if (status.error && isUnavailable(status.error))
    return (
      <>
        <PageHeader title="KMS Keys" />
        <Unavailable title="KMS is not configured on this server.">Start the server with a KMS backend (a static master key or an external key service) to manage SSE-KMS keys here.</Unavailable>
      </>
    );
  const def = status.data?.["default-key-id"];
  const list = (keys.data || []).filter((k) => !filter || k.name.toLowerCase().includes(filter.toLowerCase()));
  return (
    <>
      <PageHeader
        title="KMS Keys"
        actions={
          <>
            <Button onClick={() => setRekeying(true)}>Re-key objects</Button>
            <Button variant="primary" onClick={() => setCreating(true)}>
              Create key
            </Button>
          </>
        }
      />
      <Card title="Status">
        <Loading state={status}>
          {() => {
            const s = status.data!;
            const ok = s.state?.KeyStoreReachable !== false && s.state?.KeystoreAvailable !== false;
            return (
              <KeyValue
                rows={[
                  ["Backend", s.name || "-"],
                  ["Default key", def || "-"],
                  ["Version", s.state?.Version || "-"],
                  ["Key store", <Badge kind={ok ? "ok" : "error"}>{ok ? "reachable" : "unreachable"}</Badge>],
                ]}
              />
            );
          }}
        </Loading>
      </Card>
      <Card title="Keys" actions={<Button small onClick={keys.reload}>Refresh</Button>}>
        <div class="ops-toolbar">
          <TextInput label="Filter keys" type="search" value={filter} onInput={setFilter} />
        </div>
        <Loading state={keys}>
          {() =>
            list.length ? (
              <table>
                <thead>
                  <tr>
                    <th scope="col">Name</th>
                    <th scope="col">State</th>
                    <th scope="col" class="num">Version</th>
                    <th scope="col">Created</th>
                    <th scope="col">
                      <span class="sr-only">Actions</span>
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {list.map((k) => (
                    <tr key={k.name}>
                      <td>
                        {k.name} {k.name === def && <Badge>default</Badge>}
                      </td>
                      <td>{k.state ? <Badge kind={k.state === "enabled" ? "ok" : "warn"}>{k.state}</Badge> : "-"}</td>
                      <td class="ops-num">{k.version ?? "-"}</td>
                      <td>{date(k.createdAt)}</td>
                      <td>
                        <div class="actions">
                          <Button small onClick={() => setChecking(k.name)}>
                            Status
                          </Button>
                          <Button small onClick={() => rotate(k.name)} disabled={rotating === k.name}>
                            Rotate
                          </Button>
                          {k.state && (
                            <Button small onClick={() => setState(k.name, k.state !== "enabled")} aria-label={`${k.state === "enabled" ? "Disable" : "Enable"} ${k.name}`}>
                              {k.state === "enabled" ? "Disable" : "Enable"}
                            </Button>
                          )}
                          <Button small onClick={() => setTagging(k.name)} aria-label={`Tags of ${k.name}`}>
                            Tags
                          </Button>
                          <Button small variant="danger" onClick={() => setDeleting(k.name)} aria-label={`Delete ${k.name}`} disabled={k.name === def}>
                            Delete
                          </Button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : (
              <Empty>{filter ? "No key matches the filter." : "No keys yet."}</Empty>
            )
          }
        </Loading>
      </Card>
      <BackendCard />
      {tagging && <TagsModal id={tagging} onClose={() => setTagging(null)} />}
      {deleting && <DeleteKey id={deleting} onClose={() => setDeleting(null)} onDone={keys.reload} />}
      {rekeying && <Rekey keys={(keys.data || []).map((k) => k.name)} onClose={() => setRekeying(false)} />}
      {creating && <CreateKey onClose={() => setCreating(false)} onDone={keys.reload} />}
      {checking && <StatusModal id={checking} onClose={() => setChecking(null)} />}
    </>
  );
}
