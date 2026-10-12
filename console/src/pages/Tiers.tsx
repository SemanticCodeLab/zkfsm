import { useState } from "preact/hooks";
import { admin } from "../lib/api";
import { bytes } from "../lib/format";
import { Badge, Button, Card, Confirm, Empty, Loading, Modal, PageHeader, Select, TextInput, toast, toastError, useAsync } from "../components/ui";
import { isUnavailable, Unavailable } from "./ops/common";
import "./ops/ops.css";

type TierType = "minio" | "s3" | "azure" | "gcs";
const sections: Record<TierType, string> = { minio: "MinIO", s3: "S3", azure: "Azure", gcs: "GCS" };
const typeLabels: [TierType, string][] = [
  ["minio", "S3-compatible (MinIO, zkfsm, ...)"],
  ["s3", "S3 service"],
  ["azure", "Azure Blob Storage"],
  ["gcs", "Google Cloud Storage"],
];

interface TierCfg {
  Version: string;
  Type: TierType;
  Name: string;
  [section: string]: unknown;
}
interface TierStat {
  Name: string;
  Type: string;
  Stats: { totalSize: number; numVersions: number; numObjects: number };
}

function section(t: TierCfg): Record<string, string> {
  return (t[sections[t.Type]] as Record<string, string>) || {};
}

interface Form {
  type: TierType;
  name: string;
  endpoint: string;
  bucket: string;
  prefix: string;
  region: string;
  storageClass: string;
  access: string;
  secret: string;
}

const empty: Form = { type: "minio", name: "", endpoint: "", bucket: "", prefix: "", region: "", storageClass: "", access: "", secret: "" };

/** Body for PUT /tier; GCS takes an HMAC credentials file as base64. */
export function tierBody(f: Form): unknown {
  const s: Record<string, string> = { Endpoint: f.endpoint.trim(), Bucket: f.bucket.trim() };
  if (f.prefix.trim()) s.Prefix = f.prefix.trim();
  if (f.region.trim()) s.Region = f.region.trim();
  if (f.storageClass.trim() && f.type !== "minio") s.StorageClass = f.storageClass.trim();
  if (f.type === "azure") Object.assign(s, { AccountName: f.access, AccountKey: f.secret });
  else if (f.type === "gcs") s.Creds = btoa(JSON.stringify({ access_key: f.access, secret_key: f.secret }));
  else Object.assign(s, { AccessKey: f.access, SecretKey: f.secret });
  return { Version: "v1", Type: f.type, Name: f.name.trim().toUpperCase(), [sections[f.type]]: s };
}

const credLabels = (t: TierType): [string, string] => (t === "azure" ? ["Account name", "Account key"] : t === "gcs" ? ["HMAC access ID", "HMAC secret"] : ["Access key", "Secret key"]);

function AddTier({ onClose, onDone }: { onClose: () => void; onDone: () => void }) {
  const [f, setF] = useState<Form>(empty);
  const [busy, setBusy] = useState(false);
  const set = (k: keyof Form) => (v: string) => setF({ ...f, [k]: v });
  const nameErr = !f.name ? null : !/^[A-Za-z0-9_-]+$/.test(f.name) ? "Letters, digits, '-' and '_' only." : f.name.toUpperCase() === "STANDARD" ? "STANDARD is reserved." : null;
  const ready = f.name && !nameErr && f.bucket && f.access && f.secret && (f.endpoint || f.type === "s3" || f.type === "gcs");
  const [ak, sk] = credLabels(f.type);
  const submit = async () => {
    setBusy(true);
    try {
      await admin("/tier", { method: "PUT", encrypt: true, headers: { "content-type": "application/json" }, body: JSON.stringify(tierBody(f)) });
      toast(`Tier ${f.name.toUpperCase()} added`);
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
      title="Add tier"
      onClose={onClose}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" onClick={submit} disabled={busy || !ready}>
            {busy ? "Verifying…" : "Add tier"}
          </Button>
        </>
      }
    >
      <Select label="Type" value={f.type} onChange={(v) => setF({ ...f, type: v as TierType })} options={typeLabels} />
      <div class="row">
        <TextInput label="Name" value={f.name} onInput={set("name")} error={nameErr} hint="Stored upper-case; referenced by lifecycle transition rules." autofocus />
        <TextInput label="Endpoint" value={f.endpoint} onInput={set("endpoint")} placeholder={f.type === "azure" ? "https://account.blob.core.windows.net" : "https://host:9000"} hint={f.type === "s3" || f.type === "gcs" ? "Optional; defaults to the provider endpoint." : undefined} />
      </div>
      <div class="row">
        <TextInput label={f.type === "azure" ? "Container" : "Bucket"} value={f.bucket} onInput={set("bucket")} />
        <TextInput label="Prefix" value={f.prefix} onInput={set("prefix")} hint="Optional" />
      </div>
      <div class="row">
        <TextInput label="Region" value={f.region} onInput={set("region")} hint="Optional" />
        {f.type !== "minio" && <TextInput label="Storage class" value={f.storageClass} onInput={set("storageClass")} hint="Optional" />}
      </div>
      <div class="row">
        <TextInput label={ak} value={f.access} onInput={set("access")} autocomplete="off" />
        <TextInput label={sk} type="password" value={f.secret} onInput={set("secret")} autocomplete="new-password" />
      </div>
      <p class="hint">The server checks the remote bucket before saving. Credentials are sent encrypted.</p>
    </Modal>
  );
}

function EditCreds({ tier, onClose, onDone }: { tier: TierCfg; onClose: () => void; onDone: () => void }) {
  const [access, setAccess] = useState("");
  const [secret, setSecret] = useState("");
  const [busy, setBusy] = useState(false);
  const [ak, sk] = credLabels(tier.Type);
  const submit = async () => {
    setBusy(true);
    const body = tier.Type === "gcs" ? { creds: btoa(JSON.stringify({ access_key: access, secret_key: secret })) } : { access, secret };
    try {
      await admin(`/tier/${encodeURIComponent(tier.Name)}`, { method: "POST", encrypt: true, headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
      toast(`Credentials of ${tier.Name} updated`);
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
      title={`Edit credentials: ${tier.Name}`}
      onClose={onClose}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" onClick={submit} disabled={busy || (tier.Type === "gcs" ? !access || !secret : !access && !secret)}>
            Save
          </Button>
        </>
      }
    >
      <TextInput label={ak} value={access} onInput={setAccess} autocomplete="off" autofocus hint={tier.Type === "gcs" ? undefined : "Leave blank to keep the current value."} />
      <TextInput label={sk} type="password" value={secret} onInput={setSecret} autocomplete="new-password" />
    </Modal>
  );
}

export function Tiers() {
  const tiers = useAsync(() => admin<TierCfg[]>("/tier"));
  const stats = useAsync(() => admin<TierStat[]>("/tier-stats"));
  const [adding, setAdding] = useState(false);
  const [editing, setEditing] = useState<TierCfg | null>(null);
  const [removing, setRemoving] = useState<TierCfg | null>(null);
  const [checking, setChecking] = useState<string | null>(null);
  const reload = () => {
    tiers.reload();
    stats.reload();
  };
  const verify = async (name: string) => {
    setChecking(name);
    try {
      await admin(`/tier/${encodeURIComponent(name)}`);
      toast(`Tier ${name} is reachable`);
    } catch (e) {
      toastError(e);
    } finally {
      setChecking(null);
    }
  };
  if (tiers.error && isUnavailable(tiers.error))
    return (
      <>
        <PageHeader title="Tiers" />
        <Unavailable title="Remote tiers are not available on this server." />
      </>
    );
  const statOf = (n: string) => stats.data?.find((s) => s.Name === n)?.Stats;
  const hot = statOf("STANDARD");
  return (
    <>
      <PageHeader
        title="Tiers"
        actions={
          <>
            <Button onClick={reload}>Refresh</Button>
            <Button variant="primary" onClick={() => setAdding(true)}>
              Add tier
            </Button>
          </>
        }
      >
        <p class="hint">Remote storage that lifecycle rules can transition objects to.</p>
      </PageHeader>
      {hot && (
        <Card title="Local storage (STANDARD)">
          <p>
            {bytes(hot.totalSize)} in {hot.numObjects.toLocaleString()} objects ({hot.numVersions.toLocaleString()} versions)
          </p>
        </Card>
      )}
      <Card title="Remote tiers">
        <Loading state={tiers}>
          {() =>
            tiers.data!.length ? (
              <table>
                <thead>
                  <tr>
                    <th scope="col">Name</th>
                    <th scope="col">Type</th>
                    <th scope="col">Endpoint</th>
                    <th scope="col">Bucket / prefix</th>
                    <th scope="col" class="num">Objects</th>
                    <th scope="col" class="num">Versions</th>
                    <th scope="col" class="num">Size</th>
                    <th scope="col">
                      <span class="sr-only">Actions</span>
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {tiers.data!.map((t) => {
                    const s = section(t);
                    const st = statOf(t.Name);
                    return (
                      <tr key={t.Name}>
                        <td>
                          <strong>{t.Name}</strong>
                        </td>
                        <td>
                          <Badge>{sections[t.Type] || t.Type}</Badge>
                        </td>
                        <td class="ops-mono">{s.Endpoint || "default"}</td>
                        <td class="ops-mono">
                          {s.Bucket}
                          {s.Prefix ? `/${s.Prefix}` : ""}
                        </td>
                        <td class="ops-num">{st ? st.numObjects.toLocaleString() : "-"}</td>
                        <td class="ops-num">{st ? st.numVersions.toLocaleString() : "-"}</td>
                        <td class="ops-num">{st ? bytes(st.totalSize) : "-"}</td>
                        <td>
                          <div class="actions">
                            <Button small onClick={() => verify(t.Name)} disabled={checking === t.Name}>
                              Verify
                            </Button>
                            <Button small onClick={() => setEditing(t)}>
                              Credentials
                            </Button>
                            <Button small variant="danger" onClick={() => setRemoving(t)}>
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
              <Empty>No remote tiers configured.</Empty>
            )
          }
        </Loading>
      </Card>
      {adding && <AddTier onClose={() => setAdding(false)} onDone={reload} />}
      {editing && <EditCreds tier={editing} onClose={() => setEditing(null)} onDone={reload} />}
      {removing && (
        <Confirm
          title={`Remove tier ${removing.Name}`}
          message="A tier that still holds transitioned objects cannot be removed. Objects already on the remote are not deleted."
          confirmLabel="Remove"
          onConfirm={async () => {
            await admin(`/tier/${encodeURIComponent(removing.Name)}`, { method: "DELETE" });
            toast(`Tier ${removing.Name} removed`);
            reload();
          }}
          onClose={() => setRemoving(null)}
        />
      )}
    </>
  );
}
