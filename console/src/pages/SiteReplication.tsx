import { useState } from "preact/hooks";
import { admin } from "../lib/api";
import { Badge, Button, Card, Confirm, Empty, KeyValue, Loading, Modal, PageHeader, TextInput, toast, toastError, useAsync } from "../components/ui";
import "./ops/ops.css";

interface Peer {
  name: string;
  endpoint: string;
  deploymentID: string;
}
interface Info {
  enabled: boolean;
  name?: string;
  sites?: Peer[];
  serviceAccountAccessKey?: string;
}
interface Status {
  Enabled: boolean;
  MaxBuckets?: number;
  MaxUsers?: number;
  MaxGroups?: number;
  MaxPolicies?: number;
  Sites?: Record<string, Peer>;
  StatsSummary?: Record<string, Record<string, number>>;
}
interface SiteForm {
  name: string;
  endpoints: string;
  accessKey: string;
  secretKey: string;
}
interface AddResult {
  success?: boolean;
  status?: string;
  errorDetail?: string;
}

const blank = (): SiteForm => ({ name: "", endpoints: "", accessKey: "", secretKey: "" });

function siteErr(s: SiteForm): string | null {
  if (!s.name.trim()) return "Name is required.";
  if (!/^https?:\/\/[^\s/]+/.test(s.endpoints.trim())) return "Endpoint must be an http(s) URL.";
  if (!s.accessKey || !s.secretKey) return "Access and secret key are required.";
  return null;
}

function SiteFields({ s, set, idx }: { s: SiteForm; set: (s: SiteForm) => void; idx: number }) {
  return (
    <fieldset class="card">
      <legend>{idx === 0 ? "This site" : `Peer site ${idx}`}</legend>
      <div class="row">
        <TextInput label="Name" value={s.name} onInput={(v) => set({ ...s, name: v })} autofocus={idx === 0} />
        <TextInput label="Endpoint" value={s.endpoints} onInput={(v) => set({ ...s, endpoints: v })} placeholder="https://site.example.net:9000" />
      </div>
      <div class="row">
        <TextInput label="Access key" value={s.accessKey} onInput={(v) => set({ ...s, accessKey: v })} autocomplete="off" />
        <TextInput label="Secret key" type="password" value={s.secretKey} onInput={(v) => set({ ...s, secretKey: v })} autocomplete="new-password" />
      </div>
    </fieldset>
  );
}

function AddSites({ info, onClose, onDone }: { info: Info; onClose: () => void; onDone: () => void }) {
  // The receiving site must always be in the list; existing peers are kept.
  const me = info.sites?.find((p) => p.name === info.name);
  const [sites, setSites] = useState<SiteForm[]>([{ ...blank(), name: me?.name ?? "", endpoints: me?.endpoint ?? "" }, blank()]);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<string | null>(null);
  const errs = sites.map(siteErr);
  const submit = async () => {
    setBusy(true);
    setResult(null);
    try {
      const r = await admin<AddResult>("/site-replication/add", {
        method: "PUT",
        encrypt: true,
        headers: { "content-type": "application/json" },
        body: JSON.stringify(sites.map((s) => ({ ...s, name: s.name.trim(), endpoints: s.endpoints.trim() }))),
      });
      if (r && r.success === false) {
        setResult([r.status, r.errorDetail].filter(Boolean).join(" "));
        return;
      }
      toast(r?.status || "Sites added");
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
      title="Add sites"
      onClose={onClose}
      footer={
        <>
          <Button onClick={() => setSites([...sites, blank()])}>Add another site</Button>
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" onClick={submit} disabled={busy || errs.some(Boolean)}>
            {busy ? "Adding…" : "Add sites"}
          </Button>
        </>
      }
    >
      <p class="hint">Credentials must belong to an admin user on each site. They are sent encrypted. The first entry is this site, with the S3 endpoint peers use to reach it.</p>
      {sites.map((s, i) => (
        <div key={i}>
          <SiteFields s={s} idx={i} set={(n) => setSites(sites.map((x, j) => (j === i ? n : x)))} />
          {errs[i] && (s.name || s.endpoints) && <p class="hint">{errs[i]}</p>}
          {i > 1 && (
            <Button small variant="ghost" onClick={() => setSites(sites.filter((_, j) => j !== i))}>
              Remove entry
            </Button>
          )}
        </div>
      ))}
      {result && (
        <div class="notice notice-error" role="alert">
          {result}
        </div>
      )}
    </Modal>
  );
}

export function SiteReplication() {
  const info = useAsync(() => admin<Info>("/site-replication/info"));
  const status = useAsync(() => admin<Status>("/site-replication/status"));
  const [adding, setAdding] = useState(false);
  const [removing, setRemoving] = useState<string[] | "all" | null>(null);
  const reload = () => {
    info.reload();
    status.reload();
  };
  const remove = async (sites: string[] | "all") => {
    const r = await admin<{ status?: string; errorDetail?: string[] }>("/site-replication/remove", {
      method: "PUT",
      encrypt: true,
      headers: { "content-type": "application/json" },
      body: JSON.stringify(sites === "all" ? { all: true } : { sites }),
    });
    toast(r?.status || "Removed", r?.errorDetail?.length ? "error" : "ok");
    reload();
  };
  return (
    <>
      <PageHeader
        title="Site Replication"
        actions={
          <>
            <Button onClick={reload}>Refresh</Button>
            {info.data?.enabled && (
              <Button variant="danger" onClick={() => setRemoving("all")}>
                Remove all
              </Button>
            )}
            <Button variant="primary" onClick={() => setAdding(true)} disabled={!info.data}>
              Add sites
            </Button>
          </>
        }
      >
        <p class="hint">Keeps buckets, objects, users, groups and policies in sync across independent deployments.</p>
      </PageHeader>
      <Loading state={info}>
        {() => {
          const i = info.data!;
          if (!i.enabled)
            return (
              <Card>
                <Empty>
                  Site replication is not configured. <Button variant="primary" small onClick={() => setAdding(true)}>Add sites</Button>
                </Empty>
              </Card>
            );
          const summary = status.data?.StatsSummary || {};
          return (
            <>
              <Card title="Overview">
                <KeyValue
                  rows={[
                    ["This site", i.name || "-"],
                    ["Sites", String(i.sites?.length ?? 0)],
                    ["Service account", i.serviceAccountAccessKey || "-"],
                    ["Buckets", String(status.data?.MaxBuckets ?? "-")],
                    ["Users / groups / policies", status.data ? `${status.data.MaxUsers ?? 0} / ${status.data.MaxGroups ?? 0} / ${status.data.MaxPolicies ?? 0}` : "-"],
                  ]}
                />
              </Card>
              <Card title="Sites">
                <table>
                  <thead>
                    <tr>
                      <th scope="col">Name</th>
                      <th scope="col">Endpoint</th>
                      <th scope="col">Deployment</th>
                      <th scope="col">Status</th>
                      <th scope="col" class="num">Buckets in sync</th>
                      <th scope="col" class="num">Users in sync</th>
                      <th scope="col">
                        <span class="sr-only">Actions</span>
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    {(i.sites || []).map((p) => {
                      const s = summary[p.deploymentID];
                      const self = p.name === i.name;
                      return (
                        <tr key={p.deploymentID}>
                          <td>
                            {p.name} {self && <Badge>this site</Badge>}
                          </td>
                          <td class="ops-mono">{p.endpoint}</td>
                          <td class="ops-mono">{p.deploymentID}</td>
                          <td>{status.loading && !status.data ? "…" : s ? <Badge kind="ok">reachable</Badge> : <Badge kind="error">unreachable</Badge>}</td>
                          <td class="ops-num">{s ? `${s.ReplicatedBuckets ?? 0} / ${s.TotalBucketsCount ?? 0}` : "-"}</td>
                          <td class="ops-num">{s ? `${s.ReplicatedUsers ?? 0} / ${s.TotalUsersCount ?? "-"}` : "-"}</td>
                          <td>
                            <Button small variant="danger" onClick={() => setRemoving([p.name])} aria-label={`Remove site ${p.name}`}>
                              Remove
                            </Button>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
                {status.error && <p class="hint">Status unavailable: {status.error.message}</p>}
              </Card>
            </>
          );
        }}
      </Loading>
      {adding && info.data && <AddSites info={info.data} onClose={() => setAdding(false)} onDone={reload} />}
      {removing && (
        <Confirm
          title={removing === "all" ? "Remove site replication" : `Remove site ${removing[0]}`}
          message={removing === "all" ? "Stop replication between all sites? Data already copied stays in place." : `Stop replicating with ${removing[0]}? Its data stays in place.`}
          confirmLabel="Remove"
          onConfirm={() => remove(removing)}
          onClose={() => setRemoving(null)}
        />
      )}
    </>
  );
}
