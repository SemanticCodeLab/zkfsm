import { useState } from "preact/hooks";
import { Badge, Button, Card, Confirm, Empty, Loading, Modal, PageHeader, Select, TextInput, toast, toastError, useAsync } from "../components/ui";
import { admin, s3Xml } from "../lib/api";
import { bytes } from "../lib/format";
import { all, text } from "../lib/xml";
import { iam } from "./iam/iamapi";
import "./iam/iam.css";

interface Tenant {
  name: string;
  status: string;
  users: string[];
  buckets: { name: string; size: number; objects: number }[];
  size: number;
}

export function validTenantName(n: string): boolean {
  return /^[a-z0-9-]{1,63}$/.test(n);
}

export function Tenants() {
  const list = useAsync(() => admin<Tenant[] | null>("/tenant/list").then((x) => x || []), []);
  const [creating, setCreating] = useState(false);
  const [assign, setAssign] = useState<{ tenant: string; kind: "user" | "bucket" } | null>(null);
  const [del, setDel] = useState<string | null>(null);
  return (
    <>
      <PageHeader
        title="Tenants"
        actions={
          <>
            <Button onClick={list.reload}>Refresh</Button>
            <Button variant="primary" onClick={() => setCreating(true)}>
              Create Tenant
            </Button>
          </>
        }
      >
        <p class="hint">Tenants isolate users and buckets: a tenant's users see only its buckets.</p>
      </PageHeader>
      <Card>
        <Loading state={list}>
          {() =>
            list.data!.length === 0 ? (
              <Empty>No tenants.</Empty>
            ) : (
              <table>
                <thead>
                  <tr>
                    <th>Name</th>
                    <th>Status</th>
                    <th>Users</th>
                    <th>Buckets</th>
                    <th class="num">Usage</th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {list.data!.map((t) => (
                    <tr key={t.name}>
                      <td>{t.name}</td>
                      <td>
                        <Badge kind={t.status === "enabled" ? "ok" : "warn"}>{t.status}</Badge>
                      </td>
                      <td>{t.users.join(", ") || "-"}</td>
                      <td>{t.buckets.map((b) => b.name).join(", ") || "-"}</td>
                      <td class="num">{bytes(t.size)}</td>
                      <td class="iam-actions">
                        <Button small onClick={() => setAssign({ tenant: t.name, kind: "user" })}>
                          Assign User
                        </Button>{" "}
                        <Button small onClick={() => setAssign({ tenant: t.name, kind: "bucket" })}>
                          Assign Bucket
                        </Button>{" "}
                        <Button
                          small
                          onClick={async () => {
                            try {
                              await admin("/tenant/set-status", { method: "PUT", query: { name: t.name, status: t.status === "enabled" ? "disabled" : "enabled" } });
                              list.reload();
                            } catch (e) {
                              toastError(e);
                            }
                          }}
                        >
                          {t.status === "enabled" ? "Disable" : "Enable"}
                        </Button>{" "}
                        <Button small variant="danger" onClick={() => setDel(t.name)}>
                          Remove
                        </Button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )
          }
        </Loading>
      </Card>
      {creating && <CreateTenant onClose={() => setCreating(false)} onDone={list.reload} />}
      {assign && <Assign {...assign} onClose={() => setAssign(null)} onDone={list.reload} />}
      {del && (
        <Confirm
          title="Remove tenant"
          message={`Remove tenant ${del}? It must have no users or buckets.`}
          confirmLabel="Remove"
          onClose={() => setDel(null)}
          onConfirm={async () => {
            await admin("/tenant/remove", { method: "DELETE", query: { name: del } });
            toast("Tenant removed");
            list.reload();
          }}
        />
      )}
    </>
  );
}

function CreateTenant({ onClose, onDone }: { onClose: () => void; onDone: () => void }) {
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);
  return (
    <Modal
      title="Create tenant"
      onClose={onClose}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button
            variant="primary"
            disabled={busy || !validTenantName(name)}
            onClick={async () => {
              setBusy(true);
              try {
                await admin("/tenant/add", { method: "PUT", query: { name } });
                toast(`Tenant ${name} created`);
                onDone();
                onClose();
              } catch (e) {
                toastError(e);
              } finally {
                setBusy(false);
              }
            }}
          >
            Create
          </Button>
        </>
      }
    >
      <TextInput label="Tenant name" value={name} onInput={setName} autoFocus error={name && !validTenantName(name) ? "1-63 lowercase letters, digits or '-'." : null} />
    </Modal>
  );
}

function Assign({ tenant, kind, onClose, onDone }: { tenant: string; kind: "user" | "bucket"; onClose: () => void; onDone: () => void }) {
  const opts = useAsync(async () => {
    if (kind === "user") return (await iam.users()).map((u) => u.name);
    return all(await s3Xml("/"), "Bucket").map((b) => text(b, "Name"));
  }, [kind]);
  const [sel, setSel] = useState("");
  const [busy, setBusy] = useState(false);
  return (
    <Modal
      title={`Assign ${kind} to ${tenant}`}
      onClose={onClose}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button
            variant="primary"
            disabled={busy || !sel}
            onClick={async () => {
              setBusy(true);
              try {
                if (kind === "user") await admin("/tenant/assign-user", { method: "PUT", query: { accessKey: sel, name: tenant } });
                else await admin("/tenant/assign-bucket", { method: "PUT", query: { bucket: sel, name: tenant } });
                toast(`Assigned ${sel} to ${tenant}`);
                onDone();
                onClose();
              } catch (e) {
                toastError(e);
              } finally {
                setBusy(false);
              }
            }}
          >
            Assign
          </Button>
        </>
      }
    >
      <Loading state={opts}>{() => <Select label={kind === "user" ? "User" : "Bucket"} value={sel} onChange={setSel} options={[["", "Choose…"], ...opts.data!.map((o): [string, string] => [o, o])]} />}</Loading>
    </Modal>
  );
}
