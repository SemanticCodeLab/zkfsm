import { useEffect, useState } from "preact/hooks";
import { Button, Card, Confirm, Empty, JsonEditor, Loading, Modal, PageHeader, Select, TextInput, Toggle, toast, toastError, useAsync } from "../components/ui";
import { session } from "../lib/api";
import { date } from "../lib/format";
import { expiryOf, genAccessKey, genSecretKey, iam, ServiceAccount, validatePolicy } from "./iam/iamapi";
import { CredentialsModal, SearchBox, StatusBadge } from "./iam/widgets";
import "./iam/iam.css";

export function AccessKeys() {
  const me = useAsync(session.current, []);
  const users = useAsync(() => iam.users().catch(() => []), []);
  const [owner, setOwner] = useState("");
  const keys = useAsync(() => iam.serviceAccounts(owner || undefined), [owner]);
  const [q, setQ] = useState("");
  const [creating, setCreating] = useState(false);
  const [edit, setEdit] = useState<ServiceAccount | null>(null);
  const [del, setDel] = useState<ServiceAccount | null>(null);
  const rows = (keys.data || []).filter((k) => `${k.accessKey} ${k.name || ""} ${k.description || ""}`.toLowerCase().includes(q.toLowerCase()));
  const owners = (users.data || []).map((u) => u.name);
  return (
    <>
      <PageHeader
        title="Access Keys"
        actions={
          <>
            <Button onClick={keys.reload}>Refresh</Button>
            <Button variant="primary" onClick={() => setCreating(true)}>
              Create Access Key
            </Button>
          </>
        }
      >
        <p class="hint">Service accounts inherit their parent user's permissions unless restricted by a policy.</p>
      </PageHeader>
      <Card>
        <div class="row">
          {owners.length > 0 && (
            <Select label="Owner" value={owner} onChange={setOwner} options={[["", `Me (${me.data?.user ?? "current"})`], ...owners.map((o): [string, string] => [o, o])]} />
          )}
          <div class="field">
            <label>&nbsp;</label>
            <SearchBox value={q} onInput={setQ} label="Filter access keys" />
          </div>
        </div>
        <Loading state={keys}>
          {() =>
            rows.length === 0 ? (
              <Empty>No access keys.</Empty>
            ) : (
              <table data-testid="access-keys-table">
                <thead>
                  <tr>
                    <th>Access key</th>
                    <th>Name</th>
                    <th>Description</th>
                    <th>Status</th>
                    <th>Policy</th>
                    <th>Expires</th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {rows.map((k) => (
                    <tr key={k.accessKey}>
                      <td class="mono">{k.accessKey}</td>
                      <td>{k.name || "-"}</td>
                      <td>{k.description || "-"}</td>
                      <td>
                        <StatusBadge on={k.accountStatus === "on"} />
                      </td>
                      <td>{k.impliedPolicy ? "inherited" : "restricted"}</td>
                      <td>{expiryOf(k.expiration) ? date(k.expiration!) : "never"}</td>
                      <td class="iam-actions">
                        <Button small onClick={() => setEdit(k)}>
                          Edit
                        </Button>{" "}
                        <Button small variant="danger" onClick={() => setDel(k)}>
                          Delete
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
      {creating && <CreateAccessKey targetUser={owner || undefined} onClose={() => setCreating(false)} onDone={keys.reload} />}
      {edit && <EditAccessKey account={edit} onClose={() => setEdit(null)} onDone={keys.reload} />}
      {del && (
        <Confirm
          title="Delete access key"
          message={`Delete access key ${del.accessKey}? Applications using it stop working.`}
          onClose={() => setDel(null)}
          onConfirm={async () => {
            await iam.deleteServiceAccount(del.accessKey);
            toast("Access key deleted");
            keys.reload();
          }}
        />
      )}
    </>
  );
}

/** `datetime-local` value to ISO, or undefined when empty. */
function isoOf(local: string): string | undefined {
  if (!local) return undefined;
  const d = new Date(local);
  return isNaN(d.getTime()) ? undefined : d.toISOString();
}

export function CreateAccessKey({ targetUser, onClose, onDone }: { targetUser?: string; onClose: () => void; onDone: () => void }) {
  const [custom, setCustom] = useState(false);
  const [ak, setAk] = useState("");
  const [sk, setSk] = useState("");
  const [name, setName] = useState("");
  const [desc, setDesc] = useState("");
  const [exp, setExp] = useState("");
  const [restrict, setRestrict] = useState(false);
  const [pol, setPol] = useState('{\n  "Version": "2012-10-17",\n  "Statement": [\n    {\n      "Effect": "Allow",\n      "Action": ["s3:GetObject"],\n      "Resource": ["arn:aws:s3:::*"]\n    }\n  ]\n}');
  const [busy, setBusy] = useState(false);
  const [creds, setCreds] = useState<{ accessKey: string; secretKey: string; expiration?: string | null } | null>(null);
  useEffect(() => {
    if (custom && !ak) {
      setAk(genAccessKey());
      setSk(genSecretKey());
    }
  }, [custom]);
  if (creds)
    return (
      <CredentialsModal
        creds={creds}
        onClose={() => {
          onDone();
          onClose();
        }}
      />
    );
  const polErrs = restrict ? validatePolicy(pol) : [];
  return (
    <Modal
      title={targetUser ? `Create access key for ${targetUser}` : "Create access key"}
      wide
      onClose={onClose}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button
            variant="primary"
            disabled={busy || polErrs.length > 0}
            onClick={async () => {
              setBusy(true);
              try {
                const res = await iam.addServiceAccount({
                  targetUser,
                  accessKey: custom ? ak : undefined,
                  secretKey: custom ? sk : undefined,
                  name: name || undefined,
                  description: desc || undefined,
                  expiration: isoOf(exp),
                  policy: restrict ? JSON.parse(pol) : undefined,
                });
                setCreds(res.credentials);
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
      <div class="row">
        <TextInput label="Name" value={name} onInput={setName} />
        <TextInput label="Expiry" type="datetime-local" value={exp} onInput={setExp} hint="Empty: never expires" />
      </div>
      <TextInput label="Description" value={desc} onInput={setDesc} />
      <Toggle label="Custom access and secret key" checked={custom} onChange={setCustom} />
      {custom && (
        <div class="row">
          <TextInput label="Access key" value={ak} onInput={setAk} />
          <TextInput label="Secret key" value={sk} onInput={setSk} />
        </div>
      )}
      <Toggle label="Restrict with a policy" checked={restrict} onChange={setRestrict} />
      {restrict && (
        <>
          <JsonEditor label="Policy document" value={pol} onChange={setPol} rows={12} />
          {polErrs.length > 0 && (
            <ul class="iam-errors">
              {polErrs.map((e) => (
                <li key={e}>{e}</li>
              ))}
            </ul>
          )}
        </>
      )}
    </Modal>
  );
}

function EditAccessKey({ account, onClose, onDone }: { account: ServiceAccount; onClose: () => void; onDone: () => void }) {
  const info = useAsync(() => iam.serviceAccountInfo(account.accessKey), [account.accessKey]);
  const [on, setOn] = useState(account.accountStatus === "on");
  const [name, setName] = useState(account.name || "");
  const [desc, setDesc] = useState(account.description || "");
  const [exp, setExp] = useState("");
  const [restrict, setRestrict] = useState(!account.impliedPolicy);
  const [pol, setPol] = useState("");
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    if (info.data && !pol) {
      try {
        setPol(JSON.stringify(typeof info.data.policy === "string" ? JSON.parse(info.data.policy) : info.data.policy, null, 2));
      } catch {
        setPol(String(info.data.policy || ""));
      }
    }
  }, [info.data]);
  const polErrs = restrict && pol ? validatePolicy(pol) : [];
  return (
    <Modal
      title={`Edit ${account.accessKey}`}
      wide
      onClose={onClose}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button
            variant="primary"
            disabled={busy || polErrs.length > 0}
            onClick={async () => {
              setBusy(true);
              try {
                await iam.updateServiceAccount(account.accessKey, {
                  newStatus: on ? "on" : "off",
                  newName: name || undefined,
                  newDescription: desc || undefined,
                  newExpiration: isoOf(exp),
                  newPolicy: restrict && pol ? JSON.parse(pol) : undefined,
                });
                toast("Access key updated");
                onDone();
                onClose();
              } catch (e) {
                toastError(e);
              } finally {
                setBusy(false);
              }
            }}
          >
            Save
          </Button>
        </>
      }
    >
      <Toggle label="Enabled" checked={on} onChange={setOn} />
      <div class="row">
        <TextInput label="Name" value={name} onInput={setName} />
        <TextInput label="New expiry" type="datetime-local" value={exp} onInput={setExp} hint={expiryOf(account.expiration) ? `Now: ${date(account.expiration!)}` : "Now: never"} />
      </div>
      <TextInput label="Description" value={desc} onInput={setDesc} />
      <Toggle label="Restrict with a policy" checked={restrict} onChange={setRestrict} />
      {restrict && (
        <Loading state={info}>
          {() => (
            <>
              <JsonEditor label="Policy document" value={pol} onChange={setPol} rows={12} />
              {polErrs.length > 0 && (
                <ul class="iam-errors">
                  {polErrs.map((e) => (
                    <li key={e}>{e}</li>
                  ))}
                </ul>
              )}
            </>
          )}
        </Loading>
      )}
    </Modal>
  );
}
