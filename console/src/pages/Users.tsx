import { useState } from "preact/hooks";
import { Badge, Button, Card, Confirm, Empty, KeyValue, Loading, Modal, PageHeader, TextInput, toast, toastError, useAsync } from "../components/ui";
import { date } from "../lib/format";
import { href, navigate } from "../lib/router";
import { expiryOf, genSecretKey, iam, ServiceAccount, UserRow, validAccessKey, validSecretKey } from "./iam/iamapi";
import { CheckList, CredentialsModal, SearchBox, StatusBadge } from "./iam/widgets";
import { CreateAccessKey } from "./AccessKeys";
import "./iam/iam.css";

export function Users({ user }: { user?: string }) {
  return user ? <UserDetail name={user} /> : <UserList />;
}

function UserList() {
  const users = useAsync(iam.users, []);
  const [q, setQ] = useState("");
  const [creating, setCreating] = useState(false);
  const [del, setDel] = useState<string | null>(null);
  const rows = (users.data || []).filter((u) => u.name.toLowerCase().includes(q.toLowerCase()));
  return (
    <>
      <PageHeader
        title="Users"
        actions={
          <>
            <Button onClick={users.reload}>Refresh</Button>
            <Button variant="primary" onClick={() => setCreating(true)}>
              Create User
            </Button>
          </>
        }
      />
      <Card>
        <SearchBox value={q} onInput={setQ} label="Filter users" />
        <Loading state={users}>
          {() =>
            rows.length === 0 ? (
              <Empty>{q ? "No users match." : "No users yet."}</Empty>
            ) : (
              <table data-testid="users-table">
                <thead>
                  <tr>
                    <th>Access key</th>
                    <th>Status</th>
                    <th>Policies</th>
                    <th>Groups</th>
                    <th>
                      <span class="sr-only">Actions</span>
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map((u) => (
                    <tr key={u.name}>
                      <td>
                        <a href={href(`/iam/users/${encodeURIComponent(u.name)}`)}>{u.name}</a>
                      </td>
                      <td>
                        <StatusBadge on={u.status === "enabled"} />
                      </td>
                      <td>
                        <Tags items={u.policies} />
                      </td>
                      <td>
                        <Tags items={u.groups} />
                      </td>
                      <td class="iam-actions">
                        <Button small variant="danger" aria-label={`Delete user ${u.name}`} onClick={() => setDel(u.name)}>
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
      {creating && <CreateUser onClose={() => setCreating(false)} onDone={users.reload} />}
      {del && (
        <Confirm
          title="Delete user"
          message={
            <>
              Delete user <b>{del}</b> and its service accounts?
            </>
          }
          onClose={() => setDel(null)}
          onConfirm={async () => {
            await iam.removeUser(del);
            toast(`User ${del} deleted`);
            users.reload();
          }}
        />
      )}
    </>
  );
}

export function Tags({ items }: { items: string[] }) {
  if (!items.length) return <span class="hint">-</span>;
  return (
    <span class="iam-tags">
      {items.map((p) => (
        <Badge key={p}>{p}</Badge>
      ))}
    </span>
  );
}

function CreateUser({ onClose, onDone }: { onClose: () => void; onDone: () => void }) {
  const policies = useAsync(iam.policies, []);
  const groups = useAsync(iam.groups, []);
  const [ak, setAk] = useState("");
  const [sk, setSk] = useState("");
  const [pols, setPols] = useState<string[]>([]);
  const [grps, setGrps] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);
  const [touched, setTouched] = useState(false);
  const akErr = touched ? validAccessKey(ak) : null;
  const skErr = touched ? validSecretKey(sk) : null;
  const save = async () => {
    setTouched(true);
    if (validAccessKey(ak) || validSecretKey(sk)) return;
    setBusy(true);
    try {
      await iam.addUser(ak, sk);
      if (pols.length) await iam.setPolicies(ak, false, pols);
      for (const g of grps) await iam.updateMembers(g, [ak]);
      toast(`User ${ak} created`);
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
      title="Create user"
      onClose={onClose}
      wide
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" disabled={busy} onClick={save}>
            Save
          </Button>
        </>
      }
    >
      <form
        onSubmit={(e) => {
          e.preventDefault();
          save();
        }}
      >
        <div class="row">
          <TextInput label="Access key" value={ak} onInput={setAk} error={akErr} autoFocus autoComplete="off" />
          <TextInput label="Secret key" value={sk} onInput={setSk} error={skErr} type="password" autoComplete="new-password" />
          <Button onClick={() => setSk(genSecretKey())}>Generate</Button>
        </div>
        <CheckList legend="Policies" options={Object.keys(policies.data || {}).sort()} selected={pols} onChange={setPols} />
        <CheckList legend="Groups" options={groups.data || []} selected={grps} onChange={setGrps} empty="No groups yet." />
        <button type="submit" hidden />
      </form>
    </Modal>
  );
}

function UserDetail({ name }: { name: string }) {
  const info = useAsync(() => iam.userInfo(name), [name]);
  const sas = useAsync(() => iam.serviceAccounts(name), [name]);
  const [editPol, setEditPol] = useState(false);
  const [editGroups, setEditGroups] = useState(false);
  const [del, setDel] = useState(false);
  const [newKey, setNewKey] = useState(false);
  const [delKey, setDelKey] = useState<ServiceAccount | null>(null);
  const u: UserRow | undefined = info.data && { name, status: info.data.status, policies: (info.data.policyName || "").split(",").filter(Boolean), groups: info.data.memberOf || [] };
  return (
    <>
      <PageHeader
        title={name}
        actions={
          <>
            <a class="btn btn-ghost" href={href("/iam/users")}>
              All users
            </a>
            {u && (
              <Button
                onClick={async () => {
                  try {
                    await iam.setUserStatus(name, u.status !== "enabled");
                    info.reload();
                  } catch (e) {
                    toastError(e);
                  }
                }}
              >
                {u.status === "enabled" ? "Disable" : "Enable"}
              </Button>
            )}
            <Button variant="danger" onClick={() => setDel(true)}>
              Delete User
            </Button>
          </>
        }
      />
      <Loading state={info}>
        {() => (
          <div class="grid-2">
            <Card title="Summary">
              <KeyValue rows={[["Status", <StatusBadge on={u!.status === "enabled"} />], ["Policies", <Tags items={u!.policies} />], ["Groups", <Tags items={u!.groups} />]]} />
            </Card>
            <Card
              title="Policies"
              actions={
                <Button small onClick={() => setEditPol(true)}>
                  Edit
                </Button>
              }
            >
              <Tags items={u!.policies} />
            </Card>
            <Card
              title="Groups"
              actions={
                <Button small onClick={() => setEditGroups(true)}>
                  Edit
                </Button>
              }
            >
              <Tags items={u!.groups} />
            </Card>
          </div>
        )}
      </Loading>
      <Card
        title="Service accounts"
        actions={
          <Button small variant="primary" onClick={() => setNewKey(true)}>
            Create Access Key
          </Button>
        }
      >
        <Loading state={sas}>
          {() =>
            sas.data!.length === 0 ? (
              <Empty>No service accounts.</Empty>
            ) : (
              <table>
                <thead>
                  <tr>
                    <th>Access key</th>
                    <th>Name</th>
                    <th>Status</th>
                    <th>Expires</th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {sas.data!.map((s) => (
                    <tr key={s.accessKey}>
                      <td class="mono">{s.accessKey}</td>
                      <td>{s.name || "-"}</td>
                      <td>
                        <StatusBadge on={s.accountStatus === "on"} />
                      </td>
                      <td>{expiryOf(s.expiration) ? date(s.expiration!) : "never"}</td>
                      <td class="iam-actions">
                        <Button small variant="danger" onClick={() => setDelKey(s)}>
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
      {editPol && u && <EditPolicies who={name} isGroup={false} current={u.policies} onClose={() => setEditPol(false)} onDone={info.reload} />}
      {editGroups && u && <EditGroups user={name} current={u.groups} onClose={() => setEditGroups(false)} onDone={info.reload} />}
      {newKey && <CreateAccessKey targetUser={name} onClose={() => setNewKey(false)} onDone={sas.reload} />}
      {delKey && (
        <Confirm
          title="Delete access key"
          message={`Delete access key ${delKey.accessKey}?`}
          onClose={() => setDelKey(null)}
          onConfirm={async () => {
            await iam.deleteServiceAccount(delKey.accessKey);
            sas.reload();
          }}
        />
      )}
      {del && (
        <Confirm
          title="Delete user"
          message={`Delete user ${name}?`}
          onClose={() => setDel(false)}
          onConfirm={async () => {
            await iam.removeUser(name);
            toast(`User ${name} deleted`);
            navigate("/iam/users");
          }}
        />
      )}
    </>
  );
}

export function EditPolicies({ who, isGroup, current, onClose, onDone }: { who: string; isGroup: boolean; current: string[]; onClose: () => void; onDone: () => void }) {
  const policies = useAsync(iam.policies, []);
  const [sel, setSel] = useState(current);
  const [busy, setBusy] = useState(false);
  return (
    <Modal
      title={`Policies of ${who}`}
      onClose={onClose}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button
            variant="primary"
            disabled={busy}
            onClick={async () => {
              setBusy(true);
              try {
                await iam.setPolicies(who, isGroup, sel);
                toast("Policies updated");
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
      <Loading state={policies}>{() => <CheckList legend="Policies" options={Object.keys(policies.data!).sort()} selected={sel} onChange={setSel} />}</Loading>
    </Modal>
  );
}

function EditGroups({ user, current, onClose, onDone }: { user: string; current: string[]; onClose: () => void; onDone: () => void }) {
  const groups = useAsync(iam.groups, []);
  const [sel, setSel] = useState(current);
  const [busy, setBusy] = useState(false);
  return (
    <Modal
      title={`Groups of ${user}`}
      onClose={onClose}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button
            variant="primary"
            disabled={busy}
            onClick={async () => {
              setBusy(true);
              try {
                for (const g of sel) if (!current.includes(g)) await iam.updateMembers(g, [user]);
                for (const g of current) if (!sel.includes(g)) await iam.updateMembers(g, [user], true);
                toast("Groups updated");
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
      <Loading state={groups}>{() => <CheckList legend="Groups" options={groups.data!} selected={sel} onChange={setSel} empty="No groups yet." />}</Loading>
    </Modal>
  );
}

export { CredentialsModal };
