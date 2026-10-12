import { useState } from "preact/hooks";
import { Button, Card, Confirm, Empty, KeyValue, Loading, Modal, PageHeader, TextInput, toast, toastError, useAsync } from "../components/ui";
import { href, navigate } from "../lib/router";
import { iam } from "./iam/iamapi";
import { CheckList, SearchBox, StatusBadge } from "./iam/widgets";
import { EditPolicies, Tags } from "./Users";
import "./iam/iam.css";

export function Groups({ group }: { group?: string }) {
  return group ? <GroupDetail name={group} /> : <GroupList />;
}

function GroupList() {
  const groups = useAsync(async () => Promise.all((await iam.groups()).map((g) => iam.group(g).catch(() => ({ name: g, status: "?", members: [], policies: [] })))), []);
  const [q, setQ] = useState("");
  const [creating, setCreating] = useState(false);
  const rows = (groups.data || []).filter((g) => g.name.toLowerCase().includes(q.toLowerCase()));
  return (
    <>
      <PageHeader
        title="Groups"
        actions={
          <>
            <Button onClick={groups.reload}>Refresh</Button>
            <Button variant="primary" onClick={() => setCreating(true)}>
              Create Group
            </Button>
          </>
        }
      />
      <Card>
        <SearchBox value={q} onInput={setQ} label="Filter groups" />
        <Loading state={groups}>
          {() =>
            rows.length === 0 ? (
              <Empty>{q ? "No groups match." : "No groups yet."}</Empty>
            ) : (
              <table>
                <thead>
                  <tr>
                    <th>Name</th>
                    <th>Status</th>
                    <th class="num">Members</th>
                    <th>Policies</th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map((g) => (
                    <tr key={g.name}>
                      <td>
                        <a href={href(`/iam/groups/${encodeURIComponent(g.name)}`)}>{g.name}</a>
                      </td>
                      <td>
                        <StatusBadge on={g.status === "enabled"} />
                      </td>
                      <td class="num">{g.members.length}</td>
                      <td>
                        <Tags items={g.policies} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )
          }
        </Loading>
      </Card>
      {creating && <CreateGroup onClose={() => setCreating(false)} onDone={groups.reload} />}
    </>
  );
}

function CreateGroup({ onClose, onDone }: { onClose: () => void; onDone: () => void }) {
  const users = useAsync(iam.users, []);
  const [name, setName] = useState("");
  const [members, setMembers] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);
  return (
    <Modal
      title="Create group"
      onClose={onClose}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button
            variant="primary"
            disabled={busy || !name.trim()}
            onClick={async () => {
              setBusy(true);
              try {
                await iam.updateMembers(name.trim(), members);
                toast(`Group ${name} created`);
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
      <TextInput label="Group name" value={name} onInput={setName} autoFocus />
      <Loading state={users}>{() => <CheckList legend="Members" options={users.data!.map((u) => u.name)} selected={members} onChange={setMembers} empty="No users yet." />}</Loading>
    </Modal>
  );
}

function GroupDetail({ name }: { name: string }) {
  const g = useAsync(() => iam.group(name), [name]);
  const [editMembers, setEditMembers] = useState(false);
  const [editPol, setEditPol] = useState(false);
  const [del, setDel] = useState(false);
  return (
    <>
      <PageHeader
        title={name}
        actions={
          <>
            <a class="btn btn-ghost" href={href("/iam/groups")}>
              All groups
            </a>
            {g.data && (
              <Button
                onClick={async () => {
                  try {
                    await iam.setGroupStatus(name, g.data!.status !== "enabled");
                    g.reload();
                  } catch (e) {
                    toastError(e);
                  }
                }}
              >
                {g.data.status === "enabled" ? "Disable" : "Enable"}
              </Button>
            )}
            <Button variant="danger" onClick={() => setDel(true)}>
              Delete Group
            </Button>
          </>
        }
      />
      <Loading state={g}>
        {() => (
          <div class="grid-2">
            <Card title="Summary">
              <KeyValue rows={[["Status", <StatusBadge on={g.data!.status === "enabled"} />], ["Members", String(g.data!.members.length)], ["Policies", <Tags items={g.data!.policies} />]]} />
            </Card>
            <Card
              title="Members"
              actions={
                <Button small onClick={() => setEditMembers(true)}>
                  Edit
                </Button>
              }
            >
              {g.data!.members.length ? (
                <ul>
                  {g.data!.members.map((m) => (
                    <li key={m}>
                      <a href={href(`/iam/users/${encodeURIComponent(m)}`)}>{m}</a>
                    </li>
                  ))}
                </ul>
              ) : (
                <Empty>No members.</Empty>
              )}
            </Card>
            <Card
              title="Policies"
              actions={
                <Button small onClick={() => setEditPol(true)}>
                  Edit
                </Button>
              }
            >
              <Tags items={g.data!.policies} />
            </Card>
          </div>
        )}
      </Loading>
      {editMembers && g.data && <EditMembers group={name} current={g.data.members} onClose={() => setEditMembers(false)} onDone={g.reload} />}
      {editPol && g.data && <EditPolicies who={name} isGroup current={g.data.policies} onClose={() => setEditPol(false)} onDone={g.reload} />}
      {del && (
        <Confirm
          title="Delete group"
          message={`Delete group ${name}? Members are removed from it first.`}
          onClose={() => setDel(false)}
          onConfirm={async () => {
            if (g.data?.members.length) await iam.updateMembers(name, g.data.members, true);
            await iam.updateMembers(name, [], true);
            toast(`Group ${name} deleted`);
            navigate("/iam/groups");
          }}
        />
      )}
    </>
  );
}

function EditMembers({ group, current, onClose, onDone }: { group: string; current: string[]; onClose: () => void; onDone: () => void }) {
  const users = useAsync(iam.users, []);
  const [sel, setSel] = useState(current);
  const [busy, setBusy] = useState(false);
  return (
    <Modal
      title={`Members of ${group}`}
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
                const add = sel.filter((u) => !current.includes(u));
                const rm = current.filter((u) => !sel.includes(u));
                if (add.length) await iam.updateMembers(group, add);
                if (rm.length) await iam.updateMembers(group, rm, true);
                toast("Members updated");
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
      <Loading state={users}>{() => <CheckList legend="Members" options={users.data!.map((u) => u.name)} selected={sel} onChange={setSel} />}</Loading>
    </Modal>
  );
}
