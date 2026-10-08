import { useState } from "preact/hooks";
import { json, KMS } from "../lib/api";
import { date } from "../lib/format";
import { Badge, Button, Card, Empty, KeyValue, Loading, Modal, PageHeader, TextInput, toast, toastError, useAsync } from "../components/ui";
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

export function Kms() {
  const status = useAsync(() => kms<KmsStatus>("/status"));
  const keys = useAsync(() => kms<KeyItem[]>("/key/list", { query: { pattern: "*" } }));
  const [filter, setFilter] = useState("");
  const [creating, setCreating] = useState(false);
  const [checking, setChecking] = useState<string | null>(null);
  const [rotating, setRotating] = useState<string | null>(null);
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
          <Button variant="primary" onClick={() => setCreating(true)}>
            Create key
          </Button>
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
                      <td>{date(k.createdAt)}</td>
                      <td>
                        <div class="actions">
                          <Button small onClick={() => setChecking(k.name)}>
                            Status
                          </Button>
                          <Button small onClick={() => rotate(k.name)} disabled={rotating === k.name}>
                            Rotate
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
      {creating && <CreateKey onClose={() => setCreating(false)} onDone={keys.reload} />}
      {checking && <StatusModal id={checking} onClose={() => setChecking(null)} />}
    </>
  );
}
