import { useMemo, useState } from "preact/hooks";
import { Badge, Button, Card, Empty, Modal, PageHeader, TextInput, Toggle, toast, toastError, useAsync } from "../components/ui";
import { bytes, date, validBucketName } from "../lib/format";
import { href, navigate } from "../lib/router";
import { joinBytes, QuotaInput, Section } from "./buckets/common";
import { BucketRow, createBucket, forceDeleteBucket, listBuckets } from "./buckets/ops";
import { s3 } from "../lib/api";
import "./buckets/buckets.css";

export function Buckets() {
  const state = useAsync(listBuckets, []);
  const [q, setQ] = useState("");
  const [creating, setCreating] = useState(false);
  const [deleting, setDeleting] = useState<string | null>(null);
  const rows = useMemo(() => (state.data || []).filter((b) => b.name.includes(q.trim().toLowerCase())), [state.data, q]);
  const hasUsage = (state.data || []).some((b) => (b.size ?? 0) > 0 || (b.objects ?? 0) > 0);

  return (
    <>
      <PageHeader
        title="Buckets"
        actions={
          <>
            <Button onClick={state.reload}>Refresh</Button>
            <Button variant="primary" onClick={() => setCreating(true)}>
              Create Bucket
            </Button>
          </>
        }
      >
        <p class="hint">{state.data ? `${state.data.length} bucket${state.data.length === 1 ? "" : "s"}` : ""}</p>
      </PageHeader>
      <Card>
        <div class="bk-toolbar">
          <input type="search" class="bk-search" placeholder="Filter buckets" aria-label="Filter buckets" value={q} onInput={(e) => setQ((e.target as HTMLInputElement).value)} />
        </div>
        <Section state={state}>
          {() =>
            rows.length === 0 ? (
              <Empty>{q ? "No buckets match the filter." : "No buckets yet. Create one to get started."}</Empty>
            ) : (
              <table data-testid="bucket-table">
                <thead>
                  <tr>
                    <th>Name</th>
                    <th>Created</th>
                    {hasUsage && <th class="num">Objects</th>}
                    {hasUsage && <th class="num">Size</th>}
                    <th>Access</th>
                    <th class="bk-actions-col">
                      <span class="sr-only">Actions</span>
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map((b) => (
                    <BucketTr key={b.name} b={b} hasUsage={hasUsage} onDelete={() => setDeleting(b.name)} />
                  ))}
                </tbody>
              </table>
            )
          }
        </Section>
      </Card>
      {creating && <CreateBucket onClose={() => setCreating(false)} onDone={state.reload} />}
      {deleting && <DeleteBucket bucket={deleting} onClose={() => setDeleting(null)} onDone={state.reload} />}
    </>
  );
}

function BucketTr({ b, hasUsage, onDelete }: { b: BucketRow; hasUsage: boolean; onDelete: () => void }) {
  const access = b.read === undefined ? "-" : b.read && b.write ? "R/W" : b.read ? "R" : b.write ? "W" : "none";
  return (
    <tr class="bk-click" onClick={(e) => !(e.target as HTMLElement).closest("a,button") && navigate(`/buckets/${encodeURIComponent(b.name)}`)}>
      <td>
        <a href={href(`/buckets/${encodeURIComponent(b.name)}`)} class="bk-name">
          {b.name}
        </a>
      </td>
      <td>{date(b.created)}</td>
      {hasUsage && <td class="num">{b.objects ?? "-"}</td>}
      {hasUsage && <td class="num">{bytes(b.size)}</td>}
      <td>{access === "-" ? "-" : <Badge kind={access === "none" ? "warn" : "default"}>{access}</Badge>}</td>
      <td class="bk-actions-col">
        <a class="btn btn-sm" href={href(`/browser/${encodeURIComponent(b.name)}`)} aria-label={`Browse ${b.name}`}>
          Browse
        </a>
        <Button small variant="ghost" aria-label={`Delete bucket ${b.name}`} onClick={onDelete}>
          Delete
        </Button>
      </td>
    </tr>
  );
}

function CreateBucket({ onClose, onDone }: { onClose: () => void; onDone: () => void }) {
  const [name, setName] = useState("");
  const [versioning, setVersioning] = useState(false);
  const [lock, setLock] = useState(false);
  const [qv, setQv] = useState("");
  const [qu, setQu] = useState("GiB");
  const [busy, setBusy] = useState(false);
  const [touched, setTouched] = useState(false);
  const err = validBucketName(name);
  const submit = async (e?: Event) => {
    e?.preventDefault();
    setTouched(true);
    if (err) return;
    setBusy(true);
    try {
      await createBucket(name, { versioning, lock, quota: joinBytes(qv, qu) });
      toast(`Bucket ${name} created`);
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
      title="Create Bucket"
      onClose={onClose}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" disabled={busy} onClick={() => submit()}>
            Create
          </Button>
        </>
      }
    >
      <form onSubmit={submit}>
        <TextInput label="Bucket name" value={name} autofocus onInput={(v) => setName(v.trim())} error={name || touched ? err : null} hint="3-63 lowercase letters, digits, dots and hyphens." />
        <div class="bk-stack">
          <Toggle label="Versioning" checked={versioning || lock} disabled={lock} onChange={setVersioning} />
          <Toggle label="Object lock" checked={lock} onChange={setLock} />
          {lock && <div class="hint">Object lock requires versioning and cannot be disabled after creation.</div>}
        </div>
        <QuotaInput value={qv} unit={qu} onValue={setQv} onUnit={setQu} />
        <button type="submit" hidden />
      </form>
    </Modal>
  );
}

function DeleteBucket({ bucket, onClose, onDone }: { bucket: string; onClose: () => void; onDone: () => void }) {
  const [force, setForce] = useState(false);
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [progress, setProgress] = useState(0);
  const go = async () => {
    setBusy(true);
    try {
      if (force) await forceDeleteBucket(bucket, setProgress);
      else await s3(`/${encodeURIComponent(bucket)}`, { method: "DELETE" });
      toast(`Bucket ${bucket} deleted`);
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
      title={`Delete bucket ${bucket}`}
      onClose={onClose}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="danger" disabled={busy || (force && confirm !== bucket)} onClick={go}>
            Delete
          </Button>
        </>
      }
    >
      <p>
        Delete bucket <strong class="mono">{bucket}</strong>? A bucket must be empty unless you choose to delete its contents.
      </p>
      <Toggle label="Delete all objects and versions first" checked={force} onChange={setForce} />
      {force && (
        <>
          <div class="notice notice-warn">This permanently removes every object version in the bucket. Objects under retention may block it.</div>
          <TextInput label="Type the bucket name to confirm" value={confirm} onInput={setConfirm} />
        </>
      )}
      {busy && force && <div class="hint">Deleted {progress} versions…</div>}
    </Modal>
  );
}
