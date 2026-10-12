import { useEffect, useState } from "preact/hooks";
import { href, navigate } from "../lib/router";
import { date, validBucketName } from "../lib/format";
import { Badge, Button, Card, Confirm, Empty, JsonEditor, KeyValue, Loading, Modal, PageHeader, Select, TextInput, Toggle, toast, toastError, useAsync } from "../components/ui";
import { isUnavailable, Unavailable } from "./ops/common";
import { api, currentFields, fieldsError, partitionText, primitiveTypes, SchemaField, snapshotRows, typeText, validName } from "./ops/tables";
import "./ops/ops.css";

export function Tables({ bucket }: { bucket?: string }) {
  return bucket ? <BucketView bucket={bucket} /> : <BucketList />;
}

/** Modal with one name field. */
function NameModal({ title, label, hint, check, onSubmit, onClose }: { title: string; label: string; hint?: string; check: (v: string) => string | null; onSubmit: (v: string) => Promise<void>; onClose: () => void }) {
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);
  const err = name ? check(name) : null;
  const submit = async (e: Event) => {
    e.preventDefault();
    if (!name || err) return;
    setBusy(true);
    try {
      await onSubmit(name);
      onClose();
    } catch (x) {
      toastError(x);
    } finally {
      setBusy(false);
    }
  };
  return (
    <Modal
      title={title}
      onClose={onClose}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" onClick={submit} disabled={busy || !name || !!err}>
            Create
          </Button>
        </>
      }
    >
      <form onSubmit={submit}>
        <TextInput label={label} value={name} onInput={setName} error={err} hint={hint} autofocus />
      </form>
    </Modal>
  );
}

function BucketList() {
  const list = useAsync(api.buckets);
  const [creating, setCreating] = useState(false);
  const [removing, setRemoving] = useState<string | null>(null);
  if (list.error && isUnavailable(list.error))
    return (
      <>
        <PageHeader title="Tables" />
        <Unavailable title="S3 Tables is not available on this server." />
      </>
    );
  return (
    <>
      <PageHeader
        title="Tables"
        actions={
          <Button variant="primary" onClick={() => setCreating(true)}>
            Create table bucket
          </Button>
        }
      />
      <Card title="Table buckets" actions={<Button small onClick={list.reload}>Refresh</Button>}>
        <p class="hint">
          A table bucket holds Iceberg tables grouped in namespaces. Query engines reach it through the Iceberg REST catalog at <span class="mono">/iceberg/v1</span> with the bucket name as the warehouse.
        </p>
        <Loading state={list}>
          {() =>
            list.data!.length ? (
              <table>
                <thead>
                  <tr>
                    <th scope="col">Name</th>
                    <th scope="col">ARN</th>
                    <th scope="col">Created</th>
                    <th scope="col">
                      <span class="sr-only">Actions</span>
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {list.data!.map((b) => (
                    <tr key={b.name}>
                      <td>
                        <a href={href(`/tables/${encodeURIComponent(b.name)}`)}>{b.name}</a>
                      </td>
                      <td class="ops-mono">{b.arn}</td>
                      <td>{date(b.createdAt)}</td>
                      <td>
                        <div class="actions">
                          <Button small variant="danger" onClick={() => setRemoving(b.name)} aria-label={`Delete ${b.name}`}>
                            Delete
                          </Button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : (
              <Empty>No table buckets yet.</Empty>
            )
          }
        </Loading>
      </Card>
      {creating && (
        <NameModal
          title="Create table bucket"
          label="Table bucket name"
          check={validBucketName}
          onSubmit={async (n) => {
            await api.createBucket(n);
            toast(`Table bucket ${n} created`);
            list.reload();
          }}
          onClose={() => setCreating(false)}
        />
      )}
      {removing && (
        <Confirm
          title="Delete table bucket"
          message={
            <>
              Delete <strong>{removing}</strong>? It must have no namespaces or tables.
            </>
          }
          onConfirm={async () => {
            await api.deleteBucket(removing);
            toast("Table bucket deleted");
            list.reload();
          }}
          onClose={() => setRemoving(null)}
        />
      )}
    </>
  );
}

function CreateTable({ bucket, namespaces, onClose, onDone }: { bucket: string; namespaces: string[]; onClose: () => void; onDone: () => void }) {
  const [ns, setNs] = useState(namespaces[0]);
  const [name, setName] = useState("");
  const [fields, setFields] = useState<SchemaField[]>([{ name: "id", type: "long", required: true }]);
  const [busy, setBusy] = useState(false);
  const nameErr = validName(name);
  const fErr = fieldsError(fields);
  const set = (i: number, f: Partial<SchemaField>) => setFields(fields.map((x, k) => (k === i ? { ...x, ...f } : x)));
  const submit = async () => {
    setBusy(true);
    try {
      await api.createTable(bucket, ns, name, fields);
      toast(`Table ${ns}.${name} created`);
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
      title="Create table"
      onClose={onClose}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" onClick={submit} disabled={busy || !name || !!nameErr || !!fErr}>
            Create
          </Button>
        </>
      }
    >
      <div class="row">
        <Select label="Namespace" value={ns} onChange={setNs} options={namespaces} />
        <TextInput label="Table name" value={name} onInput={setName} error={nameErr} autofocus />
      </div>
      <h3 class="bk-h3">Columns</h3>
      {fields.map((f, i) => (
        <div class="row" key={i}>
          <TextInput label={`Column ${i + 1}`} value={f.name} onInput={(v) => set(i, { name: v })} />
          <Select label={`Type ${i + 1}`} value={String(f.type)} onChange={(v) => set(i, { type: v })} options={primitiveTypes} />
          <Toggle label="Required" checked={!!f.required} onChange={(v) => set(i, { required: v })} />
          <Button small variant="ghost" aria-label={`Remove column ${i + 1}`} onClick={() => setFields(fields.filter((_, k) => k !== i))}>
            Remove
          </Button>
        </div>
      ))}
      <Button small onClick={() => setFields([...fields, { name: "", type: "string" }])}>
        Add column
      </Button>
      {fErr && <p class="hint">{fErr}</p>}
      <p class="hint">Creates an empty Iceberg v2 table. Engines add data and evolve the schema through the catalog.</p>
    </Modal>
  );
}

function TableModal({ bucket, ns, name, onClose }: { bucket: string; ns: string; name: string; onClose: () => void }) {
  const info = useAsync(() => api.table(bucket, ns, name), [bucket, ns, name]);
  const meta = useAsync(() => api.metadata(bucket, ns, name), [bucket, ns, name]);
  const snaps = snapshotRows(meta.data);
  return (
    <Modal wide title={`Table ${ns}.${name}`} onClose={onClose} footer={<Button onClick={onClose}>Close</Button>}>
      <Loading state={info}>
        {() => {
          const t = info.data!;
          return (
            <KeyValue
              rows={[
                ["ARN", <span class="ops-mono">{t.tableARN}</span>],
                ["Format", `${t.format || "ICEBERG"} v${meta.data?.["format-version"] ?? "-"}`],
                ["Location", <span class="ops-mono">{t.warehouseLocation || "-"}</span>],
                ["Metadata", <span class="ops-mono">{t.metadataLocation || "-"}</span>],
                ["Partitioning", partitionText(meta.data)],
                ["Created", `${date(t.createdAt)}${t.createdBy ? ` by ${t.createdBy}` : ""}`],
                ["Modified", `${date(t.modifiedAt)}${t.modifiedBy ? ` by ${t.modifiedBy}` : ""}`],
              ]}
            />
          );
        }}
      </Loading>
      <h3 class="bk-h3">Schema</h3>
      <Loading state={meta}>
        {() => (
          <table>
            <thead>
              <tr>
                <th scope="col" class="num">ID</th>
                <th scope="col">Column</th>
                <th scope="col">Type</th>
                <th scope="col">Required</th>
              </tr>
            </thead>
            <tbody>
              {currentFields(meta.data).map((f) => (
                <tr key={f.id ?? f.name}>
                  <td class="ops-num">{f.id ?? "-"}</td>
                  <td>{f.name}</td>
                  <td class="ops-mono">{typeText(f.type)}</td>
                  <td>{f.required ? "yes" : "no"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Loading>
      <h3 class="bk-h3">Snapshots</h3>
      {snaps.length ? (
        <table>
          <thead>
            <tr>
              <th scope="col">Snapshot</th>
              <th scope="col">Time</th>
              <th scope="col">Operation</th>
              <th scope="col" class="num">Records</th>
            </tr>
          </thead>
          <tbody>
            {snaps.map((s) => (
              <tr key={s.id}>
                <td class="ops-mono">
                  {s.id} {s.current && <Badge kind="ok">current</Badge>}
                </td>
                <td>{date(s.time)}</td>
                <td>{s.operation}</td>
                <td class="ops-num">{s.records}</td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : (
        <Empty>No snapshots: the table has no data yet.</Empty>
      )}
    </Modal>
  );
}

function PolicyCard({ bucket }: { bucket: string }) {
  const cur = useAsync(() => api.policy(bucket), [bucket]);
  const [text, setText] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  useEffect(() => setText(null), [bucket]);
  const value = text ?? pretty(cur.data ?? "");
  let valid = true;
  try {
    if (value.trim()) JSON.parse(value);
  } catch {
    valid = false;
  }
  const save = async () => {
    setBusy(true);
    try {
      if (value.trim()) await api.putPolicy(bucket, value);
      else await api.deletePolicy(bucket);
      toast(value.trim() ? "Policy saved" : "Policy removed");
      setText(null);
      cur.reload();
    } catch (e) {
      toastError(e);
    } finally {
      setBusy(false);
    }
  };
  return (
    <Card
      title="Table bucket policy"
      actions={
        <Button small variant="primary" onClick={save} disabled={busy || !valid || text === null}>
          Save policy
        </Button>
      }
    >
      <p class="hint">A resource policy for the s3tables actions on this bucket. Leave empty for none.</p>
      <Loading state={cur}>{() => <JsonEditor label="Policy document" value={value} onChange={setText} rows={8} />}</Loading>
    </Card>
  );
}

function pretty(doc: string): string {
  try {
    return doc ? JSON.stringify(JSON.parse(doc), null, 2) : "";
  } catch {
    return doc;
  }
}

function BucketView({ bucket }: { bucket: string }) {
  const nss = useAsync(() => api.namespaces(bucket), [bucket]);
  const tbls = useAsync(() => api.tables(bucket), [bucket]);
  const [addNs, setAddNs] = useState(false);
  const [addTable, setAddTable] = useState(false);
  const [view, setView] = useState<{ ns: string; name: string } | null>(null);
  const [dropNs, setDropNs] = useState<string | null>(null);
  const [dropTable, setDropTable] = useState<{ ns: string; name: string } | null>(null);
  const names = (nss.data ?? []).map((n) => n.namespace.join("."));
  const count = (ns: string) => (tbls.data ?? []).filter((t) => t.namespace.join(".") === ns).length;
  return (
    <>
      <nav class="breadcrumbs" aria-label="Breadcrumb">
        <a href={href("/tables")}>Tables</a>
        <span aria-hidden="true">/</span>
        <span>{bucket}</span>
      </nav>
      <PageHeader
        title={<span class="mono">{bucket}</span>}
        actions={
          <>
            <Button onClick={() => navigate(`/browser/${encodeURIComponent(bucket)}`)}>Browse data files</Button>
            <Button onClick={() => setAddNs(true)}>Create namespace</Button>
            <Button variant="primary" onClick={() => setAddTable(true)} disabled={!names.length}>
              Create table
            </Button>
          </>
        }
      />
      <Card title="Namespaces">
        <Loading state={nss}>
          {() =>
            nss.data!.length ? (
              <table>
                <thead>
                  <tr>
                    <th scope="col">Namespace</th>
                    <th scope="col" class="num">Tables</th>
                    <th scope="col">Created</th>
                    <th scope="col">
                      <span class="sr-only">Actions</span>
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {nss.data!.map((n) => {
                    const ns = n.namespace.join(".");
                    return (
                      <tr key={ns}>
                        <td>{ns}</td>
                        <td class="ops-num">{tbls.data ? count(ns) : "-"}</td>
                        <td>
                          {date(n.createdAt)}
                          {n.createdBy ? ` by ${n.createdBy}` : ""}
                        </td>
                        <td>
                          <div class="actions">
                            <Button small variant="danger" onClick={() => setDropNs(ns)} aria-label={`Delete namespace ${ns}`}>
                              Delete
                            </Button>
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            ) : (
              <Empty>No namespaces yet. Create one to hold tables.</Empty>
            )
          }
        </Loading>
      </Card>
      <Card title="Tables">
        <Loading state={tbls}>
          {() =>
            tbls.data!.length ? (
              <table>
                <thead>
                  <tr>
                    <th scope="col">Table</th>
                    <th scope="col">Namespace</th>
                    <th scope="col">Modified</th>
                    <th scope="col">
                      <span class="sr-only">Actions</span>
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {tbls.data!.map((t) => {
                    const ns = t.namespace.join(".");
                    return (
                      <tr key={`${ns}.${t.name}`}>
                        <td>{t.name}</td>
                        <td>{ns}</td>
                        <td>{date(t.modifiedAt)}</td>
                        <td>
                          <div class="actions">
                            <Button small onClick={() => setView({ ns, name: t.name })} aria-label={`Details of ${ns}.${t.name}`}>
                              Details
                            </Button>
                            <Button small variant="danger" onClick={() => setDropTable({ ns, name: t.name })} aria-label={`Delete table ${ns}.${t.name}`}>
                              Delete
                            </Button>
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            ) : (
              <Empty>No tables yet.</Empty>
            )
          }
        </Loading>
      </Card>
      <PolicyCard bucket={bucket} />
      {addNs && (
        <NameModal
          title="Create namespace"
          label="Namespace name"
          check={validName}
          onSubmit={async (n) => {
            await api.createNamespace(bucket, n);
            toast(`Namespace ${n} created`);
            nss.reload();
          }}
          onClose={() => setAddNs(false)}
        />
      )}
      {addTable && <CreateTable bucket={bucket} namespaces={names} onClose={() => setAddTable(false)} onDone={tbls.reload} />}
      {view && <TableModal bucket={bucket} ns={view.ns} name={view.name} onClose={() => setView(null)} />}
      {dropNs && (
        <Confirm
          title="Delete namespace"
          message={
            <>
              Delete namespace <strong>{dropNs}</strong>? It must be empty.
            </>
          }
          onConfirm={async () => {
            await api.deleteNamespace(bucket, dropNs);
            toast("Namespace deleted");
            nss.reload();
          }}
          onClose={() => setDropNs(null)}
        />
      )}
      {dropTable && (
        <Confirm
          title="Delete table"
          message={
            <>
              Delete table{" "}
              <strong>
                {dropTable.ns}.{dropTable.name}
              </strong>
              ? Engines can no longer load it.
            </>
          }
          onConfirm={async () => {
            await api.deleteTable(bucket, dropTable.ns, dropTable.name);
            toast("Table deleted");
            tbls.reload();
          }}
          onClose={() => setDropTable(null)}
        />
      )}
    </>
  );
}
