import { useEffect, useState } from "preact/hooks";
import { Button, Card, Confirm, Empty, JsonEditor, Loading, PageHeader, TextInput, toast, toastError, useAsync } from "../components/ui";
import { href, navigate } from "../lib/router";
import { iam, policyTemplates, validatePolicy } from "./iam/iamapi";
import { SearchBox } from "./iam/widgets";
import "./iam/iam.css";

const builtin = new Set(["readonly", "readwrite", "writeonly", "diagnostics", "consoleAdmin"]);

export function Policies({ policy }: { policy?: string }) {
  if (policy === "new") return <PolicyEditor />;
  return policy ? <PolicyEditor name={policy} /> : <PolicyList />;
}

function summarize(doc: unknown): string {
  const st = (doc as { Statement?: unknown })?.Statement;
  const list = Array.isArray(st) ? st : st ? [st] : [];
  const actions = new Set<string>();
  for (const s of list) {
    const a = (s as { Action?: string | string[] }).Action;
    for (const x of Array.isArray(a) ? a : a ? [a] : []) actions.add(x);
  }
  const all = [...actions];
  return all.length > 4 ? `${all.slice(0, 4).join(", ")} +${all.length - 4}` : all.join(", ");
}

function PolicyList() {
  const pols = useAsync(iam.policies, []);
  const [q, setQ] = useState("");
  const [del, setDel] = useState<string | null>(null);
  const rows = Object.entries(pols.data || {})
    .filter(([n]) => n.toLowerCase().includes(q.toLowerCase()))
    .sort(([a], [b]) => a.localeCompare(b));
  return (
    <>
      <PageHeader
        title="Policies"
        actions={
          <>
            <Button onClick={pols.reload}>Refresh</Button>
            <Button variant="primary" onClick={() => navigate("/iam/policies/new")}>
              Create Policy
            </Button>
          </>
        }
      />
      <Card>
        <SearchBox value={q} onInput={setQ} label="Filter policies" />
        <Loading state={pols}>
          {() =>
            rows.length === 0 ? (
              <Empty>No policies.</Empty>
            ) : (
              <table data-testid="policies-table">
                <thead>
                  <tr>
                    <th>Name</th>
                    <th>Actions</th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {rows.map(([name, doc]) => (
                    <tr key={name}>
                      <td>
                        <a href={href(`/iam/policies/${encodeURIComponent(name)}`)}>{name}</a>
                      </td>
                      <td class="mono">{summarize(doc)}</td>
                      <td class="iam-actions">
                        {!builtin.has(name) && (
                          <Button small variant="danger" aria-label={`Delete policy ${name}`} onClick={() => setDel(name)}>
                            Delete
                          </Button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )
          }
        </Loading>
      </Card>
      {del && (
        <Confirm
          title="Delete policy"
          message={`Delete policy ${del}? Users and groups lose what it grants.`}
          onClose={() => setDel(null)}
          onConfirm={async () => {
            await iam.removePolicy(del);
            toast(`Policy ${del} deleted`);
            pols.reload();
          }}
        />
      )}
    </>
  );
}

function PolicyEditor({ name }: { name?: string }) {
  const [pname, setPname] = useState(name || "");
  const [text, setText] = useState(name ? "" : policyTemplates.readonly());
  const [bucket, setBucket] = useState("");
  const [busy, setBusy] = useState(false);
  const [loadErr, setLoadErr] = useState<Error | null>(null);
  const users = useAsync(() => (name ? iam.users() : Promise.resolve([])), [name]);
  useEffect(() => {
    if (name) iam.policy(name).then(setText, setLoadErr);
  }, [name]);
  const errs = text ? validatePolicy(text) : ["Policy document is empty."];
  const usedBy = (users.data || []).filter((u) => name && u.policies.includes(name)).map((u) => u.name);
  return (
    <>
      <PageHeader
        title={name ? `Policy ${name}` : "Create policy"}
        actions={
          <a class="btn btn-ghost" href={href("/iam/policies")}>
            All policies
          </a>
        }
      />
      <Card>
        {loadErr && (
          <div class="notice notice-error" role="alert">
            {loadErr.message}
          </div>
        )}
        <form
          onSubmit={async (e) => {
            e.preventDefault();
            if (errs.length || !pname.trim()) return;
            setBusy(true);
            try {
              await iam.putPolicy(pname.trim(), JSON.stringify(JSON.parse(text)));
              toast(`Policy ${pname} saved`);
              navigate("/iam/policies");
            } catch (x) {
              toastError(x);
            } finally {
              setBusy(false);
            }
          }}
        >
          <TextInput label="Policy name" value={pname} onInput={setPname} disabled={!!name} autoFocus={!name} />
          {!name && (
            <div class="iam-template-row">
              <span class="hint">Templates:</span>
              {["readonly", "readwrite", "writeonly", "diagnostics"].map((t) => (
                <Button small key={t} onClick={() => setText(policyTemplates[t]())}>
                  {t}
                </Button>
              ))}
              <input aria-label="Bucket for template" placeholder="bucket name" value={bucket} onInput={(e) => setBucket((e.target as HTMLInputElement).value)} />
              <Button small disabled={!bucket} onClick={() => setText(policyTemplates.bucket(bucket))}>
                bucket access
              </Button>
            </div>
          )}
          <JsonEditor label="Policy document" value={text} onChange={setText} rows={20} />
          {errs.length > 0 && text && (
            <ul class="iam-errors">
              {errs.map((x) => (
                <li key={x}>{x}</li>
              ))}
            </ul>
          )}
          <div class="actions">
            <Button type="submit" variant="primary" disabled={busy || errs.length > 0 || !pname.trim()}>
              Save
            </Button>
          </div>
        </form>
      </Card>
      {name && (
        <Card title="Users with this policy">
          {usedBy.length ? (
            <ul>
              {usedBy.map((u) => (
                <li key={u}>
                  <a href={href(`/iam/users/${encodeURIComponent(u)}`)}>{u}</a>
                </li>
              ))}
            </ul>
          ) : (
            <Empty>No users have this policy attached directly.</Empty>
          )}
        </Card>
      )}
    </>
  );
}
