import { useState } from "preact/hooks";
import { Badge, Button, Card, Confirm, Empty, Loading, Modal, PageHeader, Tabs, TextInput, Toggle, toast, toastError, useAsync } from "../components/ui";
import { admin, ApiError } from "../lib/api";
import { iam } from "./iam/iamapi";
import { CheckList } from "./iam/widgets";
import "./iam/iam.css";

type Kind = "openid" | "ldap";
interface IdpItem {
  type: Kind;
  name: string;
  enabled: boolean;
  roleARN?: string;
}
interface IdpInfo {
  type: Kind;
  name: string;
  info: { key: string; value: string; isCfg: boolean; isEnv: boolean }[];
}

const fields: Record<Kind, [string, string, boolean?][]> = {
  openid: [
    ["config_url", "Discovery URL (config_url)"],
    ["client_id", "Client ID"],
    ["client_secret", "Client secret", true],
    ["display_name", "Display name"],
    ["claim_name", "Policy claim name"],
    ["claim_prefix", "Claim prefix"],
    ["scopes", "Scopes (comma separated)"],
    ["redirect_uri", "Redirect URI"],
    ["role_policy", "Role policy (all identities get it)"],
  ],
  ldap: [
    ["server_addr", "Server address (host:port)"],
    ["lookup_bind_dn", "Lookup bind DN"],
    ["lookup_bind_password", "Lookup bind password", true],
    ["user_dn_search_base_dn", "User search base DN"],
    ["user_dn_search_filter", "User search filter"],
    ["group_search_base_dn", "Group search base DN"],
    ["group_search_filter", "Group search filter"],
    ["tls_ca_file", "TLS CA file"],
  ],
};

/** `key=value` pairs with values quoted when they contain spaces. */
export function settingsText(values: Record<string, string>): string {
  return Object.entries(values)
    .filter(([, v]) => v !== "")
    .map(([k, v]) => (/[\s"]/.test(v) ? `${k}="${v.replace(/"/g, '\\"')}"` : `${k}=${v}`))
    .join(" ");
}

const isUnsupported = (e?: Error) => e instanceof ApiError && (e.status === 501 || e.status === 400 && /Unknown identity provider type/.test(e.message));

export function Identity() {
  const [tab, setTab] = useState<Kind | "mappings">("openid");
  return (
    <>
      <PageHeader title="OpenID / LDAP">
        <p class="hint">External identity providers for console and STS logins. Changes apply immediately.</p>
      </PageHeader>
      <Tabs
        tabs={[
          ["openid", "OpenID"],
          ["ldap", "LDAP"],
          ["mappings", "LDAP policy mappings"],
        ]}
        active={tab}
        onChange={(k) => setTab(k as Kind)}
      />
      {tab === "mappings" ? <LdapMappings /> : <Providers kind={tab} key={tab} />}
    </>
  );
}

function Providers({ kind }: { kind: Kind }) {
  const list = useAsync(() => admin<IdpItem[] | null>(`/idp-config/${kind}`).then((x) => x || []), [kind]);
  const [edit, setEdit] = useState<{ name: string; existing: boolean } | null>(null);
  const [del, setDel] = useState<string | null>(null);
  return (
    <Card
      title={kind === "openid" ? "OpenID providers" : "LDAP directory"}
      actions={
        (kind === "openid" || (list.data && list.data.length === 0)) && (
          <Button variant="primary" onClick={() => setEdit({ name: kind === "ldap" ? "_" : "", existing: false })}>
            {kind === "openid" ? "Add Provider" : "Configure LDAP"}
          </Button>
        )
      }
    >
      {isUnsupported(list.error) ? (
        <div class="notice notice-warn">Not supported by this server.</div>
      ) : (
        <Loading state={list}>
          {() =>
            list.data!.length === 0 ? (
              <Empty>{kind === "openid" ? "No OpenID providers configured." : "LDAP is not configured."}</Empty>
            ) : (
              <table>
                <thead>
                  <tr>
                    <th>Name</th>
                    <th>Status</th>
                    {kind === "openid" && <th>Role ARN</th>}
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {list.data!.map((p) => (
                    <tr key={p.name}>
                      <td>{p.name === "_" ? "default" : p.name}</td>
                      <td>
                        <Badge kind={p.enabled ? "ok" : "warn"}>{p.enabled ? "enabled" : "disabled"}</Badge>
                      </td>
                      {kind === "openid" && <td class="mono">{p.roleARN || "-"}</td>}
                      <td class="iam-actions">
                        <Button small onClick={() => setEdit({ name: p.name, existing: true })}>
                          Edit
                        </Button>{" "}
                        <Button small variant="danger" onClick={() => setDel(p.name)}>
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
      )}
      {edit && <ProviderModal kind={kind} name={edit.name} existing={edit.existing} onClose={() => setEdit(null)} onDone={list.reload} />}
      {del && (
        <Confirm
          title="Remove provider"
          message={`Remove ${kind} configuration ${del === "_" ? "default" : del}?`}
          confirmLabel="Remove"
          onClose={() => setDel(null)}
          onConfirm={async () => {
            await admin(`/idp-config/${kind}/${encodeURIComponent(del)}`, { method: "DELETE" });
            toast("Provider removed");
            list.reload();
          }}
        />
      )}
    </Card>
  );
}

function ProviderModal({ kind, name, existing, onClose, onDone }: { kind: Kind; name: string; existing: boolean; onClose: () => void; onDone: () => void }) {
  const [pname, setPname] = useState(name);
  const [vals, setVals] = useState<Record<string, string>>({});
  const [enabled, setEnabled] = useState(true);
  const [busy, setBusy] = useState(false);
  const info = useAsync(async () => {
    if (!existing) return null;
    const i = await admin<IdpInfo>(`/idp-config/${kind}/${encodeURIComponent(name)}`);
    const v: Record<string, string> = {};
    for (const x of i.info) if (x.isCfg && x.value !== "*redacted*" && x.key !== "enable") v[x.key] = x.value;
    setVals(v);
    setEnabled(i.info.find((x) => x.key === "enable")?.value !== "off");
    return i;
  }, [kind, name]);
  return (
    <Modal
      title={existing ? `Edit ${kind} ${name === "_" ? "default" : name}` : `Add ${kind} provider`}
      wide
      onClose={onClose}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button
            variant="primary"
            disabled={busy || !pname}
            onClick={async () => {
              setBusy(true);
              try {
                const body = settingsText({ ...vals, enable: enabled ? "on" : "off" });
                await admin(`/idp-config/${kind}/${encodeURIComponent(pname)}`, { method: existing ? "POST" : "PUT", body, encrypt: true });
                toast("Identity provider saved");
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
      <Loading state={existing ? info : { loading: false, data: true }}>
        {() => (
          <>
            {kind === "openid" && <TextInput label="Configuration name" value={pname} onInput={setPname} disabled={existing} hint="Use _ for the default provider" />}
            <Toggle label="Enabled" checked={enabled} onChange={setEnabled} />
            {fields[kind].map(([k, label, secret]) => (
              <TextInput
                key={k}
                label={label}
                value={vals[k] || ""}
                type={secret ? "password" : "text"}
                hint={secret && existing ? "Leave empty to keep the stored value" : undefined}
                onInput={(v) => setVals({ ...vals, [k]: v })}
              />
            ))}
            {kind === "ldap" && (
              <>
                <Toggle label="Plain TCP without TLS (server_insecure)" checked={vals.server_insecure === "on"} onChange={(b) => setVals({ ...vals, server_insecure: b ? "on" : "" })} />
                <Toggle label="StartTLS" checked={vals.server_starttls === "on"} onChange={(b) => setVals({ ...vals, server_starttls: b ? "on" : "" })} />
                <Toggle label="Skip TLS verification" checked={vals.tls_skip_verify === "on"} onChange={(b) => setVals({ ...vals, tls_skip_verify: b ? "on" : "" })} />
              </>
            )}
          </>
        )}
      </Loading>
    </Modal>
  );
}

interface Entities {
  userMappings?: { user: string; policies: string[] }[] | null;
  groupMappings?: { group: string; policies: string[] }[] | null;
}

function LdapMappings() {
  const ents = useAsync(() => admin<Entities>("/idp/ldap/policy-entities"), []);
  const [adding, setAdding] = useState(false);
  const rows = [...(ents.data?.userMappings || []).map((m) => ({ dn: m.user, group: false, policies: m.policies })), ...(ents.data?.groupMappings || []).map((m) => ({ dn: m.group, group: true, policies: m.policies }))];
  return (
    <Card
      title="Policies mapped to LDAP users and groups"
      actions={
        <Button variant="primary" onClick={() => setAdding(true)}>
          Attach Policies
        </Button>
      }
    >
      <Loading state={ents}>
        {() =>
          rows.length === 0 ? (
            <Empty>No mappings.</Empty>
          ) : (
            <table>
              <thead>
                <tr>
                  <th>Distinguished name</th>
                  <th>Kind</th>
                  <th>Policies</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {rows.map((r) => (
                  <tr key={`${r.group}:${r.dn}`}>
                    <td class="mono">{r.dn}</td>
                    <td>{r.group ? "group" : "user"}</td>
                    <td>
                      <span class="iam-tags">
                        {r.policies.map((p) => (
                          <Badge key={p}>{p}</Badge>
                        ))}
                      </span>
                    </td>
                    <td class="iam-actions">
                      <Button
                        small
                        variant="danger"
                        onClick={async () => {
                          try {
                            await admin("/idp/ldap/policy/detach", { method: "POST", body: JSON.stringify({ policies: r.policies, [r.group ? "group" : "user"]: r.dn }), encrypt: true });
                            ents.reload();
                          } catch (e) {
                            toastError(e);
                          }
                        }}
                      >
                        Detach all
                      </Button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )
        }
      </Loading>
      {adding && <AttachLdap onClose={() => setAdding(false)} onDone={ents.reload} />}
    </Card>
  );
}

function AttachLdap({ onClose, onDone }: { onClose: () => void; onDone: () => void }) {
  const pols = useAsync(iam.policies, []);
  const [dn, setDn] = useState("");
  const [group, setGroup] = useState(false);
  const [sel, setSel] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);
  return (
    <Modal
      title="Attach policies to an LDAP entity"
      onClose={onClose}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button
            variant="primary"
            disabled={busy || !dn || !sel.length}
            onClick={async () => {
              setBusy(true);
              try {
                await admin("/idp/ldap/policy/attach", { method: "POST", body: JSON.stringify({ policies: sel, [group ? "group" : "user"]: dn }), encrypt: true });
                toast("Policies attached");
                onDone();
                onClose();
              } catch (e) {
                toastError(e);
              } finally {
                setBusy(false);
              }
            }}
          >
            Attach
          </Button>
        </>
      }
    >
      <TextInput label="Distinguished name" value={dn} onInput={setDn} placeholder="uid=alice,ou=people,dc=example,dc=org" />
      <Toggle label="This is a group DN" checked={group} onChange={setGroup} />
      <Loading state={pols}>{() => <CheckList legend="Policies" options={Object.keys(pols.data!).sort()} selected={sel} onChange={setSel} />}</Loading>
    </Modal>
  );
}
