// Object details dialog: metadata, preview, share, tags, versions, retention and legal hold.
import { useEffect, useState } from "preact/hooks";
import { downloadUrl, encodeKey, presign, s3, s3Xml } from "../../lib/api";
import { bytes, date } from "../../lib/format";
import { tagsXml } from "../../lib/xml";
import { Badge, Button, Confirm, Empty, KeyValue, Modal, Select, Tabs, TextInput, Toggle, toast, toastError, useAsync } from "../../components/ui";
import { optional, PairsEditor, Section } from "./common";
import { baseName, deleteXml, parseDeleteErrors, parseVersions, previewKind } from "./keys";
import { legalHoldXml, parseTagSet, retentionXml, text } from "./xmlcfg";

const opath = (b: string, k: string) => `/${encodeURIComponent(b)}/${encodeKey(k)}`;
const PREVIEW_MAX = 1024 * 1024;

export interface PanelProps {
  bucket: string;
  objectKey: string;
  versionId?: string;
  lockEnabled: boolean;
  onClose: () => void;
  onChanged: () => void;
}

export function ObjectPanel(p: PanelProps) {
  const [tab, setTab] = useState("overview");
  const head = useAsync(async () => (await s3(opath(p.bucket, p.objectKey), { method: "HEAD", query: { versionId: p.versionId } })).headers, [p.bucket, p.objectKey, p.versionId]);
  const tabs: [string, string][] = [
    ["overview", "Overview"],
    ["preview", "Preview"],
    ["share", "Share"],
    ["tags", "Tags"],
    ["versions", "Versions"],
  ];
  if (p.lockEnabled) tabs.push(["lock", "Retention"]);
  return (
    <Modal wide title={baseName(p.objectKey, p.objectKey.slice(0, p.objectKey.lastIndexOf("/") + 1))} onClose={p.onClose}>
      <div class="bk-objpath mono">
        {p.bucket}/{p.objectKey}
        {p.versionId && <span class="hint"> (version {p.versionId})</span>}
      </div>
      <Tabs tabs={tabs} active={tab} onChange={setTab} />
      <div class="bk-tab" role="tabpanel">
        {tab === "overview" && <Overview {...p} head={head} />}
        {tab === "preview" && <Preview {...p} contentType={head.data?.get("content-type") || ""} size={Number(head.data?.get("content-length") || 0)} />}
        {tab === "share" && <Share {...p} />}
        {tab === "tags" && <ObjTags {...p} />}
        {tab === "versions" && <Versions {...p} />}
        {tab === "lock" && <Lock {...p} />}
      </div>
    </Modal>
  );
}

function Overview(p: PanelProps & { head: { loading: boolean; error?: Error; data?: Headers } }) {
  const [del, setDel] = useState(false);
  return (
    <Section state={p.head}>
      {() => {
        const h = p.head.data!;
        const meta: [string, string][] = [];
        const other: [string, string][] = [];
        h.forEach((v, k) => (k.startsWith("x-amz-meta-") ? meta.push([k.slice(11), v]) : other.push([k, v])));
        return (
          <>
            <KeyValue
              rows={[
                ["Size", bytes(Number(h.get("content-length")))],
                ["Last modified", date(h.get("last-modified"))],
                ["Content type", h.get("content-type") || "-"],
                ["ETag", <span class="mono">{(h.get("etag") || "-").replace(/"/g, "")}</span>],
                ["Version", <span class="mono">{h.get("x-amz-version-id") || "-"}</span>],
                ["Storage class", h.get("x-amz-storage-class") || "STANDARD"],
                ["Encryption", h.get("x-amz-server-side-encryption") || "none"],
              ]}
            />
            <h3 class="bk-h3">User metadata</h3>
            {meta.length ? <KeyValue rows={meta.map(([k, v]) => [k, v])} /> : <p class="hint">None</p>}
            <details class="bk-details">
              <summary>All response headers</summary>
              <KeyValue rows={other.map(([k, v]) => [k, <span class="mono">{v}</span>])} />
            </details>
            <div class="bk-buttons">
              <a class="btn btn-primary" href={downloadUrl(p.bucket, p.objectKey, p.versionId)} download={baseName(p.objectKey)}>
                Download
              </a>
              <Button variant="danger" onClick={() => setDel(true)}>
                Delete object
              </Button>
            </div>
            {del && (
              <Confirm
                title="Delete object"
                message={p.versionId ? `Permanently delete version ${p.versionId} of ${p.objectKey}?` : `Delete ${p.objectKey}? In a versioned bucket this adds a delete marker.`}
                onConfirm={async () => {
                  await s3(opath(p.bucket, p.objectKey), { method: "DELETE", query: { versionId: p.versionId } });
                  toast("Object deleted");
                  p.onChanged();
                  p.onClose();
                }}
                onClose={() => setDel(false)}
              />
            )}
          </>
        );
      }}
    </Section>
  );
}

function Preview(p: PanelProps & { contentType: string; size: number }) {
  const kind = previewKind(p.objectKey, p.contentType);
  const url = downloadUrl(p.bucket, p.objectKey, p.versionId);
  const txt = useAsync(async () => {
    if (kind !== "text") return "";
    const r = await fetch(url, { credentials: "same-origin", headers: { range: `bytes=0-${PREVIEW_MAX - 1}` } });
    if (!r.ok && r.status !== 206) throw new Error(`Preview failed (${r.status})`);
    return r.text();
  }, [url, kind]);
  if (kind === "image")
    return (
      <div class="preview">
        <img src={url} alt={p.objectKey} />
      </div>
    );
  if (kind === "none") return <Empty>No preview available for this file type.</Empty>;
  return (
    <Section state={txt}>
      {() => (
        <>
          {p.size > PREVIEW_MAX && <div class="notice">Showing the first 1 MiB of {bytes(p.size)}.</div>}
          <pre class="mono bk-pre preview">{txt.data}</pre>
        </>
      )}
    </Section>
  );
}

const EXPIRY: [string, string][] = [
  ["3600", "1 hour"],
  ["21600", "6 hours"],
  ["86400", "1 day"],
  ["259200", "3 days"],
  ["604800", "7 days"],
];

function Share(p: PanelProps) {
  const [exp, setExp] = useState("86400");
  const [link, setLink] = useState<{ url: string; expires: string } | null>(null);
  const [busy, setBusy] = useState(false);
  const gen = async () => {
    setBusy(true);
    try {
      const r = await presign(p.bucket, p.objectKey, Number(exp), p.versionId);
      setLink({ ...r, url: new URL(r.url, location.href).toString() });
    } catch (e) {
      toastError(e);
    } finally {
      setBusy(false);
    }
  };
  return (
    <>
      <p class="hint">Anyone with the link can download this object until it expires.</p>
      <div class="row">
        <Select label="Link expires in" value={exp} onChange={setExp} options={EXPIRY} />
        <Button variant="primary" disabled={busy} onClick={gen}>
          Generate link
        </Button>
      </div>
      {link && (
        <>
          <div class="bk-share">
            <input class="mono" readOnly value={link.url} aria-label="Share link" onFocus={(e) => (e.target as HTMLInputElement).select()} />
            <Button
              onClick={() =>
                navigator.clipboard.writeText(link.url).then(
                  () => toast("Link copied"),
                  () => toast("Copy failed; select the link and copy it manually", "error"),
                )
              }
            >
              Copy
            </Button>
          </div>
          <p class="hint">Expires {date(link.expires)}</p>
        </>
      )}
    </>
  );
}

function ObjTags(p: PanelProps) {
  const st = useAsync(() => optional(async () => parseTagSet(await s3Xml(opath(p.bucket, p.objectKey), { query: { tagging: true, versionId: p.versionId } }))), [p.bucket, p.objectKey, p.versionId]);
  const [pairs, setPairs] = useState<[string, string][]>([]);
  useEffect(() => {
    if (st.data !== undefined) setPairs(Object.entries(st.data || {}));
  }, [st.data]);
  const save = async () => {
    try {
      const clean = pairs.filter(([k]) => k.trim());
      if (clean.length) await s3(opath(p.bucket, p.objectKey), { method: "PUT", query: { tagging: true, versionId: p.versionId }, body: tagsXml(Object.fromEntries(clean)) });
      else await s3(opath(p.bucket, p.objectKey), { method: "DELETE", query: { tagging: true, versionId: p.versionId } });
      toast("Tags saved");
      st.reload();
    } catch (e) {
      toastError(e);
    }
  };
  return (
    <Section state={st}>
      {() => (
        <>
          <PairsEditor pairs={pairs} onChange={setPairs} />
          <div class="bk-buttons">
            <Button variant="primary" onClick={save}>
              Save tags
            </Button>
          </div>
        </>
      )}
    </Section>
  );
}

function Versions(p: PanelProps) {
  const st = useAsync(async () => {
    const d = await s3Xml(`/${encodeURIComponent(p.bucket)}`, { query: { versions: true, prefix: p.objectKey, "max-keys": 1000 } });
    return parseVersions(d).versions.filter((v) => v.key === p.objectKey);
  }, [p.bucket, p.objectKey]);
  const [del, setDel] = useState<string | null>(null);
  const [bypass, setBypass] = useState(false);
  return (
    <Section state={st}>
      {() =>
        !st.data!.length ? (
          <Empty>No versions found.</Empty>
        ) : (
          <>
            {p.lockEnabled && <Toggle label="Bypass governance retention" checked={bypass} onChange={setBypass} />}
            <table>
              <thead>
                <tr>
                  <th>Version</th>
                  <th>Modified</th>
                  <th class="num">Size</th>
                  <th class="bk-actions-col">
                    <span class="sr-only">Actions</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {st.data!.map((v) => (
                  <tr key={v.versionId}>
                    <td>
                      <span class="mono bk-small">{v.versionId}</span> {v.isLatest && <Badge kind="ok">Latest</Badge>} {v.deleteMarker && <Badge kind="warn">Delete marker</Badge>}
                    </td>
                    <td>{date(v.lastModified)}</td>
                    <td class="num">{v.deleteMarker ? "-" : bytes(v.size)}</td>
                    <td class="bk-actions-col">
                      {!v.deleteMarker && (
                        <a class="btn btn-sm" href={downloadUrl(p.bucket, p.objectKey, v.versionId)} download={baseName(p.objectKey)} aria-label={`Download version ${v.versionId}`}>
                          Download
                        </a>
                      )}
                      <Button small variant="ghost" aria-label={`Delete version ${v.versionId}`} onClick={() => setDel(v.versionId!)}>
                        Delete
                      </Button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {del && (
              <Confirm
                title="Delete version"
                message={`Permanently delete version ${del}?`}
                onConfirm={async () => {
                  const res = await s3Xml(`/${encodeURIComponent(p.bucket)}`, {
                    method: "POST",
                    query: { delete: true },
                    headers: { "content-type": "application/xml", ...(bypass ? { "x-amz-bypass-governance-retention": "true" } : {}) },
                    body: deleteXml([{ key: p.objectKey, versionId: del }]),
                  });
                  const errs = parseDeleteErrors(res);
                  if (errs.length) throw new Error(errs[0].message || errs[0].code);
                  toast("Version deleted");
                  st.reload();
                  p.onChanged();
                }}
                onClose={() => setDel(null)}
              />
            )}
          </>
        )
      }
    </Section>
  );
}

function toLocalInput(iso: string): string {
  const d = iso ? new Date(iso) : new Date(Date.now() + 86400000);
  const z = new Date(d.getTime() - d.getTimezoneOffset() * 60000);
  return z.toISOString().slice(0, 16);
}

function Lock(p: PanelProps) {
  const q = { versionId: p.versionId };
  const hold = useAsync(() => optional(async () => text(await s3Xml(opath(p.bucket, p.objectKey), { query: { "legal-hold": true, ...q } }), "Status") === "ON"), [p.bucket, p.objectKey, p.versionId]);
  const ret = useAsync(
    () =>
      optional(async () => {
        const d = await s3Xml(opath(p.bucket, p.objectKey), { query: { retention: true, ...q } });
        return { mode: text(d, "Mode"), until: text(d, "RetainUntilDate") };
      }),
    [p.bucket, p.objectKey, p.versionId],
  );
  const [mode, setMode] = useState<"GOVERNANCE" | "COMPLIANCE">("GOVERNANCE");
  const [until, setUntil] = useState(toLocalInput(""));
  const [bypass, setBypass] = useState(false);
  useEffect(() => {
    if (ret.data) {
      setMode(ret.data.mode === "COMPLIANCE" ? "COMPLIANCE" : "GOVERNANCE");
      setUntil(toLocalInput(ret.data.until));
    }
  }, [ret.data]);
  const setHold = async (on: boolean) => {
    try {
      await s3(opath(p.bucket, p.objectKey), { method: "PUT", query: { "legal-hold": true, ...q }, body: legalHoldXml(on) });
      toast(`Legal hold ${on ? "on" : "off"}`);
      hold.reload();
    } catch (e) {
      toastError(e);
    }
  };
  const saveRet = async () => {
    try {
      await s3(opath(p.bucket, p.objectKey), {
        method: "PUT",
        query: { retention: true, ...q },
        headers: bypass ? { "x-amz-bypass-governance-retention": "true" } : {},
        body: retentionXml(mode, new Date(until)),
      });
      toast("Retention saved");
      ret.reload();
    } catch (e) {
      toastError(e);
    }
  };
  return (
    <>
      <h3 class="bk-h3">Legal hold</h3>
      <Section state={hold}>{() => <Toggle label="Legal hold" checked={!!hold.data} onChange={setHold} />}</Section>
      <h3 class="bk-h3">Retention</h3>
      <Section state={ret}>
        {() => (
          <>
            <p class="hint">{ret.data?.mode ? `Currently ${ret.data.mode} until ${date(ret.data.until)}.` : "No retention set on this version."}</p>
            <div class="row">
              <Select label="Retention mode" value={mode} onChange={(v) => setMode(v as "GOVERNANCE" | "COMPLIANCE")} options={[["GOVERNANCE", "Governance"], ["COMPLIANCE", "Compliance"]]} />
              <TextInput label="Retain until" type="datetime-local" value={until} onInput={setUntil} />
            </div>
            <Toggle label="Bypass governance retention" checked={bypass} onChange={setBypass} />
            <div class="bk-buttons">
              <Button variant="primary" onClick={saveRet}>
                Save retention
              </Button>
            </div>
          </>
        )}
      </Section>
    </>
  );
}
