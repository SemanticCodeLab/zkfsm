import { Fragment } from "preact";
import { useCallback, useEffect, useMemo, useRef, useState } from "preact/hooks";
import { downloadUrl, encodeKey, s3, s3Xml } from "../lib/api";
import { bytes, date } from "../lib/format";
import { href, navigate, useRoute } from "../lib/router";
import { Badge, Button, Card, Empty, Modal, PageHeader, TextInput, Toggle, toast, toastError, useAsync } from "../components/ui";
import { ErrorNote, Section } from "./buckets/common";
import { baseName, chunk, crumbs, deleteXml, folderKey, ObjEntry, parentPrefix, parseDeleteErrors, parseListV2, parseVersions, SortKey, sortObjects, uploadKey } from "./buckets/keys";
import { listBuckets } from "./buckets/ops";
import { ObjectPanel } from "./buckets/ObjectPanel";
import { loadLock } from "./buckets/TabsSimple";
import { filesFromDrop, UploadList, useUploads } from "./buckets/Uploads";
import "./buckets/buckets.css";

export function Browser({ bucket }: { bucket?: string }) {
  if (!bucket) return <BucketPicker />;
  return <ObjectBrowser bucket={bucket} key={bucket} />;
}

function BucketPicker() {
  const st = useAsync(listBuckets, []);
  return (
    <>
      <PageHeader title="Object Browser">
        <p class="hint">Choose a bucket to browse.</p>
      </PageHeader>
      <Card>
        <Section state={st}>
          {() =>
            st.data!.length === 0 ? (
              <Empty>
                No buckets. <a href={href("/buckets")}>Create one</a>.
              </Empty>
            ) : (
              <ul class="bk-picker">
                {st.data!.map((b) => (
                  <li key={b.name}>
                    <a href={href(`/browser/${encodeURIComponent(b.name)}`)}>
                      <span class="bk-folder-icon" aria-hidden="true" />
                      <span class="mono">{b.name}</span>
                      <span class="hint">{date(b.created)}</span>
                    </a>
                  </li>
                ))}
              </ul>
            )
          }
        </Section>
      </Card>
    </>
  );
}

interface Row {
  id: string; // selection key: folder prefix or key + "\0" + versionId
  folder: boolean;
  key: string;
  obj?: ObjEntry;
}

const PAGE = 200;

function ObjectBrowser({ bucket }: { bucket: string }) {
  const route = useRoute();
  const prefix = route.params.get("prefix") || "";
  const bpath = `/${encodeURIComponent(bucket)}`;
  const [versions, setVersions] = useState(false);
  const [search, setSearch] = useState("");
  const [applied, setApplied] = useState("");
  const [sort, setSort] = useState<SortKey>("name");
  const [desc, setDesc] = useState(false);
  const [folders, setFolders] = useState<string[]>([]);
  const [objects, setObjects] = useState<ObjEntry[]>([]);
  const [cursor, setCursor] = useState<{ token?: string; key?: string; version?: string } | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<Error | null>(null);
  const [sel, setSel] = useState<Set<string>>(new Set());
  const [open, setOpen] = useState<{ key: string; versionId?: string } | null>(null);
  const [delOpen, setDelOpen] = useState(false);
  const [mkdir, setMkdir] = useState(false);
  const [over, setOver] = useState(false);
  const lock = useAsync(() => loadLock(bucket).catch(() => null), [bucket]);
  const seq = useRef(0);

  const load = useCallback(
    async (more: boolean) => {
      const n = ++seq.current;
      setLoading(true);
      setError(null);
      const listPrefix = prefix + applied;
      try {
        if (versions) {
          const d = await s3Xml(bpath, {
            query: { versions: true, prefix: listPrefix, delimiter: "/", "max-keys": PAGE, "key-marker": more ? cursor?.key : undefined, "version-id-marker": more ? cursor?.version : undefined },
          });
          if (n !== seq.current) return;
          const l = parseVersions(d);
          setFolders((f) => (more ? [...f, ...l.folders] : l.folders));
          setObjects((o) => (more ? [...o, ...l.versions] : l.versions));
          setCursor(l.nextKey ? { key: l.nextKey, version: l.nextVersion || undefined } : null);
        } else {
          const d = await s3Xml(bpath, { query: { "list-type": 2, prefix: listPrefix, delimiter: "/", "max-keys": PAGE, "continuation-token": more ? cursor?.token : undefined } });
          if (n !== seq.current) return;
          const l = parseListV2(d);
          setFolders((f) => (more ? [...f, ...l.folders] : l.folders));
          setObjects((o) => (more ? [...o, ...l.objects] : l.objects));
          setCursor(l.next ? { token: l.next } : null);
        }
        if (!more) setSel(new Set());
      } catch (e) {
        if (n === seq.current) setError(e as Error);
      } finally {
        if (n === seq.current) setLoading(false);
      }
    },
    [bpath, prefix, applied, versions, cursor],
  );

  useEffect(() => {
    load(false);
  }, [bpath, prefix, applied, versions]);
  useEffect(() => {
    setSearch("");
    setApplied("");
  }, [prefix]);

  const refresh = () => load(false);
  const uploads = useUploads(bucket, useDebounced(refresh, 400));

  const rows: Row[] = useMemo(() => {
    const fs = [...folders].sort((a, b) => (desc && sort === "name" ? b.localeCompare(a) : a.localeCompare(b)));
    const os = sortObjects(
      objects.filter((o) => o.key !== prefix || o.versionId),
      sort,
      desc,
    );
    return [
      ...fs.map((f) => ({ id: f, folder: true, key: f })),
      ...os.map((o) => ({ id: `${o.key}\0${o.versionId || ""}`, folder: false, key: o.key, obj: o })),
    ];
  }, [folders, objects, sort, desc, prefix]);

  const goPrefix = (p: string) => navigate(`/browser/${encodeURIComponent(bucket)}`, { prefix: p || undefined });
  const openRow = (r: Row) => (r.folder ? goPrefix(r.key) : setOpen({ key: r.key, versionId: versions ? r.obj?.versionId : undefined }));
  const toggle = (id: string) =>
    setSel((s) => {
      const n = new Set(s);
      n.has(id) ? n.delete(id) : n.add(id);
      return n;
    });
  const allSel = rows.length > 0 && rows.every((r) => sel.has(r.id));

  const startUpload = (list: { file: File; path: string }[]) => {
    if (!list.length) return;
    uploads.add(list.map(({ file, path }) => ({ file, key: uploadKey(prefix, { name: path }) })));
  };
  const onFiles = (e: Event) => {
    const input = e.target as HTMLInputElement;
    startUpload(Array.from(input.files || []).map((f) => ({ file: f, path: f.webkitRelativePath || f.name })));
    input.value = "";
  };

  const sortBtn = (k: SortKey, label: string) => (
    <button
      type="button"
      class="bk-sort"
      aria-label={`Sort by ${label}`}
      aria-sort={sort === k ? (desc ? "descending" : "ascending") : undefined}
      onClick={() => (sort === k ? setDesc(!desc) : (setSort(k), setDesc(false)))}
    >
      {label}
      {sort === k ? (desc ? " ▾" : " ▴") : ""}
    </button>
  );

  return (
    <>
      <nav class="breadcrumbs" aria-label="Breadcrumb">
        <a href={href("/browser")}>Buckets</a>
        <span aria-hidden="true">/</span>
        {prefix ? <a href={href(`/browser/${encodeURIComponent(bucket)}`)}>{bucket}</a> : <span aria-current="page">{bucket}</span>}
        {crumbs(prefix).map((c, i, a) => (
          <Fragment key={c.prefix}>
            <span aria-hidden="true">/</span>
            {i === a.length - 1 ? (
              <span aria-current="page">{c.name}</span>
            ) : (
              <a href={href(`/browser/${encodeURIComponent(bucket)}`, { prefix: c.prefix })}>{c.name}</a>
            )}
          </Fragment>
        ))}
      </nav>
      <PageHeader
        title={<span class="mono">{bucket}</span>}
        actions={
          <>
            <a class="btn" href={href(`/buckets/${encodeURIComponent(bucket)}`)}>
              Settings
            </a>
            <Button onClick={() => setMkdir(true)}>New folder</Button>
            <label class="btn">
              Upload folder
              <input type="file" class="sr-only" multiple {...{ webkitdirectory: "", directory: "" }} aria-label="Upload folder" onChange={onFiles} />
            </label>
            <label class="btn btn-primary">
              Upload files
              <input type="file" class="sr-only" multiple aria-label="Upload files" onChange={onFiles} data-testid="upload-input" />
            </label>
          </>
        }
      />
      <UploadList items={uploads.items} cancel={uploads.cancel} clear={uploads.clear} />
      <div
        class={`dropzone bk-drop${over ? " over" : ""}`}
        onDragOver={(e) => {
          if (!e.dataTransfer?.types.includes("Files")) return;
          e.preventDefault();
          setOver(true);
        }}
        onDragLeave={(e) => e.currentTarget === e.target && setOver(false)}
        onDrop={async (e) => {
          e.preventDefault();
          setOver(false);
          if (e.dataTransfer) startUpload(await filesFromDrop(e.dataTransfer));
        }}
      >
        <div class="bk-toolbar">
          <form
            class="bk-searchform"
            role="search"
            onSubmit={(e) => {
              e.preventDefault();
              setApplied(search);
            }}
          >
            <input type="search" class="bk-search" placeholder={`Search in ${prefix || "/"} by name prefix`} aria-label="Search objects" value={search} onInput={(e) => {
              const v = (e.target as HTMLInputElement).value;
              setSearch(v);
              if (!v) setApplied("");
            }} />
            <Button small type="submit">
              Search
            </Button>
          </form>
          <Toggle label="Show versions" checked={versions} onChange={setVersions} />
          <div class="bk-spacer" />
          {prefix && (
            <Button small variant="ghost" onClick={() => goPrefix(parentPrefix(prefix))}>
              Up
            </Button>
          )}
          <Button small onClick={refresh}>
            Refresh
          </Button>
          <Button small variant="danger" disabled={sel.size === 0} onClick={() => setDelOpen(true)}>
            Delete
          </Button>
        </div>
        {error ? (
          <ErrorNote error={error} />
        ) : rows.length === 0 && !loading ? (
          <Empty>{applied ? "Nothing matches the search." : "This folder is empty. Drop files here or use Upload files."}</Empty>
        ) : (
          <table class="bk-objects" aria-label="Objects" aria-busy={loading}>
            <thead>
              <tr>
                <th class="bk-check-col">
                  <input type="checkbox" aria-label="Select all" checked={allSel} onChange={() => setSel(allSel ? new Set() : new Set(rows.map((r) => r.id)))} />
                </th>
                <th>{sortBtn("name", "Name")}</th>
                <th>{sortBtn("modified", "Last modified")}</th>
                <th class="num">{sortBtn("size", "Size")}</th>
                <th class="bk-actions-col">
                  <span class="sr-only">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => {
                const name = baseName(r.key, prefix);
                return (
                  <tr
                    key={r.id}
                    tabIndex={0}
                    class={`bk-click${sel.has(r.id) ? " bk-selected" : ""}`}
                    data-testid="object-row"
                    aria-selected={sel.has(r.id)}
                    onKeyDown={(e) => {
                      if (e.target !== e.currentTarget) return;
                      if (e.key === "Enter") openRow(r);
                      else if (e.key === " ") {
                        e.preventDefault();
                        toggle(r.id);
                      } else if (e.key === "Delete") {
                        if (!sel.size) setSel(new Set([r.id]));
                        setDelOpen(true);
                      }
                    }}
                    onClick={(e) => !(e.target as HTMLElement).closest("a,button,input,label") && openRow(r)}
                  >
                    <td class="bk-check-col">
                      <input type="checkbox" aria-label={`Select ${name}`} checked={sel.has(r.id)} onChange={() => toggle(r.id)} />
                    </td>
                    <td>
                      <button type="button" class="bk-link" onClick={() => openRow(r)} tabIndex={-1}>
                        <span class={r.folder ? "bk-folder-icon" : "bk-file-icon"} aria-hidden="true" />
                        <span class="bk-ellipsis">{name}</span>
                      </button>
                      {r.obj?.versionId && (
                        <span class="bk-vmeta">
                          <span class="mono bk-small">{r.obj.versionId}</span>
                          {r.obj.isLatest && <Badge kind="ok">Latest</Badge>}
                          {r.obj.deleteMarker && <Badge kind="warn">Delete marker</Badge>}
                        </span>
                      )}
                    </td>
                    <td>{r.obj ? date(r.obj.lastModified) : ""}</td>
                    <td class="num">{r.obj && !r.obj.deleteMarker ? bytes(r.obj.size) : ""}</td>
                    <td class="bk-actions-col">
                      {r.obj && !r.obj.deleteMarker && (
                        <a class="btn btn-sm" href={downloadUrl(bucket, r.key, versions ? r.obj.versionId : undefined)} download={baseName(r.key)} title={`Download ${name}`}>
                          Download
                        </a>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
        <div class="bk-footer">
          <span class="hint">
            {folders.length} folder{folders.length === 1 ? "" : "s"}, {objects.length} {versions ? "version" : "object"}
            {objects.length === 1 ? "" : "s"}
            {sel.size ? `, ${sel.size} selected` : ""}
          </span>
          {loading && <span class="loading">Loading…</span>}
          {cursor && !loading && (
            <Button small onClick={() => load(true)}>
              Load more
            </Button>
          )}
        </div>
      </div>
      {open && <ObjectPanel bucket={bucket} objectKey={open.key} versionId={open.versionId} lockEnabled={!!lock.data?.enabled} onClose={() => setOpen(null)} onChanged={refresh} />}
      {delOpen && (
        <DeleteDialog
          bucket={bucket}
          rows={rows.filter((r) => sel.has(r.id))}
          versionMode={versions}
          lockEnabled={!!lock.data?.enabled}
          onClose={() => setDelOpen(false)}
          onDone={() => {
            setSel(new Set());
            refresh();
          }}
        />
      )}
      {mkdir && <NewFolder bucket={bucket} prefix={prefix} onClose={() => setMkdir(false)} onDone={(p) => goPrefix(p)} />}
    </>
  );
}

function useDebounced(fn: () => void, ms: number) {
  const t = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  const f = useRef(fn);
  f.current = fn;
  return useCallback(() => {
    clearTimeout(t.current);
    t.current = setTimeout(() => f.current(), ms);
  }, [ms]);
}

/** Expands rows into concrete deletions; folders are listed recursively. */
async function collectTargets(bucket: string, rows: Row[], versionMode: boolean, allVersions: boolean): Promise<{ key: string; versionId?: string }[]> {
  const bpath = `/${encodeURIComponent(bucket)}`;
  const out: { key: string; versionId?: string }[] = [];
  const listVersions = async (prefix: string, exact?: string) => {
    let km: string | undefined;
    let vm: string | undefined;
    for (;;) {
      const l = parseVersions(await s3Xml(bpath, { query: { versions: true, prefix, "max-keys": 1000, "key-marker": km, "version-id-marker": vm } }));
      for (const v of l.versions) if (exact === undefined || v.key === exact) out.push({ key: v.key, versionId: v.versionId });
      if (!l.nextKey) break;
      km = l.nextKey;
      vm = l.nextVersion || undefined;
    }
  };
  for (const r of rows) {
    if (r.folder) {
      if (allVersions || versionMode) await listVersions(r.key);
      else {
        let token: string | undefined;
        for (;;) {
          const l = parseListV2(await s3Xml(bpath, { query: { "list-type": 2, prefix: r.key, "max-keys": 1000, "continuation-token": token } }));
          out.push(...l.objects.map((o) => ({ key: o.key })));
          if (!l.next) break;
          token = l.next;
        }
        out.push({ key: r.key });
      }
    } else if (versionMode) out.push({ key: r.key, versionId: r.obj?.versionId });
    else if (allVersions) await listVersions(r.key, r.key);
    else out.push({ key: r.key });
  }
  return out;
}

function DeleteDialog({ bucket, rows, versionMode, lockEnabled, onClose, onDone }: { bucket: string; rows: Row[]; versionMode: boolean; lockEnabled: boolean; onClose: () => void; onDone: () => void }) {
  const [allVersions, setAllVersions] = useState(false);
  const [bypass, setBypass] = useState(false);
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState(0);
  const folders = rows.filter((r) => r.folder).length;
  const go = async () => {
    setBusy(true);
    try {
      const targets = await collectTargets(bucket, rows, versionMode, allVersions);
      const failures: string[] = [];
      for (const group of chunk(targets, 1000)) {
        const res = await s3Xml(`/${encodeURIComponent(bucket)}`, {
          method: "POST",
          query: { delete: true },
          headers: { "content-type": "application/xml", ...(bypass ? { "x-amz-bypass-governance-retention": "true" } : {}) },
          body: deleteXml(group),
        });
        failures.push(...parseDeleteErrors(res).map((e) => `${e.key}: ${e.message || e.code}`));
        setDone((d) => d + group.length);
      }
      if (failures.length) toast(`${failures.length} failed. ${failures[0]}`, "error");
      else toast(`Deleted ${targets.length} item${targets.length === 1 ? "" : "s"}`);
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
      title="Delete objects"
      onClose={onClose}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="danger" disabled={busy || rows.length === 0} onClick={go}>
            Delete
          </Button>
        </>
      }
    >
      <p>
        Delete {rows.length} selected item{rows.length === 1 ? "" : "s"}
        {folders ? ` (including everything inside ${folders} folder${folders === 1 ? "" : "s"})` : ""}?
      </p>
      {rows.length <= 5 && (
        <ul class="bk-dellist mono">
          {rows.map((r) => (
            <li key={r.id}>
              {r.key}
              {versionMode && r.obj?.versionId ? ` (${r.obj.versionId})` : ""}
            </li>
          ))}
        </ul>
      )}
      {versionMode ? (
        <div class="notice notice-warn">Selected versions are deleted permanently.</div>
      ) : (
        <Toggle label="Delete all versions permanently" checked={allVersions} onChange={setAllVersions} />
      )}
      {lockEnabled && <Toggle label="Bypass governance retention" checked={bypass} onChange={setBypass} />}
      {busy && <p class="hint">Deleted {done}…</p>}
    </Modal>
  );
}

function NewFolder({ bucket, prefix, onClose, onDone }: { bucket: string; prefix: string; onClose: () => void; onDone: (p: string) => void }) {
  const [name, setName] = useState("");
  const key = folderKey(prefix, name);
  const go = async (e?: Event) => {
    e?.preventDefault();
    if (!key) return;
    try {
      await s3(`/${encodeURIComponent(bucket)}/${encodeKey(key)}`, { method: "PUT", body: "" });
      toast(`Folder ${key} created`);
      onClose();
      onDone(key);
    } catch (x) {
      toastError(x);
    }
  };
  return (
    <Modal
      title="New folder"
      onClose={onClose}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" disabled={!key} onClick={() => go()}>
            Create
          </Button>
        </>
      }
    >
      <form onSubmit={go}>
        <TextInput label="Folder name" value={name} onInput={setName} autofocus error={name && !key ? "Invalid folder name." : null} hint={key ? `Creates ${key}` : undefined} />
      </form>
    </Modal>
  );
}

