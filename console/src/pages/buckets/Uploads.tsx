// Upload queue: runs a few uploads at a time and renders per-file progress.
import { useRef, useState } from "preact/hooks";
import { bytes } from "../../lib/format";
import { Badge, Button, Progress } from "../../components/ui";
import { isCancelled, UploadHandle, uploadFile } from "./upload";

export interface UploadItem {
  id: number;
  key: string;
  size: number;
  sent: number;
  status: "queued" | "uploading" | "done" | "error" | "cancelled";
  error?: string;
}

const PARALLEL_FILES = 3;
let seq = 0;

export function useUploads(bucket: string, onFileDone: () => void) {
  const [items, setItems] = useState<UploadItem[]>([]);
  const files = useRef(new Map<number, { file: File; key: string }>());
  const handles = useRef(new Map<number, UploadHandle>());
  const queue = useRef<number[]>([]);
  const active = useRef(0);

  const patch = (id: number, p: Partial<UploadItem>) => setItems((xs) => xs.map((x) => (x.id === id ? { ...x, ...p } : x)));

  const pump = () => {
    while (active.current < PARALLEL_FILES && queue.current.length) {
      const id = queue.current.shift()!;
      const job = files.current.get(id);
      if (!job) continue;
      const { file, key } = job;
      active.current++;
      patch(id, { status: "uploading" });
      const h = uploadFile(bucket, key, file, (sent) => patch(id, { sent }));
      handles.current.set(id, h);
      h.promise.then(
        () => {
          patch(id, { status: "done", sent: file.size });
          onFileDone();
        },
        (e) => patch(id, isCancelled(e) ? { status: "cancelled" } : { status: "error", error: e instanceof Error ? e.message : String(e) }),
      ).finally(() => {
        active.current--;
        handles.current.delete(id);
        files.current.delete(id);
        pump();
      });
    }
  };

  const add = (list: { file: File; key: string }[]) => {
    const fresh: UploadItem[] = list.map(({ file, key }) => {
      const id = ++seq;
      files.current.set(id, { file, key });
      queue.current.push(id);
      return { id, key, size: file.size, sent: 0, status: "queued" };
    });
    setItems((xs) => [...xs, ...fresh]);
    setTimeout(pump, 0);
  };

  const cancel = (id: number) => {
    const h = handles.current.get(id);
    if (h) h.cancel();
    else {
      queue.current = queue.current.filter((x) => x !== id);
      files.current.delete(id);
      patch(id, { status: "cancelled" });
    }
  };

  const clear = () => setItems((xs) => xs.filter((x) => x.status === "uploading" || x.status === "queued"));
  return { items, add, cancel, clear };
}

export function UploadList({ items, cancel, clear }: { items: UploadItem[]; cancel: (id: number) => void; clear: () => void }) {
  if (!items.length) return null;
  const running = items.filter((x) => x.status === "uploading" || x.status === "queued").length;
  return (
    <section class="card bk-uploads" aria-label="Uploads">
      <div class="card-head">
        <h2>Uploads {running ? `(${running} in progress)` : ""}</h2>
        <div class="actions">
          <Button small onClick={clear} disabled={running === items.length}>
            Clear finished
          </Button>
        </div>
      </div>
      <ul class="bk-upload-list">
        {items.map((x) => (
          <li key={x.id} data-testid="upload-item">
            <div class="bk-upload-row">
              <span class="mono bk-ellipsis" title={x.key}>
                {x.key}
              </span>
              <span class="hint">
                {bytes(x.sent)} / {bytes(x.size)}
              </span>
              {x.status === "done" && <Badge kind="ok">Done</Badge>}
              {x.status === "error" && <Badge kind="error">Failed</Badge>}
              {x.status === "cancelled" && <Badge>Cancelled</Badge>}
              {x.status === "queued" && <Badge>Queued</Badge>}
              {(x.status === "uploading" || x.status === "queued") && (
                <Button small variant="ghost" aria-label={`Cancel upload ${x.key}`} onClick={() => cancel(x.id)}>
                  Cancel
                </Button>
              )}
            </div>
            <Progress value={x.size ? (x.sent / x.size) * 100 : x.status === "done" ? 100 : 0} label={`Upload progress ${x.key}`} />
            {x.error && <div class="error bk-small">{x.error}</div>}
          </li>
        ))}
      </ul>
    </section>
  );
}

/** Collects files from a drop, walking dropped directories. */
export async function filesFromDrop(dt: DataTransfer): Promise<{ file: File; path: string }[]> {
  const out: { file: File; path: string }[] = [];
  const entries = Array.from(dt.items || [])
    .map((i) => (i.kind === "file" && "webkitGetAsEntry" in i ? i.webkitGetAsEntry() : null))
    .filter(Boolean) as FileSystemEntry[];
  if (!entries.length) return Array.from(dt.files).map((f) => ({ file: f, path: f.name }));
  const walk = async (e: FileSystemEntry, base: string): Promise<void> => {
    if (e.isFile) {
      const f = await new Promise<File>((res, rej) => (e as FileSystemFileEntry).file(res, rej));
      out.push({ file: f, path: base + f.name });
    } else if (e.isDirectory) {
      const reader = (e as FileSystemDirectoryEntry).createReader();
      for (;;) {
        const batch = await new Promise<FileSystemEntry[]>((res, rej) => reader.readEntries(res, rej));
        if (!batch.length) break;
        for (const c of batch) await walk(c, `${base}${e.name}/`);
      }
    }
  };
  for (const e of entries) await walk(e, "");
  return out;
}
