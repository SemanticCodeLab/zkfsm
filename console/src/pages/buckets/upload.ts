// Browser uploads: single PUT via XHR (for progress) or multipart for large files.
import { CSRF_HEADER, encodeKey, qs, s3, s3Xml } from "../../lib/api";
import { completeXml, parseUploadId, planParts, useMultipart } from "./keys";

export interface UploadHandle {
  promise: Promise<void>;
  cancel: () => void;
}

class Cancelled extends Error {
  constructor() {
    super("Upload cancelled");
  }
}
export const isCancelled = (e: unknown) => e instanceof Cancelled;

function objectPath(bucket: string, key: string) {
  return `/${encodeURIComponent(bucket)}/${encodeKey(key)}`;
}

function xhrPut(url: string, body: Blob, contentType: string, onProgress: (loaded: number) => void, track: (x: XMLHttpRequest) => void): Promise<XMLHttpRequest> {
  return new Promise((resolve, reject) => {
    const x = new XMLHttpRequest();
    track(x);
    x.open("PUT", url);
    x.setRequestHeader(CSRF_HEADER, "1");
    if (contentType) x.setRequestHeader("content-type", contentType);
    x.upload.onprogress = (e) => onProgress(e.loaded);
    x.onload = () => {
      if (x.status >= 200 && x.status < 300) return resolve(x);
      const m = /<Message>([^<]*)<\/Message>/.exec(x.responseText || "");
      reject(new Error(m ? m[1] : `Upload failed (${x.status})`));
    };
    x.onerror = () => reject(new Error("Network error during upload"));
    x.onabort = () => reject(new Cancelled());
    x.send(body);
  });
}

/** Starts uploading `file` to bucket/key; `onProgress` gets bytes sent so far. */
export function uploadFile(bucket: string, key: string, file: Blob, onProgress: (sent: number) => void, concurrency = 3): UploadHandle {
  const live = new Set<XMLHttpRequest>();
  let cancelled = false;
  const track = (x: XMLHttpRequest) => {
    live.add(x);
    x.addEventListener("loadend", () => live.delete(x));
  };
  const cancel = () => {
    cancelled = true;
    live.forEach((x) => x.abort());
  };
  const type = file.type || "application/octet-stream";
  const base = `/api/v1/s3${objectPath(bucket, key)}`;

  const single = async () => {
    await xhrPut(base, file, type, onProgress, track);
    onProgress(file.size);
  };

  const multi = async () => {
    const init = await s3Xml(objectPath(bucket, key), { method: "POST", query: { uploads: true }, headers: { "content-type": type } });
    const uploadId = parseUploadId(init);
    const parts = planParts(file.size);
    const sent = new Map<number, number>();
    const report = () => onProgress([...sent.values()].reduce((a, b) => a + b, 0));
    const done: { number: number; etag: string }[] = [];
    let next = 0;
    const worker = async () => {
      while (next < parts.length) {
        if (cancelled) throw new Cancelled();
        const p = parts[next++];
        const url = base + qs({ partNumber: p.number, uploadId });
        const x = await xhrPut(url, file.slice(p.start, p.end), "", (n) => {
          sent.set(p.number, n);
          report();
        }, track);
        sent.set(p.number, p.end - p.start);
        report();
        done.push({ number: p.number, etag: x.getResponseHeader("etag") || "" });
      }
    };
    try {
      await Promise.all(Array.from({ length: Math.min(concurrency, parts.length) }, worker));
      if (cancelled) throw new Cancelled();
      await s3(objectPath(bucket, key), { method: "POST", query: { uploadId }, headers: { "content-type": "application/xml" }, body: completeXml(done) });
    } catch (e) {
      cancel();
      await s3(objectPath(bucket, key), { method: "DELETE", query: { uploadId } }).catch(() => {});
      throw e;
    }
  };

  return { promise: useMultipart(file.size) ? multi() : single(), cancel };
}
