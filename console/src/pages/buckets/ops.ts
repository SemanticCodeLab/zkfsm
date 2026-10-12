// Bucket-level operations shared by the bucket list and detail pages.
import { admin, s3, s3Xml } from "../../lib/api";
import { chunk, deleteXml, parseDeleteErrors, parseVersions } from "./keys";
import { all, children, text, versioningXml } from "./xmlcfg";

export interface BucketRow {
  name: string;
  created: string;
  size?: number;
  objects?: number;
  read?: boolean;
  write?: boolean;
}

export async function listBuckets(): Promise<BucketRow[]> {
  const d = await s3Xml("/");
  const rows: BucketRow[] = all(d, "Bucket").map((b) => ({ name: text(b, "Name"), created: text(b, "CreationDate") }));
  try {
    const info = await admin<{ Buckets?: { name: string; size?: number; objects?: number; access?: { read: boolean; write: boolean } }[] }>("/accountinfo");
    const by = new Map((info?.Buckets || []).map((b) => [b.name, b]));
    for (const r of rows) {
      const b = by.get(r.name);
      if (!b) continue;
      r.size = b.size;
      r.objects = b.objects;
      r.read = b.access?.read;
      r.write = b.access?.write;
    }
  } catch {
    /* account info is optional */
  }
  return rows;
}

export async function createBucket(name: string, opts: { versioning: boolean; lock: boolean; quota: number }) {
  const b = `/${encodeURIComponent(name)}`;
  await s3(b, { method: "PUT", headers: opts.lock ? { "x-amz-bucket-object-lock-enabled": "true" } : {} });
  if (opts.versioning || opts.lock) await s3(b, { method: "PUT", query: { versioning: true }, body: versioningXml("Enabled") });
  if (opts.quota > 0) await setQuota(name, opts.quota);
}

export function setQuota(bucket: string, bytes: number) {
  return admin("/set-bucket-quota", {
    method: "PUT",
    query: { bucket },
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ quota: bytes, size: bytes, quotatype: "hard" }),
  });
}

/** Deletes every object version, delete marker and pending upload, then the bucket. */
export async function forceDeleteBucket(bucket: string, onProgress?: (deleted: number) => void) {
  const b = `/${encodeURIComponent(bucket)}`;
  let deleted = 0;
  let keyMarker: string | null = null;
  let versionMarker: string | null = null;
  for (;;) {
    const d = await s3Xml(b, { query: { versions: true, "max-keys": 1000, "key-marker": keyMarker, "version-id-marker": versionMarker } });
    const l = parseVersions(d);
    for (const group of chunk(l.versions, 1000)) {
      if (!group.length) continue;
      const res = await s3Xml(b, { method: "POST", query: { delete: true }, headers: { "content-type": "application/xml" }, body: deleteXml(group.map((v) => ({ key: v.key, versionId: v.versionId }))) });
      const errs = parseDeleteErrors(res);
      if (errs.length) throw new Error(`Could not delete ${errs[0].key}: ${errs[0].message || errs[0].code}`);
      deleted += group.length;
      onProgress?.(deleted);
    }
    if (!l.nextKey) break;
    keyMarker = l.nextKey;
    versionMarker = l.nextVersion;
  }
  try {
    const up = await s3Xml(b, { query: { uploads: true } });
    for (const u of children(up, "Upload")) {
      await s3(`${b}/${text(u, "Key").split("/").map(encodeURIComponent).join("/")}`, { method: "DELETE", query: { uploadId: text(u, "UploadId") } }).catch(() => {});
    }
  } catch {
    /* listing uploads is best effort */
  }
  await s3(b, { method: "DELETE" });
}
