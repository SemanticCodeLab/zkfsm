// Pure helpers for object keys, listings, deletes and multipart planning.
import { doc } from "../../lib/xml";
import { all, children, root, text } from "./xmlcfg";

export const MiB = 1024 * 1024;
export const PART_SIZE = 16 * MiB;
export const SINGLE_PUT_MAX = 16 * MiB;
const MAX_PARTS = 10000;

export interface Part {
  number: number;
  start: number;
  end: number; // exclusive
}

/** Splits `size` bytes into parts of `partSize`, growing the part size to stay within 10000 parts. */
export function planParts(size: number, partSize = PART_SIZE): Part[] {
  let ps = partSize;
  while (Math.ceil(size / ps) > MAX_PARTS) ps *= 2;
  const parts: Part[] = [];
  if (size === 0) return [{ number: 1, start: 0, end: 0 }];
  for (let start = 0, n = 1; start < size; start += ps, n++) parts.push({ number: n, start, end: Math.min(size, start + ps) });
  return parts;
}

export function useMultipart(size: number): boolean {
  return size > SINGLE_PUT_MAX;
}

/** "a/b/" -> [{name:"a",prefix:"a/"},{name:"b",prefix:"a/b/"}]. */
export function crumbs(prefix: string): { name: string; prefix: string }[] {
  const out: { name: string; prefix: string }[] = [];
  let acc = "";
  for (const part of prefix.split("/").filter(Boolean)) {
    acc += `${part}/`;
    out.push({ name: part, prefix: acc });
  }
  return out;
}

export function parentPrefix(prefix: string): string {
  const p = prefix.replace(/\/$/, "");
  const i = p.lastIndexOf("/");
  return i < 0 ? "" : p.slice(0, i + 1);
}

/** Display name of `key` relative to `prefix`. */
export function baseName(key: string, prefix = ""): string {
  const rest = key.startsWith(prefix) ? key.slice(prefix.length) : key;
  return rest || key;
}

/** Normalizes a user-typed folder name into a prefix under `prefix`. */
export function folderKey(prefix: string, name: string): string | null {
  const n = name.trim().replace(/^\/+|\/+$/g, "");
  if (!n || n.split("/").some((s) => s === "" || s === "." || s === "..")) return null;
  return `${prefix}${n}/`;
}

/** Upload key: prefix + relative path (for folder uploads) or file name. */
export function uploadKey(prefix: string, file: { name: string; webkitRelativePath?: string }): string {
  const rel = (file.webkitRelativePath || file.name).replace(/^\/+/, "");
  return prefix + rel;
}

export interface ObjEntry {
  key: string;
  size: number;
  lastModified: string;
  etag: string;
  storageClass: string;
  versionId?: string;
  isLatest?: boolean;
  deleteMarker?: boolean;
}

export interface Listing {
  folders: string[];
  objects: ObjEntry[];
  next: string | null;
}

export function parseListV2(d: Document): Listing {
  return {
    folders: all(d, "CommonPrefixes").map((c) => text(c, "Prefix")),
    objects: children(d, "Contents").map((c) => ({
      key: text(c, "Key"),
      size: Number(text(c, "Size")) || 0,
      lastModified: text(c, "LastModified"),
      etag: text(c, "ETag").replace(/"/g, ""),
      storageClass: text(c, "StorageClass"),
    })),
    next: text(d, "IsTruncated") === "true" ? text(d, "NextContinuationToken") || null : null,
  };
}

export interface VersionListing {
  folders: string[];
  versions: ObjEntry[];
  nextKey: string | null;
  nextVersion: string | null;
}

export function parseVersions(d: Document): VersionListing {
  const r = root(d);
  const versions: ObjEntry[] = [];
  for (const c of r ? Array.from(r.children) : []) {
    if (c.localName !== "Version" && c.localName !== "DeleteMarker") continue;
    versions.push({
      key: text(c, "Key"),
      size: Number(text(c, "Size")) || 0,
      lastModified: text(c, "LastModified"),
      etag: text(c, "ETag").replace(/"/g, ""),
      storageClass: text(c, "StorageClass"),
      versionId: text(c, "VersionId"),
      isLatest: text(c, "IsLatest") === "true",
      deleteMarker: c.localName === "DeleteMarker",
    });
  }
  const trunc = text(d, "IsTruncated") === "true";
  return {
    folders: all(d, "CommonPrefixes").map((c) => text(c, "Prefix")),
    versions,
    nextKey: trunc ? text(d, "NextKeyMarker") || null : null,
    nextVersion: trunc ? text(d, "NextVersionIdMarker") || null : null,
  };
}

export function deleteXml(objs: { key: string; versionId?: string }[], quiet = true): string {
  return doc("Delete", { Quiet: quiet, Object: objs.map((o) => ({ Key: o.key, VersionId: o.versionId || undefined })) });
}

/** Errors from a DeleteObjects response. */
export function parseDeleteErrors(d: Document): { key: string; code: string; message: string }[] {
  return children(d, "Error").map((e) => ({ key: text(e, "Key"), code: text(e, "Code"), message: text(e, "Message") }));
}

export function chunk<T>(xs: T[], n: number): T[][] {
  const out: T[][] = [];
  for (let i = 0; i < xs.length; i += n) out.push(xs.slice(i, i + n));
  return out;
}

export type SortKey = "name" | "size" | "modified";

export function sortObjects(xs: ObjEntry[], by: SortKey, desc: boolean): ObjEntry[] {
  const f = desc ? -1 : 1;
  return [...xs].sort((a, b) => {
    let c = 0;
    if (by === "size") c = a.size - b.size;
    else if (by === "modified") c = a.lastModified.localeCompare(b.lastModified);
    if (c === 0) c = a.key.localeCompare(b.key);
    if (c === 0 && a.lastModified !== b.lastModified) c = b.lastModified.localeCompare(a.lastModified);
    return c * f;
  });
}

const TEXT_EXT = /\.(txt|md|json|ya?ml|xml|csv|tsv|log|ini|toml|conf|cfg|sh|py|js|ts|tsx|jsx|go|rs|zig|c|h|cpp|java|html?|css|sql|env)$/i;
const IMG_EXT = /\.(png|jpe?g|gif|webp|svg|bmp|ico|avif)$/i;

export function previewKind(key: string, contentType = ""): "text" | "image" | "none" {
  if (contentType.startsWith("image/") || IMG_EXT.test(key)) return "image";
  if (contentType.startsWith("text/") || /json|xml|yaml|javascript/.test(contentType) || TEXT_EXT.test(key)) return "text";
  return "none";
}

/** Upload id from InitiateMultipartUploadResult. */
export function parseUploadId(d: Document): string {
  return text(d, "UploadId");
}

export function completeXml(parts: { number: number; etag: string }[]): string {
  return doc("CompleteMultipartUpload", {
    Part: [...parts].sort((a, b) => a.number - b.number).map((p) => ({ PartNumber: p.number, ETag: p.etag })),
  });
}
