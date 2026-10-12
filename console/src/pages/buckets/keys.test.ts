import { describe, expect, it } from "vitest";
import { baseName, chunk, completeXml, crumbs, deleteXml, folderKey, MiB, parentPrefix, parseListV2, parseVersions, planParts, previewKind, sortObjects, uploadKey, useMultipart } from "./keys";
import { parseXml } from "./xmlcfg";

describe("planParts", () => {
  it("splits into 16 MiB parts with a short tail", () => {
    const p = planParts(40 * MiB);
    expect(p.map((x) => x.number)).toEqual([1, 2, 3]);
    expect(p[2]).toEqual({ number: 3, start: 32 * MiB, end: 40 * MiB });
  });
  it("covers every byte exactly once", () => {
    const size = 100 * MiB + 17;
    const p = planParts(size);
    expect(p[0].start).toBe(0);
    for (let i = 1; i < p.length; i++) expect(p[i].start).toBe(p[i - 1].end);
    expect(p[p.length - 1].end).toBe(size);
  });
  it("grows the part size past 10000 parts", () => {
    const p = planParts(10001 * 16 * MiB);
    expect(p.length).toBeLessThanOrEqual(10000);
    expect(p[0].end).toBe(32 * MiB);
  });
  it("threshold", () => {
    expect(useMultipart(16 * MiB)).toBe(false);
    expect(useMultipart(16 * MiB + 1)).toBe(true);
  });
});

describe("key helpers", () => {
  it("crumbs and parents", () => {
    expect(crumbs("a/b/")).toEqual([
      { name: "a", prefix: "a/" },
      { name: "b", prefix: "a/b/" },
    ]);
    expect(crumbs("")).toEqual([]);
    expect(parentPrefix("a/b/")).toBe("a/");
    expect(parentPrefix("a/")).toBe("");
  });
  it("names", () => {
    expect(baseName("a/b/c.txt", "a/b/")).toBe("c.txt");
    expect(baseName("a/b/", "a/")).toBe("b/");
    expect(uploadKey("x/", { name: "f.txt" })).toBe("x/f.txt");
    expect(uploadKey("x/", { name: "f.txt", webkitRelativePath: "dir/f.txt" })).toBe("x/dir/f.txt");
  });
  it("folder keys", () => {
    expect(folderKey("a/", " new ")).toBe("a/new/");
    expect(folderKey("", "x/y/")).toBe("x/y/");
    expect(folderKey("", "..")).toBeNull();
    expect(folderKey("", "a//b")).toBeNull();
    expect(folderKey("", "  ")).toBeNull();
  });
  it("chunk", () => {
    expect(chunk([1, 2, 3, 4, 5], 2)).toEqual([[1, 2], [3, 4], [5]]);
  });
  it("preview kind", () => {
    expect(previewKind("a.png")).toBe("image");
    expect(previewKind("a.bin", "text/plain")).toBe("text");
    expect(previewKind("a.json")).toBe("text");
    expect(previewKind("a.pdf", "application/pdf")).toBe("none");
  });
});

describe("listings", () => {
  it("parses ListObjectsV2", () => {
    const d = parseXml(
      `<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><IsTruncated>true</IsTruncated><NextContinuationToken>tok</NextContinuationToken>
      <Contents><Key>a/x.txt</Key><Size>5</Size><LastModified>2026-01-01T00:00:00Z</LastModified><ETag>"e1"</ETag><StorageClass>STANDARD</StorageClass></Contents>
      <CommonPrefixes><Prefix>a/b/</Prefix></CommonPrefixes></ListBucketResult>`,
    );
    const l = parseListV2(d);
    expect(l.next).toBe("tok");
    expect(l.folders).toEqual(["a/b/"]);
    expect(l.objects[0]).toMatchObject({ key: "a/x.txt", size: 5, etag: "e1" });
  });
  it("parses versions and delete markers in order", () => {
    const d = parseXml(
      `<ListVersionsResult><IsTruncated>false</IsTruncated>
      <DeleteMarker><Key>k</Key><VersionId>v3</VersionId><IsLatest>true</IsLatest><LastModified>2026-01-03T00:00:00Z</LastModified></DeleteMarker>
      <Version><Key>k</Key><VersionId>v2</VersionId><IsLatest>false</IsLatest><Size>3</Size><LastModified>2026-01-02T00:00:00Z</LastModified></Version></ListVersionsResult>`,
    );
    const l = parseVersions(d);
    expect(l.nextKey).toBeNull();
    expect(l.versions.map((v) => [v.versionId, v.deleteMarker, v.isLatest])).toEqual([
      ["v3", true, true],
      ["v2", false, false],
    ]);
  });
  it("sorts", () => {
    const o = (key: string, size: number, lastModified: string) => ({ key, size, lastModified, etag: "", storageClass: "" });
    const xs = [o("b", 1, "2026-01-02"), o("a", 3, "2026-01-01"), o("c", 2, "2026-01-03")];
    expect(sortObjects(xs, "name", false).map((x) => x.key)).toEqual(["a", "b", "c"]);
    expect(sortObjects(xs, "size", true).map((x) => x.key)).toEqual(["a", "c", "b"]);
    expect(sortObjects(xs, "modified", false).map((x) => x.key)).toEqual(["a", "b", "c"]);
  });
});

describe("request bodies", () => {
  it("delete objects", () => {
    const x = deleteXml([{ key: "a&b" }, { key: "c", versionId: "v1" }]);
    expect(x).toContain("<Quiet>true</Quiet>");
    expect(x).toContain("<Object><Key>a&amp;b</Key></Object>");
    expect(x).toContain("<Object><Key>c</Key><VersionId>v1</VersionId></Object>");
  });
  it("complete multipart orders parts", () => {
    const x = completeXml([
      { number: 2, etag: '"b"' },
      { number: 1, etag: '"a"' },
    ]);
    expect(x.indexOf("<PartNumber>1</PartNumber>")).toBeLessThan(x.indexOf("<PartNumber>2</PartNumber>"));
  });
});
