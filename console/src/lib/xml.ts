// Small helpers for S3 XML bodies.

export function esc(s: string): string {
  return s.replace(/[<>&'"]/g, (c) => ({ "<": "&lt;", ">": "&gt;", "&": "&amp;", "'": "&apos;", '"': "&quot;" })[c]!);
}

function rootOf(el: Element | Document): Element | null {
  return el.nodeType === 9 ? (el as Document).documentElement : (el as Element);
}

/** Direct children of `el` named `name` (namespace-agnostic). */
export function children(el: Element | Document, name: string): Element[] {
  const root = rootOf(el);
  if (!root) return [];
  return Array.from(root.children).filter((c) => c.localName === name);
}

/** All descendants named `name`. */
export function all(el: Element | Document, name: string): Element[] {
  return Array.from(el.getElementsByTagName("*")).filter((e) => e.localName === name);
}

export function text(el: Element | Document | null | undefined, name: string): string {
  if (!el) return "";
  const root = rootOf(el);
  const c = root ? Array.from(root.children).find((x) => x.localName === name) : undefined;
  return c?.textContent ?? "";
}

/** Builds `<Name>..children..</Name>` from a plain object; arrays repeat the element. */
export type XmlValue = string | number | boolean | null | undefined | XmlObj | XmlValue[];
export interface XmlObj {
  [k: string]: XmlValue;
}

export function build(name: string, v: XmlValue, xmlns?: string): string {
  if (v === null || v === undefined) return "";
  if (Array.isArray(v)) return v.map((x) => build(name, x)).join("");
  const attr = xmlns ? ` xmlns="${xmlns}"` : "";
  if (typeof v === "object") {
    const inner = Object.entries(v)
      .map(([k, x]) => build(k, x))
      .join("");
    return `<${name}${attr}>${inner}</${name}>`;
  }
  return `<${name}${attr}>${esc(String(v))}</${name}>`;
}

export const S3NS = "http://s3.amazonaws.com/doc/2006-03-01/";

export function doc(name: string, v: XmlObj): string {
  return `<?xml version="1.0" encoding="UTF-8"?>${build(name, v, S3NS)}`;
}

/** Tag set <-> record. */
export function parseTags(d: Document): Record<string, string> {
  const out: Record<string, string> = {};
  for (const t of all(d, "Tag")) out[text(t, "Key")] = text(t, "Value");
  return out;
}

export function tagsXml(tags: Record<string, string>): string {
  return doc("Tagging", { TagSet: { Tag: Object.entries(tags).map(([Key, Value]) => ({ Key, Value })) } });
}
