// Hash router: #/buckets/foo/browse?prefix=a/ -> { path: "/buckets/foo/browse", params }.
import { useEffect, useState } from "preact/hooks";

export interface Route {
  path: string;
  segments: string[];
  params: URLSearchParams;
}

export function parse(hash: string): Route {
  const h = hash.replace(/^#/, "") || "/";
  const [p, q = ""] = h.split("?", 2);
  const path = p.startsWith("/") ? p : `/${p}`;
  return { path, segments: path.split("/").filter(Boolean).map(decodeURIComponent), params: new URLSearchParams(q) };
}

export function href(path: string, params?: Record<string, string | undefined>): string {
  const q = new URLSearchParams();
  for (const [k, v] of Object.entries(params || {})) if (v !== undefined && v !== "") q.set(k, v);
  const s = q.toString();
  return `#${path}${s ? `?${s}` : ""}`;
}

export function navigate(path: string, params?: Record<string, string | undefined>) {
  location.hash = href(path, params);
}

export function useRoute(): Route {
  const [r, setR] = useState(() => parse(location.hash));
  useEffect(() => {
    const f = () => setR(parse(location.hash));
    addEventListener("hashchange", f);
    return () => removeEventListener("hashchange", f);
  }, []);
  return r;
}
