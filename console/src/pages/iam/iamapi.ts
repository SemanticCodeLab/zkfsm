// IAM admin API wrappers and pure helpers shared by the identity pages.
import { admin, ApiError } from "../../lib/api";

export interface UserRow {
  name: string;
  status: "enabled" | "disabled" | string;
  policies: string[];
  groups: string[];
}

export interface GroupInfo {
  name: string;
  status: string;
  members: string[];
  policies: string[];
}

export interface ServiceAccount {
  accessKey: string;
  parentUser: string;
  accountStatus: "on" | "off" | string;
  impliedPolicy: boolean;
  name?: string | null;
  description?: string | null;
  expiration?: string | null;
}

export function splitList(s: string | null | undefined): string[] {
  return (s || "")
    .split(",")
    .map((x) => x.trim())
    .filter(Boolean);
}

/** list-users map -> sorted rows. */
export function normalizeUsers(raw: Record<string, { status?: string; policyName?: string | null; memberOf?: string[] | null }> | null): UserRow[] {
  return Object.entries(raw || {})
    .map(([name, u]) => ({ name, status: u.status || "enabled", policies: splitList(u.policyName), groups: u.memberOf || [] }))
    .sort((a, b) => a.name.localeCompare(b.name));
}

/** The epoch is the "never expires" sentinel. */
export function expiryOf(s: string | null | undefined): Date | null {
  if (!s) return null;
  const d = new Date(s);
  return isNaN(d.getTime()) || d.getTime() <= 0 ? null : d;
}

const KEY_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
const SECRET_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

export function randomString(len: number, alphabet: string): string {
  const out: string[] = [];
  const buf = new Uint32Array(len);
  crypto.getRandomValues(buf);
  for (const n of buf) out.push(alphabet[n % alphabet.length]);
  return out.join("");
}
export const genAccessKey = () => randomString(20, KEY_CHARS);
export const genSecretKey = () => randomString(40, SECRET_CHARS);

export function validAccessKey(k: string): string | null {
  if (k.length < 3) return "At least 3 characters.";
  if (k.length > 128) return "At most 128 characters.";
  if (/[\s,=]/.test(k)) return "No spaces, commas or '='.";
  return null;
}

export function validSecretKey(k: string): string | null {
  if (k.length < 8) return "At least 8 characters.";
  if (k.length > 40) return "At most 40 characters.";
  return null;
}

/** Basic structural checks of a policy document; returns problems found. */
export function validatePolicy(text: string): string[] {
  let doc: unknown;
  try {
    doc = JSON.parse(text);
  } catch (e) {
    return [`Invalid JSON: ${(e as Error).message}`];
  }
  const errs: string[] = [];
  if (!doc || typeof doc !== "object" || Array.isArray(doc)) return ["The policy must be a JSON object."];
  const d = doc as Record<string, unknown>;
  if (d.Version !== undefined && d.Version !== "2012-10-17" && d.Version !== "2008-10-17") errs.push('Version should be "2012-10-17".');
  const st = d.Statement;
  const list = Array.isArray(st) ? st : st && typeof st === "object" ? [st] : null;
  if (!list || list.length === 0) return [...errs, "Statement must be a non-empty array."];
  list.forEach((s, i) => {
    const n = `Statement ${i + 1}`;
    if (!s || typeof s !== "object") return errs.push(`${n}: must be an object.`);
    const x = s as Record<string, unknown>;
    if (x.Effect !== "Allow" && x.Effect !== "Deny") errs.push(`${n}: Effect must be "Allow" or "Deny".`);
    if (x.Action === undefined && x.NotAction === undefined) errs.push(`${n}: Action is required.`);
    if (x.Resource === undefined && x.NotResource === undefined) errs.push(`${n}: Resource is required.`);
    return 0;
  });
  return errs;
}

const doc = (statements: object[]) => JSON.stringify({ Version: "2012-10-17", Statement: statements }, null, 2);

export const policyTemplates: Record<string, (bucket?: string) => string> = {
  readonly: () => doc([{ Effect: "Allow", Action: ["s3:GetBucketLocation", "s3:GetObject", "s3:ListBucket", "s3:ListAllMyBuckets"], Resource: ["arn:aws:s3:::*"] }]),
  readwrite: () => doc([{ Effect: "Allow", Action: ["s3:*"], Resource: ["arn:aws:s3:::*"] }]),
  writeonly: () => doc([{ Effect: "Allow", Action: ["s3:PutObject"], Resource: ["arn:aws:s3:::*"] }]),
  diagnostics: () => doc([{ Effect: "Allow", Action: ["admin:ServerInfo", "admin:Prometheus", "admin:ServerTrace", "admin:ConsoleLog", "admin:Heal"], Resource: ["arn:aws:s3:::*"] }]),
  bucket: (bucket = "my-bucket") =>
    doc([
      { Effect: "Allow", Action: ["s3:ListBucket", "s3:GetBucketLocation"], Resource: [`arn:aws:s3:::${bucket}`] },
      { Effect: "Allow", Action: ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"], Resource: [`arn:aws:s3:::${bucket}/*`] },
    ]),
};

/** True when the server says the feature or route does not exist. */
export function unsupported(e: unknown): boolean {
  return e instanceof ApiError && (e.status === 501 || e.status === 404 && e.code === "404");
}

export const iam = {
  users: async () => normalizeUsers(await admin("/list-users")),
  userInfo: (name: string) => admin<{ policyName?: string; status: string; memberOf?: string[] }>("/user-info", { query: { accessKey: name } }),
  addUser: (name: string, secretKey: string, status = "enabled") =>
    admin("/add-user", { method: "PUT", query: { accessKey: name }, body: JSON.stringify({ secretKey, status }), encrypt: true }),
  removeUser: (name: string) => admin("/remove-user", { method: "DELETE", query: { accessKey: name } }),
  setUserStatus: (name: string, enabled: boolean) => admin("/set-user-status", { method: "PUT", query: { accessKey: name, status: enabled ? "enabled" : "disabled" } }),
  setPolicies: (who: string, isGroup: boolean, policies: string[]) =>
    admin("/set-user-or-group-policy", { method: "PUT", query: { policyName: policies.join(","), userOrGroup: who, isGroup: isGroup ? "true" : "false" } }),

  groups: async () => ((await admin<string[] | null>("/groups")) || []).sort(),
  group: async (name: string): Promise<GroupInfo> => {
    const g = await admin<{ name: string; status: string; members: string[] | null; policy: string }>("/group", { query: { group: name } });
    return { name: g.name, status: g.status, members: g.members || [], policies: splitList(g.policy) };
  },
  updateMembers: (group: string, members: string[], remove = false) =>
    admin("/update-group-members", { method: "PUT", body: JSON.stringify({ group, members, isRemove: remove }) }),
  setGroupStatus: (group: string, enabled: boolean) => admin("/set-group-status", { method: "PUT", query: { group, status: enabled ? "enabled" : "disabled" } }),

  policies: async () => (await admin<Record<string, unknown>>("/list-canned-policies")) || {},
  policy: async (name: string) => JSON.stringify(await admin("/info-canned-policy", { query: { name } }), null, 2),
  putPolicy: (name: string, text: string) => admin("/add-canned-policy", { method: "PUT", query: { name }, body: text }),
  removePolicy: (name: string) => admin("/remove-canned-policy", { method: "DELETE", query: { name } }),

  serviceAccounts: async (user?: string) => (await admin<{ accounts: ServiceAccount[] | null }>("/list-service-accounts", { query: { user } })).accounts || [],
  addServiceAccount: (req: { targetUser?: string; accessKey?: string; secretKey?: string; name?: string; description?: string; expiration?: string; policy?: unknown }) =>
    admin<{ credentials: { accessKey: string; secretKey: string; expiration?: string | null } }>("/add-service-account", { method: "PUT", body: JSON.stringify(req), encrypt: true }),
  updateServiceAccount: (key: string, req: { newStatus?: string; newPolicy?: unknown; newExpiration?: string; newName?: string; newDescription?: string; newSecretKey?: string }) =>
    admin("/update-service-account", { method: "POST", query: { accessKey: key }, body: JSON.stringify(req), encrypt: true }),
  deleteServiceAccount: (key: string) => admin("/delete-service-account", { method: "DELETE", query: { accessKey: key } }),
  serviceAccountInfo: (key: string) => admin<ServiceAccount & { policy: string }>("/info-service-account", { query: { accessKey: key } }),
};
