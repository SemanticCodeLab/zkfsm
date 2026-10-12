import { describe, expect, it } from "vitest";
import { expiryOf, genAccessKey, genSecretKey, normalizeUsers, policyTemplates, splitList, validAccessKey, validatePolicy, validSecretKey } from "./iamapi";
import { settingsText } from "../Identity";
import { validTenantName } from "../Tenants";

describe("policy validation", () => {
  it("accepts every template", () => {
    for (const t of Object.values(policyTemplates)) expect(validatePolicy(t("b"))).toEqual([]);
  });
  it("reports structural problems", () => {
    expect(validatePolicy("{")[0]).toMatch(/Invalid JSON/);
    expect(validatePolicy("[]")).toEqual(["The policy must be a JSON object."]);
    expect(validatePolicy('{"Version":"2012-10-17"}')).toEqual(["Statement must be a non-empty array."]);
    const errs = validatePolicy('{"Version":"2012-10-17","Statement":[{"Effect":"Maybe"}]}');
    expect(errs).toContain('Statement 1: Effect must be "Allow" or "Deny".');
    expect(errs).toContain("Statement 1: Action is required.");
    expect(errs).toContain("Statement 1: Resource is required.");
  });
  it("scopes the bucket template", () => {
    expect(policyTemplates.bucket("photos")).toContain("arn:aws:s3:::photos/*");
  });
});

describe("credentials", () => {
  it("generates valid keys", () => {
    expect(genAccessKey()).toMatch(/^[A-Z0-9]{20}$/);
    const s = genSecretKey();
    expect(s).toHaveLength(40);
    expect(validSecretKey(s)).toBeNull();
    expect(genSecretKey()).not.toEqual(s);
  });
  it("validates", () => {
    expect(validAccessKey("ab")).not.toBeNull();
    expect(validAccessKey("a b c")).not.toBeNull();
    expect(validAccessKey("alice")).toBeNull();
    expect(validSecretKey("short")).not.toBeNull();
    expect(validSecretKey("x".repeat(41))).not.toBeNull();
  });
});

describe("normalization", () => {
  it("turns list-users into rows", () => {
    const rows = normalizeUsers({ bob: { status: "disabled" }, alice: { status: "enabled", policyName: "readonly, diag", memberOf: ["devs"] } });
    expect(rows.map((r) => r.name)).toEqual(["alice", "bob"]);
    expect(rows[0].policies).toEqual(["readonly", "diag"]);
    expect(rows[0].groups).toEqual(["devs"]);
    expect(rows[1].policies).toEqual([]);
    expect(normalizeUsers(null)).toEqual([]);
  });
  it("splits lists and reads the never-expires sentinel", () => {
    expect(splitList(" a,,b ")).toEqual(["a", "b"]);
    expect(expiryOf("1970-01-01T00:00:00Z")).toBeNull();
    expect(expiryOf("2030-01-01T00:00:00Z")?.getUTCFullYear()).toBe(2030);
  });
  it("formats identity settings and tenant names", () => {
    expect(settingsText({ client_id: "c", display_name: "Corp SSO", empty: "" })).toBe('client_id=c display_name="Corp SSO"');
    expect(validTenantName("team-a")).toBe(true);
    expect(validTenantName("Team A")).toBe(false);
  });
});
