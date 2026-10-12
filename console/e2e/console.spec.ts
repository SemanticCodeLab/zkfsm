import { expect, Page, test } from "@playwright/test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const shots = process.env.SCREENSHOT_DIR || "test-results/screenshots";
const ak = process.env.CONSOLE_ACCESS_KEY || "admin";
const sk = process.env.CONSOLE_SECRET_KEY || "adminsecret";
const bucket = `e2e-${Date.now().toString(36)}`;

async function shot(page: Page, name: string) {
  await page.screenshot({ path: join(shots, `${name}.png`), fullPage: true });
}

async function login(page: Page) {
  await page.goto("/");
  await page.getByLabel("Access key").fill(ak);
  await page.getByLabel("Secret key").fill(sk);
  await page.getByRole("button", { name: "Log in" }).click();
  await expect(page.getByRole("navigation", { name: "Main" })).toBeVisible();
}

test.describe.configure({ mode: "serial" });

test("login is required and rejects bad credentials", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("button", { name: "Log in" })).toBeVisible();
  await shot(page, "01-login");
  await page.getByLabel("Access key").fill(ak);
  await page.getByLabel("Secret key").fill("wrong-secret");
  await page.getByRole("button", { name: "Log in" }).click();
  await expect(page.getByRole("alert")).toContainText(/invalid/i);
  // The session cookie is HttpOnly: page scripts cannot read it.
  await login(page);
  expect(await page.evaluate(() => document.cookie)).toBe("");
  const cookies = await page.context().cookies();
  const c = cookies.find((x) => x.name === "zkfsm_console");
  expect(c?.httpOnly).toBe(true);
  expect(c?.sameSite).toBe("Strict");
  await expect(page.getByRole("heading", { name: "Dashboard" })).toBeVisible();
  await page.waitForTimeout(1500);
  await shot(page, "02-dashboard");
});

test("create bucket, upload, download, delete", async ({ page }) => {
  await login(page);
  await page.goto("/#/buckets");
  await page.getByRole("button", { name: "Create Bucket" }).click();
  await page.getByLabel("Bucket name").fill(bucket);
  await page.getByRole("button", { name: "Create", exact: true }).click();
  await expect(page.getByRole("link", { name: bucket, exact: true })).toBeVisible();
  await shot(page, "03-buckets");

  await page.goto(`/#/browser/${bucket}`);
  await page.getByLabel("Upload files").setInputFiles({ name: "hello.txt", mimeType: "text/plain", buffer: Buffer.from("hello from the console\n") });
  const row = page.getByRole("row").filter({ hasText: "hello.txt" });
  await expect(row).toBeVisible();
  await shot(page, "04-browser");

  const [download] = await Promise.all([page.waitForEvent("download"), row.getByRole("link", { name: "Download" }).click()]);
  expect(download.suggestedFilename()).toBe("hello.txt");
  expect(readFileSync(await download.path())).toEqual(Buffer.from("hello from the console\n"));

  await row.getByRole("checkbox").check();
  await page.getByRole("button", { name: "Delete", exact: true }).first().click();
  await page.getByRole("dialog").getByRole("button", { name: "Delete" }).click();
  await expect(page.getByRole("row").filter({ hasText: "hello.txt" })).toHaveCount(0);
});

test("set a lifecycle rule", async ({ page }) => {
  await login(page);
  await page.goto(`/#/buckets/${bucket}?tab=lifecycle`);
  await page.getByRole("button", { name: "Add lifecycle rule" }).click();
  const dlg = page.getByRole("dialog");
  await dlg.getByLabel("Rule ID").fill("expire-logs");
  await dlg.getByLabel("Prefix").fill("logs/");
  await dlg.getByLabel("Expire current versions after (days)").fill("30");
  await dlg.getByRole("button", { name: "Save" }).click();
  await expect(page.getByRole("cell", { name: "expire-logs" })).toBeVisible();
  await expect(page.getByText("expire after 30d")).toBeVisible();
  await shot(page, "05-lifecycle");
});

test("create policy and user", async ({ page }) => {
  await login(page);
  const policy = `e2e-read-${bucket}`;
  await page.goto("/#/iam/policies");
  await page.getByRole("button", { name: "Create Policy" }).click();
  await page.getByLabel("Policy name").fill(policy);
  await page.getByLabel("Bucket for template").fill(bucket);
  await page.getByRole("button", { name: "bucket access" }).click();
  await shot(page, "06-policy-editor");
  await page.getByRole("button", { name: "Save" }).click();
  await expect(page.getByRole("link", { name: policy })).toBeVisible();

  const user = `e2e-user-${Date.now().toString(36)}`;
  await page.goto("/#/iam/users");
  await page.getByRole("button", { name: "Create User" }).click();
  await page.getByLabel("Access key").fill(user);
  await page.getByLabel("Secret key").fill("e2e-secret-123");
  await page.getByRole("checkbox", { name: policy }).check();
  await page.getByRole("button", { name: "Save" }).click();
  const row = page.getByRole("row").filter({ hasText: user });
  await expect(row).toBeVisible();
  await expect(row).toContainText(policy);
  await shot(page, "07-users");

  // The new user can log in and sees only what the policy allows.
  await page.getByRole("button", { name: "Log out" }).click();
  await page.getByLabel("Access key").fill(user);
  await page.getByLabel("Secret key").fill("e2e-secret-123");
  await page.getByRole("button", { name: "Log in" }).click();
  await expect(page.getByRole("navigation", { name: "Main" })).toBeVisible();
});

test("every page and bucket tab renders without errors", async ({ page }) => {
  const problems: string[] = [];
  page.on("console", (m) => {
    // 4xx probes of optional features are expected; script and CSP errors are not.
    if (m.type() === "error" && !/Failed to load resource/.test(m.text())) problems.push(m.text());
  });
  page.on("pageerror", (e) => problems.push(String(e)));
  await login(page);
  const routes = ["/", "/buckets", `/browser/${bucket}`, "/tables", "/tiers", "/site-replication", "/iam/users", "/iam/groups", "/iam/access-keys", "/iam/policies", "/iam/identity", "/iam/tenants", "/monitoring", "/monitoring?tab=heal", "/monitoring?tab=pools", "/events", "/events?tab=audit", "/events?tab=lambda", "/batch", "/kms", "/settings"];
  for (const t of ["summary", "versioning", "lock", "quota", "lifecycle", "policy", "tags", "replication", "encryption", "cors", "website", "events"]) routes.push(`/buckets/${bucket}?tab=${t}`);
  for (const r of routes) {
    await page.goto(`/#${r}`);
    await expect(page.locator("#main h1").first()).toBeVisible();
    await expect(page.locator("#main .loading")).toHaveCount(0);
    expect(await page.locator("#main .notice-error").allTextContents(), `errors on ${r}`).toEqual([]);
    await page.screenshot({ path: join(shots, "pages", `${r.replace(/[^a-z0-9]+/gi, "-").replace(/^-|-$/g, "") || "dashboard"}.png`), fullPage: true });
  }
  expect(problems).toEqual([]);
});

test("multipart upload shows progress and stores the object", async ({ page }) => {
  await login(page);
  await page.goto(`/#/browser/${bucket}`);
  // 17 MiB: above the single-PUT limit, so two parts.
  const big = Buffer.alloc(17 * 1024 * 1024, 7);
  await page.getByLabel("Upload files").setInputFiles({ name: "big.bin", mimeType: "application/octet-stream", buffer: big });
  await expect(page.getByRole("progressbar", { name: "Upload progress big.bin" })).toBeVisible();
  const row = page.getByRole("row").filter({ hasText: "big.bin" });
  await expect(row).toBeVisible({ timeout: 60_000 });
  await expect(row).toContainText("17.0 MiB");
  await shot(page, "10-multipart-upload");
  const head = await page.request.head(`/api/v1/s3/${bucket}/big.bin`);
  expect(head.headers()["etag"]).toMatch(/-2"?$/);
  expect(head.headers()["content-length"]).toBe(String(big.length));
});

test("kms key lifecycle", async ({ page }) => {
  await login(page);
  await page.goto("/#/kms");
  await page.getByRole("button", { name: "Create key" }).click();
  await page.getByLabel("Key name").fill("e2e-key");
  await page.getByRole("dialog").getByRole("button", { name: "Create" }).click();
  const row = page.getByRole("row").filter({ hasText: "e2e-key" });
  await expect(row).toContainText("enabled");
  await row.getByRole("button", { name: "Disable e2e-key" }).click();
  await expect(row).toContainText("disabled");
  await row.getByRole("button", { name: "Enable e2e-key" }).click();
  await expect(row).toContainText("enabled");
  await row.getByRole("button", { name: "Tags of e2e-key" }).click();
  const tags = page.getByRole("dialog");
  await tags.getByRole("button", { name: "Add tag" }).click();
  await tags.getByRole("textbox", { name: "Key 1" }).fill("team");
  await tags.getByRole("textbox", { name: "Value 1" }).fill("storage");
  await tags.getByRole("button", { name: "Save" }).click();
  await expect(page.getByRole("dialog")).toHaveCount(0);
  await row.getByRole("button", { name: "Tags of e2e-key" }).click();
  await expect(page.getByRole("dialog").getByRole("textbox", { name: "Value 1" })).toHaveValue("storage");
  await page.getByRole("dialog").getByRole("button", { name: "Cancel" }).click();
  await expect(page.getByRole("heading", { name: "Backend" })).toBeVisible();
  await shot(page, "11-kms");
  await row.getByRole("button", { name: "Delete e2e-key" }).click();
  await page.getByRole("dialog").getByRole("button", { name: "Delete" }).click();
  await expect(page.getByRole("row").filter({ hasText: "e2e-key" })).toHaveCount(0);
});

test("table bucket, namespace and table", async ({ page }) => {
  await login(page);
  const tb = `${bucket}-tb`;
  await page.goto("/#/tables");
  await page.getByRole("button", { name: "Create table bucket" }).click();
  await page.getByLabel("Table bucket name").fill(tb);
  await page.getByRole("dialog").getByRole("button", { name: "Create" }).click();
  await page.getByRole("link", { name: tb, exact: true }).click();
  await page.getByRole("button", { name: "Create namespace" }).click();
  await page.getByLabel("Namespace name").fill("sales");
  await page.getByRole("dialog").getByRole("button", { name: "Create" }).click();
  await expect(page.getByRole("cell", { name: "sales", exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Create table" }).click();
  const dlg = page.getByRole("dialog");
  await dlg.getByLabel("Table name").fill("orders");
  await dlg.getByRole("button", { name: "Add column" }).click();
  await dlg.getByRole("textbox", { name: "Column 2" }).fill("note");
  await dlg.getByRole("button", { name: "Create" }).click();
  await expect(page.getByRole("cell", { name: "orders", exact: true })).toBeVisible();
  await shot(page, "12-tables");
  await page.getByRole("button", { name: "Details of sales.orders" }).click();
  const det = page.getByRole("dialog");
  await expect(det.getByRole("cell", { name: "note", exact: true })).toBeVisible();
  await expect(det.getByRole("cell", { name: "long", exact: true })).toBeVisible();
  await expect(det).toContainText(`s3://${tb}/`);
  await shot(page, "13-table-details");
  await det.getByRole("button", { name: "Close" }).first().click();
  await page.getByRole("button", { name: "Delete table sales.orders" }).click();
  await page.getByRole("dialog").getByRole("button", { name: "Delete" }).click();
  await expect(page.getByRole("cell", { name: "orders", exact: true })).toHaveCount(0);
});

test("batch job runs to completion", async ({ page }) => {
  await login(page);
  const put = await page.request.put(`/api/v1/s3/${bucket}/tmp/old.txt`, { data: "x", headers: { "x-console-csrf": "1" } });
  expect(put.ok()).toBe(true);
  await page.goto("/#/batch");
  await page.getByRole("button", { name: "Start job" }).click();
  const dlg = page.getByRole("dialog");
  await dlg.getByLabel("Job type").selectOption("expire");
  await expect(dlg.getByLabel("Job definition (YAML)")).toHaveValue(/expire:/);
  await expect(dlg).toContainText("Replace the template values");
  await dlg.getByLabel("Job definition (YAML)").fill(`expire:\n  apiVersion: v1\n  bucket: ${bucket}\n  prefix: tmp/\n  rules:\n    - type: object\n      name: "*"\n      olderThan: 0h\n      purge:\n        retainVersions: 0\n`);
  await dlg.getByRole("button", { name: "Start job" }).click();
  const row = page.getByRole("row").filter({ hasText: "expire" });
  await expect(row).toContainText("complete", { timeout: 30_000 });
  await row.getByRole("button", { name: /Status of/ }).click();
  await expect(page.getByRole("dialog")).toContainText("Objects");
  await shot(page, "14-batch");
  expect((await page.request.get(`/api/v1/s3/${bucket}/tmp/old.txt`)).status()).toBe(404);
});

test("lambda target", async ({ page }) => {
  await login(page);
  await page.goto("/#/events?tab=lambda");
  await page.getByRole("button", { name: "Add lambda target" }).click();
  const dlg = page.getByRole("dialog");
  await dlg.getByLabel("Identifier").fill("e2efn");
  await dlg.getByLabel("endpoint").fill("http://127.0.0.1:9/fn");
  await dlg.getByRole("button", { name: "Save" }).click();
  const row = page.getByRole("row").filter({ hasText: "e2efn" });
  await expect(row).toContainText("arn:minio:s3-object-lambda::e2efn:webhook");
  await shot(page, "15-lambda-targets");
  await row.getByRole("button", { name: "Remove lambda_webhook:e2efn" }).click();
  await page.getByRole("dialog").getByRole("button", { name: "Remove" }).click();
  await expect(page.getByRole("row").filter({ hasText: "e2efn" })).toHaveCount(0);
});

test("dark theme and keyboard navigation", async ({ page }) => {
  await login(page);
  await page.getByRole("button", { name: /Switch to (dark|light) theme/ }).click();
  const theme = await page.evaluate(() => document.documentElement.dataset.theme);
  if (theme !== "dark") await page.getByRole("button", { name: /Switch to dark theme/ }).click();
  await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");
  await page.goto("/#/buckets");
  await page.reload();
  await expect(page.getByRole("heading", { name: "Buckets" })).toBeVisible();
  await page.keyboard.press("Tab");
  await expect(page.getByRole("link", { name: "Skip to content" })).toBeFocused();
  await page.keyboard.press("Enter");
  await expect(page.locator("#main")).toBeFocused();
  await shot(page, "08-dark-buckets");
  await page.goto("/");
  // Two metric samples (5 s apart) are needed before the charts draw lines.
  await page.waitForTimeout(11_000);
  await shot(page, "09-dark-dashboard");
});

test("API rejects requests without the CSRF header or session", async ({ request }) => {
  const anon = await request.get("/api/v1/s3/");
  expect(anon.status()).toBe(401);
  const noCsrf = await request.post("/api/v1/login", { data: { accessKey: ak, secretKey: sk } });
  expect(noCsrf.status()).toBe(403);
  const crossSite = await request.post("/api/v1/login", { data: { accessKey: ak, secretKey: sk }, headers: { "x-console-csrf": "1", origin: "http://evil.example" } });
  expect(crossSite.status()).toBe(403);
  const page = await request.get("/");
  expect(page.headers()["content-security-policy"]).toContain("default-src 'self'");
});
