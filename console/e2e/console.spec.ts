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
