import { expect, Page, test } from "@playwright/test";
import { join } from "node:path";

// Live trace/log run against CONSOLE_URL (single node); pools against POOLS_CONSOLE_URL,
// a 2-pool 4-node cluster started by tests/console.sh.
const shots = process.env.SCREENSHOT_DIR || "test-results/screenshots";
const ak = process.env.CONSOLE_ACCESS_KEY || "admin";
const sk = process.env.CONSOLE_SECRET_KEY || "adminsecret";
const poolsUrl = process.env.POOLS_CONSOLE_URL;

async function shot(page: Page, name: string) {
  await page.screenshot({ path: join(shots, `${name}.png`), fullPage: true });
}

async function login(page: Page, base = "") {
  await page.goto(`${base}/`);
  await page.getByLabel("Access key").fill(ak);
  await page.getByLabel("Secret key").fill(sk);
  await page.getByRole("button", { name: "Log in" }).click();
  await expect(page.getByRole("navigation", { name: "Main" })).toBeVisible();
}

test.describe.configure({ mode: "serial" });

test("live trace shows a PUT and filters errors", async ({ page }) => {
  await login(page);
  const bucket = `trace-${Date.now().toString(36)}`;
  const csrf = { "x-console-csrf": "1" };
  expect((await page.request.put(`/api/v1/s3/${bucket}`, { headers: csrf })).ok()).toBe(true);
  await page.goto("/#/monitoring?tab=trace");
  await expect(page.getByText("live", { exact: true })).toBeVisible();
  // The page keeps no credentials: only the HttpOnly session cookie exists.
  expect(await page.evaluate(() => JSON.stringify({ ...localStorage }) + JSON.stringify({ ...sessionStorage }) + document.cookie)).not.toMatch(/secret|ASIA/);
  expect((await page.request.put(`/api/v1/s3/${bucket}/traced.txt`, { headers: csrf, data: "hello trace" })).ok()).toBe(true);
  const row = page.getByRole("table", { name: "Trace entries" }).getByRole("row").filter({ hasText: "s3.PutObject" }).filter({ hasText: "traced.txt" });
  await expect(row).toBeVisible();
  await expect(row).toContainText("PUT");
  await shot(page, "20-trace");

  await page.getByRole("button", { name: "Clear" }).click();
  await expect(page.getByText("Waiting for requests…")).toBeVisible();
  await page.getByRole("switch", { name: "Errors only" }).check({ force: true });
  await expect(page.getByText("live", { exact: true })).toBeVisible();
  await page.waitForTimeout(500);
  await page.request.get(`/api/v1/s3/${bucket}/missing.txt`);
  await page.request.get(`/api/v1/s3/${bucket}/traced.txt`);
  const table = page.getByRole("table", { name: "Trace entries" });
  await expect(table.getByRole("row").filter({ hasText: "missing.txt" })).toBeVisible();
  await expect(table.getByRole("row").filter({ hasText: "traced.txt" })).toHaveCount(0);

  await page.getByRole("button", { name: "Pause" }).click();
  await expect(page.getByText("paused", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Resume" }).click();
  await expect(page.getByText("live", { exact: true })).toBeVisible();
});

test("live log shows entries and filters by level", async ({ page }) => {
  await login(page);
  await page.goto("/#/monitoring?tab=logs");
  const table = page.getByRole("table", { name: "Log entries" });
  await expect(table.getByRole("row").filter({ hasText: "INFO" }).first()).toBeVisible();
  await expect(table).toContainText("console on");
  await shot(page, "21-logs");
  await page.getByLabel("Minimum level").selectOption("ERROR");
  await expect(table.getByRole("row").filter({ hasText: "INFO" })).toHaveCount(0);
});

test("heal and scanner panels", async ({ page }) => {
  await login(page);
  await page.goto("/#/monitoring?tab=heal");
  await expect(page.getByRole("table", { name: "Erasure sets" })).toContainText("Pool 1, set 1");
  await expect(page.getByText("Current cycle")).toBeVisible();
  await expect(page.getByText("Objects scanned").last()).toBeVisible();
  await shot(page, "22-heal");
});

test.describe("pools on a 2-pool cluster", () => {
  test.skip(!poolsUrl, "POOLS_CONSOLE_URL not set");

  test("rebalance start and stop", async ({ page }) => {
    await login(page, poolsUrl);
    await page.goto(`${poolsUrl}/#/monitoring?tab=pools`);
    await expect(page.locator("tr[data-pool]")).toHaveCount(2);
    await expect(page.locator('tr[data-pool="0"]')).toContainText("of");
    await page.getByRole("button", { name: "Start rebalance" }).click();
    await expect(page.getByRole("button", { name: "Stop rebalance" })).toBeVisible();
    await expect(page.locator(".kv").filter({ hasText: "ID" })).toContainText("running");
    await shot(page, "23-rebalance-running");
    await page.getByRole("button", { name: "Stop rebalance" }).click();
    await page.getByRole("dialog").getByRole("button", { name: "Stop rebalance" }).click();
    await expect(page.getByRole("button", { name: "Start rebalance" })).toBeVisible();
    await expect(page.locator(".kv").filter({ hasText: "ID" })).toContainText("stopped");
  });

  test("decommission start, status and cancel", async ({ page }) => {
    await login(page, poolsUrl);
    await page.goto(`${poolsUrl}/#/monitoring?tab=pools`);
    const row = page.locator('tr[data-pool="0"]');
    await row.getByRole("button", { name: "Decommission" }).click();
    const dlg = page.getByRole("dialog");
    await expect(dlg).toContainText("Every object on pool 1 is moved");
    await dlg.getByRole("button", { name: "Decommission" }).click();
    await expect(row).toContainText("draining");
    await expect(row.getByRole("progressbar", { name: "Pool 1 drain progress" })).toBeVisible();
    await expect(row).toContainText("moved");
    // Rebalance and a second drain are refused while the pool drains.
    await expect(page.getByRole("button", { name: "Start rebalance" })).toBeDisabled();
    await expect(page.locator('tr[data-pool="1"]').getByRole("button", { name: "Decommission" })).toBeDisabled();
    await shot(page, "24-decommission");
    await row.getByRole("button", { name: "Cancel decommission" }).click();
    await page.getByRole("dialog").getByRole("button", { name: "Cancel decommission" }).click();
    await expect(row).toContainText("canceled");
    await expect(row.getByRole("button", { name: "Decommission" })).toBeEnabled();
    await shot(page, "25-decommission-canceled");
  });
});
