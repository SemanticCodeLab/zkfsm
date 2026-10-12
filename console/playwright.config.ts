import { defineConfig } from "@playwright/test";

// The server is started by tests/console.sh, which exports CONSOLE_URL.
export default defineConfig({
  testDir: "e2e",
  timeout: 90_000,
  // Debug server builds derive admin payload keys slowly; allow for it.
  expect: { timeout: 15_000 },
  workers: 1,
  reporter: [["list"]],
  outputDir: process.env.PW_OUTPUT_DIR || "test-results",
  use: {
    baseURL: process.env.CONSOLE_URL || "http://127.0.0.1:9001",
    viewport: { width: 1360, height: 860 },
    trace: "off",
  },
});
