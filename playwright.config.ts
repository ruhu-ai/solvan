import { defineConfig, devices } from "@playwright/test";

const baseURL = process.env.SOLVAN_BASE_URL;
if (!baseURL) {
  throw new Error("SOLVAN_BASE_URL is required. Run tests through scripts/check-browser.");
}

export default defineConfig({
  testDir: "./tests/e2e",
  forbidOnly: true,
  retries: process.env.CI ? 1 : 0,
  workers: 1,
  reporter: [["list"], ["html", { open: "never" }]],
  use: {
    baseURL,
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
    video: "retain-on-failure",
  },
  projects: [
    // Signs in once against whichever identity provider this deployment is
    // configured with, so the cases that follow run as a real operator rather
    // than testing the login screen ninety times over.
    { name: "setup", testMatch: /auth\.setup\.ts/ },
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"], storageState: "tests/e2e/.auth/operator.json" },
      dependencies: ["setup"],
    },
    {
      name: "mobile-chromium",
      use: { ...devices["Pixel 7"], storageState: "tests/e2e/.auth/operator.json" },
      dependencies: ["setup"],
    },
  ],
});

