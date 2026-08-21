/** The Fleet governance tabs: Memory, Security, Audit render the durable
 *  records the local seed writes, filter them, and state their empty cases;
 *  the Agents tab opens a durable run ledger; Platform explains how to read
 *  itself. These assert against the live projection over the seeded local
 *  database — no snapshot stubbing — because the blank-panel regression this
 *  file exists to prevent only reproduces on real data flow.
 */
import { expect, test } from "@playwright/test";
import type { Page } from "@playwright/test";

function shell(page: Page) {
  return page.getByRole("navigation", { name: "Primary" });
}

async function openFleetTab(page: Page, tab: string): Promise<void> {
  await page.goto("/");
  await shell(page).waitFor({ state: "attached" });
  const openNavigation = page.getByRole("button", { name: "Open navigation" });
  if (await openNavigation.isVisible()) await openNavigation.click();
  await shell(page).getByRole("button", { name: "Agent Fleet", exact: true }).click();
  await page.getByRole("tab", { name: tab }).click();
}

test("memory tab shows seeded queues and filters them", async ({ page }) => {
  await openFleetTab(page, "Memory");
  await expect(page.getByRole("heading", { name: "Memory candidates" })).toBeVisible();
  // The seed writes one candidate per spec queue; the blank-panel regression
  // rendered literally nothing here.
  await expect(page.locator(".memory-card")).not.toHaveCount(0);
  await page.getByRole("button", { name: "Promoted", exact: true }).click();
  await expect(page.locator(".memory-card")).toHaveCount(1);
  await expect(page.locator(".memory-card").getByText("PROMOTED")).toBeVisible();
  // A filter that matches nothing states so rather than rendering a blank
  // panel; PENDING seeds exist, but not under this search.
  await page.getByRole("button", { name: "Pending", exact: true }).click();
  await page.getByPlaceholder("Search purpose, classification, decision, or scope").fill("no-such-candidate");
  await expect(page.getByText("No memory candidate matches these filters.")).toBeVisible();
});

test("security tab groups seeded events by control", async ({ page }) => {
  await openFleetTab(page, "Security");
  await expect(page.getByRole("heading", { name: "Security events" })).toBeVisible();
  await expect(page.locator(".security-card")).not.toHaveCount(0);
  // Grouped by the control that refused, not a flat list.
  await expect(page.locator(".skills-group-title").filter({ hasText: "MODEL ARMOR" })).toBeVisible();
  await page.getByRole("button", { name: "High", exact: true }).click();
  await expect(page.locator(".security-card")).toHaveCount(1);
});

test("audit tab filters the immutable sequence by stream", async ({ page }) => {
  await openFleetTab(page, "Audit");
  await expect(page.getByRole("heading", { name: "Audit events", exact: true })).toBeVisible();
  const rows = page.locator(".responsive-table tbody tr");
  await expect(rows).not.toHaveCount(0);
  await page.getByPlaceholder("Search actor, event, stream, or decision").fill("coordinator");
  await expect(rows).not.toHaveCount(0);
  await page.getByPlaceholder("Search actor, event, stream, or decision").fill("no-such-actor");
  await expect(page.getByText("No audit event matches these filters.")).toBeVisible();
});

test("audit rows link to the surfaces that display their streams", async ({ page }) => {
  await openFleetTab(page, "Audit");
  // The seeded INCIDENT stream row links to the incident workspace; streams
  // without a surface stay citable text rather than dead anchors.
  const incidentLink = page.locator('td[data-label="Stream"] a[href*="?incident="]').first();
  await expect(incidentLink).toBeVisible();
  const memoryLink = page.locator('td[data-label="Stream"] a[href="/?fleet=memory"]').first();
  await expect(memoryLink).toBeVisible();
});

test("a fleet tab is addressable by URL", async ({ page }) => {
  await page.goto("/?fleet=memory");
  await expect(page.getByRole("tab", { name: "Memory", selected: true })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Memory candidates" })).toBeVisible();
  // Switching tabs keeps the URL shareable.
  await page.getByRole("tab", { name: "Security" }).click();
  await expect(page).toHaveURL(/fleet=security/);
});

test("agent cards carry digest-verified manifest facts", async ({ page }) => {
  await openFleetTab(page, "Agents");
  // Fleet-level facts are stated once above the grid, not on every card.
  await expect(page.locator(".fleet-note")).toContainText("google-adk");
  const card = page.locator(".agent-card", { hasText: "Evidence Agent" });
  await expect(card).toContainText("Owner department");
  await expect(card).toContainText("sre-platform");
  // PR-032: discovery is metadata exposure, never execution permission.
  await expect(card).toContainText("discovery only, never execution");
  await card.getByRole("button", { name: /Run history/ }).click();
  await expect(page.getByText("Framework / model")).toBeVisible();
  await expect(page.getByText("gemini-3.6-flash", { exact: false })).toBeVisible();
  // The one field with no record behind it says so instead of asserting one.
  await expect(page.getByText("No durable evaluation receipt exists in this scope.")).toBeVisible();
});

test("agent card opens a durable run ledger grouped by its work", async ({ page }) => {
  await openFleetTab(page, "Agents");
  const card = page.locator(".agent-card", { hasText: "Evidence Agent" });
  await expect(card).toBeVisible();
  await card.getByRole("button", { name: /Run history/ }).click();
  await expect(page.getByRole("heading", { name: "Run history" })).toBeVisible();
  // The seed anchors runs to the local incident; the ledger groups by it.
  await expect(page.locator(".skills-group-title").filter({ hasText: /Incident inc_/ })).toBeVisible();
  await expect(page.locator(".memory-card").first()).toBeVisible();
  await page.getByRole("button", { name: "Failed", exact: true }).click();
  await expect(page.getByText("No run matches these filters.")).toBeVisible();
  await page.getByRole("button", { name: "Back to agents", exact: true }).click();
  await expect(page.locator(".agent-grid")).toBeVisible();
});

test("platform tab explains how to read itself", async ({ page }) => {
  await openFleetTab(page, "Platform");
  await expect(page.getByRole("heading", { name: "How to read platform status" })).toBeVisible();
  await expect(page.getByText("The console never offers a manual")).toBeVisible();
  await expect(page.getByText("local evidence is never presented as cloud proof")).toBeVisible();
});
