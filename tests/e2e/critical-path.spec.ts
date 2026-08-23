import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";
import type { Page } from "@playwright/test";
import { execFileSync } from "node:child_process";

let releaseProjection: unknown;

function explicitReleaseProjection(): unknown {
  releaseProjection ??= JSON.parse(execFileSync(
    "uv",
    [
      "run",
      "python",
      "-c",
      "import json; from apps.api.console_fixture import console_snapshot; print(json.dumps(console_snapshot(), default=str))",
    ],
    { cwd: process.cwd(), encoding: "utf8" },
  ));
  return releaseProjection;
}

async function useExplicitReleaseProjection(page: Page): Promise<void> {
  await page.route("**/api/console/snapshot", async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify(explicitReleaseProjection()),
    });
  });
}

// The primary navigation landmark. A page may carry more than one <nav>, so
// every wait-for-the-shell-to-render check names the one it means.
function shell(page: Page) {
  return page.getByRole("navigation", { name: "Primary" });
}

async function navigate(page: Page, name: "Chat" | "Alerts" | "Reliability Cases" | "Integrations" | "Agent Fleet" | "Release Evidence" | "Settings"): Promise<void> {
  // The shell renders only once identity resolves, so wait for it before
  // deciding whether the mobile drawer needs opening. Checking first raced the
  // session gate and left the drawer shut with the item off-screen. Settings
  // renders a second navigation landmark, so this addresses the named one.
  await shell(page).waitFor({ state: "attached" });
  const openNavigation = page.getByRole("button", { name: "Open navigation" });
  if (await openNavigation.isVisible()) await openNavigation.click();
  await shell(page).getByRole("button", { name, exact: true }).click();
}

test("central Chat attaches only a reader-selected incident receipt", async ({ page }) => {
  await page.route("**/api/v1/liaison/directory**", async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        items: [{
          record_type: "incident",
          record_id: "INC-1042",
          title: "Elevated payment errors",
          service: "payments-api",
          state: "MITIGATED",
          severity: "SEV2",
          revision: `sha256:${"1".repeat(64)}`,
        }],
        next_cursor: null,
      }),
    });
  });
  await page.route("**/api/v1/liaison/selections", async (route) => {
    expect(route.request().headers()["idempotency-key"]).toBeTruthy();
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({ selection_receipt_id: "rsl_01KZMEK6J01N4NZRBJM6TA38RT" }),
    });
  });
  await page.route("**/api/v1/liaison/selections/*:open", async (route) => {
    expect(route.request().headers()["idempotency-key"]).toBeTruthy();
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({ thread_id: "thr_01KZMEK6J01N4NZRBJM6TA38RT" }),
    });
  });

  await page.goto("/");
  await expect(page.locator(".topbar")).not.toContainText("europe-west1");
  await expect(page.getByText("No production authority")).toBeVisible();
  await navigate(page, "Chat");
  await expect(page.getByRole("heading", { name: "Chat with Solvan" })).toBeVisible();
  await expect(page.getByText("Elevated payment errors")).toBeVisible();
  await page.getByRole("button", { name: /Attach INC-1042/ }).click();
  await expect(page.getByText("Attached incident")).toBeVisible();
  await expect(page.getByText(/INC-1042 · Elevated payment errors/)).toBeVisible();
  await page.getByRole("button", { name: "Return to workspace" }).click();
  await expect(page.getByText("Attached incident")).toHaveCount(0);
});

test("central Chat binds a visible service to an exact recent window", async ({ page }) => {
  await page.route("**/api/v1/liaison/services**", async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        items: [{ service_key: "payments-api", visible_record_count: 3 }],
      }),
    });
  });
  await page.route("**/api/v1/liaison/service-selections", async (route) => {
    expect(route.request().headers()["idempotency-key"]).toBeTruthy();
    const request = route.request().postDataJSON() as {
      service_key: string;
      window_start: string;
      window_end: string;
    };
    expect(request.service_key).toBe("payments-api");
    expect(new Date(request.window_end).getTime() - new Date(request.window_start).getTime())
      .toBe(6 * 60 * 60 * 1000);
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({ selection_receipt_id: "ssl_01KZMEK6J01N4NZRBJM6TA38RT" }),
    });
  });
  await page.route("**/api/v1/liaison/service-selections/*:open", async (route) => {
    expect(route.request().headers()["idempotency-key"]).toBeTruthy();
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        thread_id: "thr_01KZMEK6J01N4NZRBJM6TA38RS",
        window_start: "2026-08-15T06:00:00Z",
        window_end: "2026-08-15T12:00:00Z",
      }),
    });
  });

  await page.goto("/");
  await navigate(page, "Chat");
  await page.getByRole("tab", { name: "Services" }).click();
  await page.getByRole("button", { name: "Last 6h" }).click();
  await expect(page.getByText("payments-api")).toBeVisible();
  await page.getByRole("button", { name: "Attach payments-api for the last 6 hours" }).click();
  await expect(page.getByText("Attached service window")).toBeVisible();
  await expect(page.getByRole("heading", { name: "About payments-api" })).toBeVisible();
});

async function selectSettingsSection(page: Page, section: string, desktopLabel: string): Promise<void> {
  const mobileSection = page.getByLabel("Settings section", { exact: true });
  if (await mobileSection.isVisible()) await mobileSection.selectOption(section);
  else await page.getByRole("button", { name: desktopLabel }).click();
}

test("settings exposes truthful scope, runtime provenance, and persistent personal preferences", async ({ page }) => {
  await page.goto("/");
  await navigate(page, "Settings");

  await expect(page.getByRole("heading", { name: "Settings", exact: true })).toBeVisible();
  const theme = page.getByRole("radiogroup", { name: "Theme" });
  await expect(theme.getByRole("radio", { name: "System" })).toHaveAttribute("aria-checked", "true");
  const timezone = page.getByLabel("Display timezone");
  await timezone.selectOption("Africa/Lagos");
  await expect(timezone).toHaveValue("Africa/Lagos");
  await expect(timezone.locator("option")).toHaveCount(20);
  await expect(timezone.locator("option", { hasText: "West Africa Time (Lagos)" })).toHaveCount(1);
  await expect(timezone.locator("option", { hasText: "Africa — Abidjan" })).toHaveCount(0);
  await expect(page.getByLabel("IANA timezone")).toHaveCount(0);
  await theme.getByRole("radio", { name: "Dark" }).click();
  await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");
  await page.reload();
  await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");
  await expect(page.getByLabel("Display timezone")).toHaveValue("Africa/Lagos");

  await navigate(page, "Settings");
  await selectSettingsSection(page, "runtime", "AI runtime");
  await expect(page.getByText("Gemini 3.6 Flash")).toBeVisible();
  await expect(page.getByTitle("LOCAL FIXTURE")).toBeVisible();
  await expect(page.getByText("Ruhu design partner")).toHaveCount(0);
  await selectSettingsSection(page, "governance", "Safety and governance");
  await expect(page.getByRole("heading", { name: "Earned autonomy" })).toBeVisible();
  await expect(page.locator(".settings-refusal").getByText(/no production authority/i)).toBeVisible();
});

test("operator menu and settings remain accessible on a narrow screen", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/");
  await page.getByRole("button", { name: "Operator menu" }).click();
  await expect(page.getByRole("dialog", { name: "Operator menu" })).toContainText("Local development reader");
  await page.getByRole("button", { name: "Profile and session" }).click();
  await expect(page.getByRole("heading", { name: "Identity and roles" })).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth)).toBeFalsy();
});

test("settings has no serious accessibility violations in light or dark", async ({ page }) => {
  await page.goto("/?section=personal");
  const theme = page.getByRole("radiogroup", { name: "Theme" });
  await theme.getByRole("radio", { name: "Light" }).click();
  const light = await new AxeBuilder({ page }).analyze();
  expect(light.violations.filter((item) => ["serious", "critical"].includes(item.impact ?? ""))).toEqual([]);

  await theme.getByRole("radio", { name: "Dark" }).click();
  const dark = await new AxeBuilder({ page }).analyze();
  expect(dark.violations.filter((item) => ["serious", "critical"].includes(item.impact ?? ""))).toEqual([]);
});

test("settings remains usable when its dedicated projection request fails", async ({ page }) => {
  await page.route("**/api/console/snapshot", async (route) => {
    const response = await route.fetch();
    const snapshot = await response.json() as Record<string, unknown>;
    delete snapshot.settings;
    await route.fulfill({ response, json: snapshot });
  });
  await page.route("**/api/console/settings", async (route) => {
    await route.fulfill({ status: 503, contentType: "application/json", body: JSON.stringify({ detail: "temporarily unavailable" }) });
  });
  await page.goto("/?section=about");
  await expect(page.getByRole("heading", { name: "Build information" })).toBeVisible();
  await expect(page.getByText("Some settings details could not be refreshed")).toBeVisible();
  await expect(page.getByText("Settings details unavailable")).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Operator menu" })).toBeVisible();
});

test("personal preferences stay operable when browser storage is blocked", async ({ page }) => {
  await page.addInitScript(() => {
    Storage.prototype.setItem = () => { throw new DOMException("Storage blocked", "SecurityError"); };
  });
  await page.goto("/?section=personal");
  await page.getByRole("radiogroup", { name: "Theme" }).getByRole("radio", { name: "Dark" }).click();
  await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");
  await expect(page.getByRole("alert")).toContainText("Applied for this tab; browser storage is unavailable.");
});

test("settings deep links and browser history restore the correct surface", async ({ page }) => {
  await page.goto("/");
  await navigate(page, "Settings");
  await page.goBack();
  await expect(page.getByRole("heading", { name: "Production reliability, with proof" })).toBeVisible();

  await page.goto("/?section=runtime");
  await expect(page.getByRole("heading", { name: "Effective model and platform" })).toBeVisible();
  await selectSettingsSection(page, "about", "About");
  await expect(page.getByRole("heading", { name: "Build and diagnostics" })).toBeVisible();
  await page.goBack();
  await expect(page.getByRole("heading", { name: "Effective model and platform" })).toBeVisible();
});

test("channel settings bind Slack and Discord without browser-asserted provider identity", async ({ page }) => {
  const enrollmentBodies: Array<Record<string, unknown>> = [];
  await page.route("**/api/v1/channels/providers", async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        authority: "PRODUCTION",
        providers: ["SLACK", "DISCORD", "EMAIL"].map((channel_kind) => ({
          channel_kind,
          status: "AVAILABLE",
          safe_reason_code: "DEPLOYED_PATH_PASSED",
          next_step_code: "REQUALIFY_BEFORE_EXPIRY",
          checked_at: "2026-08-15T12:00:00Z",
          expires_at: "2026-08-15T13:00:00Z",
          receipt_ref: "gs://evidence/provider.json",
          deployment_id: "staging-20260815",
          service_revision: `${channel_kind.toLowerCase()}-00017-current`,
        })),
      }),
    });
  });
  await page.route("**/api/v1/channels/bindings", async (route) => {
    await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ bindings: [] }) });
  });
  await page.route("**/api/v1/channels/enrollments", async (route) => {
    enrollmentBodies.push(route.request().postDataJSON() as Record<string, unknown>);
    expect(route.request().headers()["idempotency-key"]).toBeTruthy();
    await route.fulfill({
      status: 201,
      contentType: "application/json",
      body: JSON.stringify({
        challenge_id: "enr_01KZMEK6J01N4NZRBJM6TA38RT",
        channel_kind: "SLACK",
        status: "DISPATCHED",
        instruction: "Send `solvan enroll proof-code` to the installed Solvan app.",
        expires_in_seconds: 600,
        code: "proof-code",
      }),
    });
  });
  await page.route("**/api/v1/channels/enrollments/*", async (route) => {
    if (route.request().method() === "DELETE") {
      expect(route.request().headers()["idempotency-key"]).toBeTruthy();
      await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ status: "CANCELLED" }) });
      return;
    }
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        challenge_id: "enr_01KZMEK6J01N4NZRBJM6TA38RT",
        channel_kind: "SLACK",
        channel_identity: null,
        status: "DISPATCHED",
        issued_at: "2026-08-15T12:00:00Z",
        expires_at: "2026-08-15T12:10:00Z",
        attempts: 0,
        safe_reason_code: null,
      }),
    });
  });

  await page.goto("/?section=channels");
  await expect(page.getByRole("heading", { name: "Conversation channels" })).toBeVisible();
  await expect(page.getByLabel(/Slack.*ID/i)).toHaveCount(0);
  await expect(page.getByLabel(/Discord.*ID/i)).toHaveCount(0);
  await page.getByRole("button", { name: "Connect Slack" }).click();
  await expect.poll(() => enrollmentBodies.length).toBe(1);
  expect(enrollmentBodies[0]).toEqual({ schema_version: 1, channel_kind: "SLACK" });
  await expect(page.getByText(/solvan enroll proof-code/)).toBeVisible();
  await page.getByRole("button", { name: "Cancel verification" }).click();
  await expect(page.getByText("The pending verification was cancelled.", { exact: true })).toBeVisible();
});

test("channel settings sends email verification without exposing a production code", async ({ page }) => {
  let emailRequest: Record<string, unknown> | null = null;
  await page.route("**/api/v1/channels/providers", async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        authority: "PRODUCTION",
        providers: ["SLACK", "DISCORD", "EMAIL"].map((channel_kind) => ({
          channel_kind,
          status: "AVAILABLE",
          safe_reason_code: "DEPLOYED_PATH_PASSED",
          next_step_code: "REQUALIFY_BEFORE_EXPIRY",
          checked_at: "2026-08-15T12:00:00Z",
          expires_at: "2026-08-15T13:00:00Z",
          receipt_ref: "gs://evidence/provider.json",
          deployment_id: "staging-20260815",
          service_revision: `${channel_kind.toLowerCase()}-00017-current`,
        })),
      }),
    });
  });
  await page.route("**/api/v1/channels/bindings", async (route) => {
    await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ bindings: [] }) });
  });
  await page.route("**/api/v1/channels/enrollments", async (route) => {
    emailRequest = route.request().postDataJSON() as Record<string, unknown>;
    await route.fulfill({
      status: 201,
      contentType: "application/json",
      body: JSON.stringify({
        challenge_id: "enr_01KZMEK6J01N4NZRBJM6TA38RS",
        channel_kind: "EMAIL",
        status: "DISPATCHED",
        instruction: "Check your inbox and reply to the signed verification message.",
        expires_in_seconds: 600,
      }),
    });
  });

  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/?section=channels");
  await page.getByLabel("Email address").fill("operator@example.com");
  await page.getByRole("button", { name: "Connect Email" }).click();
  await expect.poll(() => emailRequest).not.toBeNull();
  expect(emailRequest).toEqual({
    schema_version: 1,
    channel_kind: "EMAIL",
    email_address: "operator@example.com",
  });
  await expect(page.getByText("Check your inbox and reply to the signed verification message.")).toBeVisible();
  await expect(page.getByText(/proof-code/)).toHaveCount(0);
  expect(await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth)).toBeFalsy();
});

test("operator overview renders the durable local projection without authority", async ({ page }) => {
  const consoleErrors: string[] = [];
  page.on("console", (message) => {
    if (message.type() === "error") consoleErrors.push(message.text());
  });

  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Production reliability, with proof" })).toBeVisible();
  // No standing banner: the authority statement lives once, in the sidebar.
  await expect(page.locator(".fixture-banner")).toHaveCount(0);
  await expect(page.getByText("No production authority")).toBeVisible();
  await expect(page.getByRole("heading", { name: "Connection Exhaustion on payments-api" })).toBeVisible();
  await expect(page.getByText("No human approval is currently pending.")).toBeVisible();
  expect(consoleErrors).toEqual([]);
});

test("Alerts presents a scannable queue and answer-first investigation report", async ({ page }, testInfo) => {
  await page.goto("/");
  await navigate(page, "Alerts");

  await expect(page.getByRole("heading", { name: "Alerts", exact: true })).toBeVisible();
  await expect(page.getByLabel("Alert queue summary").getByRole("button", { name: /Active/ })).toHaveAttribute("aria-pressed", "true");
  await expect(page.getByText("Elevated payment errors on payments-api", { exact: true })).toBeVisible();

  const search = page.getByRole("textbox", { name: "Search visible alerts" });
  await search.fill("not-present");
  await expect(page.getByText("No alerts match this view")).toBeVisible();
  await search.fill("payments");
  await expect(page.getByText("Elevated payment errors on payments-api", { exact: true })).toBeVisible();

  await page.getByRole("button", { name: /Open Elevated payment errors/ }).click();
  await expect(page.getByRole("article", { name: "Alert investigation report" })).toBeVisible();
  await expect(page.getByText("Committed decision · not a simulation")).toBeVisible();
  await expect(page.getByRole("heading", { name: "Why this Alert became an Incident" })).toBeVisible();
  await expect(page.getByText("Investigate, then escalate by rule", { exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "Copy safe link" })).toBeVisible();
  for (const section of ["What happened", "Impact", "Likely cause", "Key evidence", "Recommended next step"]) {
    await expect(page.getByRole("heading", { name: section, exact: true })).toBeVisible();
  }
  if (testInfo.project.name === "chromium") {
    await expect(page.getByLabel("Ask about this alert")).toBeVisible();
  } else {
    await expect(page.getByRole("button", { name: "Ask about this alert" })).toBeVisible();
  }
  await expect(page.getByRole("heading", { name: "Open linked Incident", exact: true })).toBeVisible();
  await expect(page.getByText("Local development has no cloud identity or command authority.")).toBeVisible();

  await page.getByText("Technical details", { exact: true }).click();
  await expect(page.getByRole("button", { name: "Run triage again" })).toBeDisabled();
  await expect(page.getByRole("button", { name: "Give feedback" })).toBeDisabled();
  expect(await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth)).toBeFalsy();
});

test("Alerts detail keeps the report primary on a narrow screen", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/");
  await navigate(page, "Alerts");
  await page.getByRole("button", { name: /Open Elevated payment errors/ }).click();
  await expect(page.getByRole("article", { name: "Alert investigation report" })).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth)).toBeFalsy();
});

test("local API exposes a correlated trace and the overview has no horizontal overflow", async ({ page, request }) => {
  const apiUrl = process.env.SOLVAN_API_URL;
  if (!apiUrl) throw new Error("SOLVAN_API_URL is required");
  const response = await request.get(`${apiUrl}/api/console/snapshot`);
  expect(response.ok()).toBeTruthy();
  expect(response.headers()["x-trace-id"]).toMatch(/^[a-f0-9]{32}$/);

  await page.goto("/");
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth);
  expect(overflow).toBeFalsy();
});

test("an incident with no proposed mutation exposes no approval control", async ({ page }) => {
  await page.goto("/");
  await page.getByRole("button", { name: /Open incident workspace/ }).click();
  await expect(page.getByRole("heading", { name: "Connection Exhaustion on payments-api" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Who is working this incident" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "What happened and what happens next" })).toBeVisible();
  await expect(page.getByText("Incident Supervisor Agent")).toBeVisible();

  await page.getByRole("tab", { name: "Actions" }).click();
  await expect(page.getByText("Connector success and independent recovery remain separate states.")).toBeVisible();
  await expect(page.locator(".budget-pill")).toContainText("0");
  await expect(page.locator(".budget-pill")).toContainText("durable actions");
  await expect(page.getByRole("button", { name: "Review exact approval" })).toHaveCount(0);
});

test("fleet makes discovery and platform health scope explicit", async ({ page }) => {
  await page.goto("/");
  await navigate(page, "Agent Fleet");
  await expect(page.getByRole("heading", { name: "Agent Fleet" })).toBeVisible();
  await expect(page.getByText("Execution Agent")).toBeVisible();
  await expect(page.getByText("Deployed").first()).toBeVisible();

  // The list states how many revisions this scope can select and what each row
  // reaches. The governance record and the status vocabulary belong to one
  // revision, so they are read in its detail rather than repeated on every row.
  await page.getByRole("tab", { name: "Tools" }).click();
  await expect(page.getByRole("heading", { name: "Tools" })).toBeVisible();
  await expect(page.getByText(/selectable in this scope|none selectable here/)).toBeVisible();
  await expect(page.getByRole("heading", { name: "Managed Prometheus query" })).toBeVisible();
  await expect(page.getByText("Registry discovery never grants invocation")).toHaveCount(0);
  await page.getByRole("button", { name: /^Managed Prometheus query/i }).click();
  await expect(page.getByText("Whether the exact capability was probed and remains fresh.")).toBeVisible();
  await expect(page.getByText("Registry discovery never grants invocation")).toBeVisible();
  await page.getByRole("button", { name: "Back to tools" }).click();
  await expect(page.getByRole("heading", { name: "Managed Prometheus query" })).toBeVisible();

  await page.getByRole("tab", { name: "Skills" }).click();
  await expect(page.getByRole("heading", { name: "Skills" })).toBeVisible();
  await expect(page.getByText("Skills are data, never authority.")).toBeVisible();
  await expect(page.getByRole("heading", { name: "Payment connection exhaustion" })).toBeVisible();
  await page.getByRole("heading", { name: "Payment connection exhaustion" }).click();
  await expect(page.getByText("Provenance and governance", { exact: true })).toBeVisible();
  await expect(page.getByText(/grants no action authority/i)).toBeVisible();

  await page.getByRole("tab", { name: "Alert policies" }).click();
  await expect(page.getByText("No trigger policy is approved in this scope.")).toBeVisible();

  await page.getByRole("tab", { name: "Platform" }).click();
  await expect(page.getByText("Agent Gateway")).toBeVisible();
  // The verdict is stated once, up front, rather than left for the operator to
  // synthesise from seven cards. "Healthy" no longer appears for a component
  // with no cloud receipt: readiness is derived from where it was verified.
  await expect(page.getByRole("heading", { name: /0 of 7 components verified in the cloud/ })).toBeVisible();
  await expect(page.getByText("Not release ready")).toBeVisible();
  await expect(page.getByText("Not verified").first()).toBeVisible();
  await expect(page.getByText("Capture the platform preflight receipt before calling this healthy.").first()).toBeVisible();
  // Provenance stays available for audit, one disclosure away rather than
  // repeated on every card.
  await expect(page.getByText("How this was determined").first()).toBeVisible();
});

test("Fleet exposes governed Alert policy and capacity evidence", async ({ page }) => {
  await page.goto("/");
  await navigate(page, "Agent Fleet");
  await page.getByRole("tab", { name: "Alert policies", exact: true }).click();

  await expect(page.getByRole("heading", { name: "Alert policies", exact: true })).toBeVisible();
  await expect(page.getByText("These revisions decide which verified source observations may receive bounded triage.")).toBeVisible();
  await expect(page.getByText("0 of 4 model-request reservations active")).toBeVisible();
  // The page states that it is scripted data rather than presenting a fixture's
  // lifecycle and approval as a deployment's.
  await expect(page.getByText(/SCRIPTED_RELEASE_FIXTURE/)).toBeVisible();
  await expect(page.getByRole("button", { name: /payments-http-errors/ })).toBeVisible();
  // What the policy does, and whether it can admit right now, are on the card:
  // the operator should not have to open a detail panel to learn either.
  await expect(page.getByText("Investigate, then escalate by rule")).toBeVisible();
  // The badge now carries its machine state as a real text node so assistive
  // technology reaches it; `title` alone was hover-only, which specification 6
  // never permitted. The visible label is still the human sentence.
  await expect(page.locator(".status-badge-label").getByText("Admitting", { exact: true })).toBeVisible();
  await expect(page.getByText("Source ready")).toBeVisible();
  await expect(page.getByText("user:policy-approver@example.com")).toBeVisible();
  await page.getByRole("button", { name: /payments-http-errors/ }).click();
  await expect(page.getByRole("heading", { name: "payments-http-errors@4", exact: true })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Eligible source connections" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Calibrated starts and outcome suggestions" })).toBeVisible();
  await expect(page.getByText("EXAMPLE — NOT A DEFAULT")).toBeVisible();
  await expect(page.getByText("Machine-proposed · requires author review")).toBeVisible();
  await expect(page.getByText("Test a draft against an authorized historical sample")).toBeVisible();
});

test("Skills catalog supports browse, filtering, detail, and lifecycle review", async ({ page }) => {
  await page.goto("/");
  await navigate(page, "Agent Fleet");
  await page.getByRole("tab", { name: "Skills", exact: true }).click();

  const search = page.getByRole("textbox", { name: "Search skills", exact: true });
  await expect(search).toBeVisible();
  await expect(page.getByRole("heading", { name: "Reliability triage flows" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Imported · quarantine to approval" })).toBeVisible();
  await search.fill("connection");
  await expect(page.getByRole("heading", { name: "Payment connection exhaustion" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Triage connection exhaustion" })).toBeVisible();

  await page.getByRole("button", { name: "Needs attention", exact: true }).click();
  await expect(page.getByRole("status").filter({ hasText: "1 skill" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Triage connection exhaustion" })).toBeHidden();

  await page.getByRole("heading", { name: "Payment connection exhaustion" }).click();
  await expect(page.getByText("Imported content stays in the quarantine store")).toBeVisible();
  // Provenance is recorded but not led with: the governance sentence and the
  // revision digest are one click away rather than absent.
  await expect(page.getByText("Selection still requires exact scope, region, purpose, profile, and coordinator revalidation.")).toBeHidden();
  await page.getByText("Provenance and governance", { exact: true }).click();
  await expect(page.getByText("Selection still requires exact scope, region, purpose, profile, and coordinator revalidation.")).toBeVisible();
  await expect(page.getByText("Revision digest", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Back to skills", exact: true }).click();

  await page.getByRole("button", { name: "All", exact: true }).click();
  await search.fill("Triage latency");
  await page.getByRole("heading", { name: "Triage latency", exact: true }).click();
  await expect(page.getByRole("tab", { name: "SKILL.md" })).toBeVisible();
  await expect(page.getByText("Progressive disclosure")).toBeVisible();
  await page.getByRole("button", { name: "Source view", exact: true }).click();
  await expect(page.getByText("name: triage-latency")).toBeVisible();
  await page.getByRole("tab", { name: "PROVENANCE.yaml" }).click();
  await expect(page.getByText("source_kind: FIRST_PARTY")).toBeVisible();
  await page.getByRole("button", { name: "Back to skills", exact: true }).click();

  await page.getByRole("button", { name: "Add / import skill", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Import governed guidance" })).toBeVisible();
  for (const label of ["QUARANTINED", "DRAFT", "IN_REVIEW", "APPROVED", "DEPRECATED", "REJECTED", "REFUSED"]) {
    await expect(page.getByText(label, { exact: true })).toBeVisible();
  }
});

test("Skills governance loads and registers exact authenticated policy inputs", async ({ page }) => {
  const writes: Array<{ path: string; authorization: string | null; body: Record<string, unknown> }> = [];
  const projection = {
    owners: [{ owner_slug: "reliability-platform", owner_department: "Reliability Platform", retired_at: null }],
    licenses: [{ normalized_identifier: "Apache-2.0", policy_version: "2026-08-14", import_allowed: true, redistribution_allowed: true, enabled: true }],
    readers: [],
    destinations: [{ destination_id: "tenant-guidance-default", destination_kind: "GCS", binding_ref: "gs://regional-skills/exports", region: "europe-west1", classification_ceiling: "INTERNAL", enabled: true }],
  };
  await page.route("**/v1/skills/governance", async (route) => {
    await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(projection) });
  });
  await page.route("**/v1/skills/governance/owners", async (route) => {
    writes.push({
      path: new URL(route.request().url()).pathname,
      authorization: await route.request().headerValue("authorization"),
      body: route.request().postDataJSON() as Record<string, unknown>,
    });
    await route.fulfill({ status: 201, contentType: "application/json", body: JSON.stringify({ owner_slug: "reliability-platform" }) });
  });

  await page.goto("/");
  await navigate(page, "Agent Fleet");
  await page.getByRole("tab", { name: "Skills", exact: true }).click();
  await page.getByRole("button", { name: "Add / import skill", exact: true }).click();
  await page.getByLabel("One-time Google identity token").fill("Bearer short-lived-test-token");
  await page.getByText("Configure Skills governance", { exact: true }).click();
  await page.getByRole("button", { name: "Load registered governance" }).click();

  await expect(page.getByRole("heading", { name: "Owners · 1" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "License policies · 1" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Reader grants · 0" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Export destinations · 1" })).toBeVisible();

  await page.getByRole("button", { name: "Register owner" }).click();
  await expect.poll(() => writes.length).toBe(1);
  expect(writes[0]).toEqual({
    path: "/api/v1/skills/governance/owners",
    authorization: "Bearer short-lived-test-token",
    body: {
      owner_slug: "reliability-platform",
      owner_department: "Reliability Platform",
      purpose: "SKILL_GOVERNANCE",
    },
  });
  await expect(page.getByRole("status").filter({ hasText: "Current scope-bound governance loaded." })).toBeVisible();
});

test("investigation map is derived from durable plan and evidence records", async ({ page }) => {
  await page.goto("/");
  await page.getByRole("button", { name: /Open incident workspace/ }).click();
  await expect(page.getByText("Operator brief")).toBeVisible();
  await expect(page.getByRole("button", { name: /Cloud Monitoring on payments-api\/http_5xx_ratio/ }).first()).toBeVisible();

  await page.getByRole("tab", { name: "Evidence" }).click();
  await expect(page.getByRole("heading", { name: "Investigation map" })).toBeVisible();
  await expect(page.getByText(/Accepted durable plan · version/)).toBeVisible();
  await expect(page.getByRole("heading", { name: "6 stored records" })).toBeVisible();
  await expect(page.getByText("Inferred — not validated", { exact: true })).toBeVisible();
  await expect(page.getByText(/chain[- ]of[- ]thought/i)).toHaveCount(0);
});

test("inconclusive verification refuses to imply recovery", async ({ page }) => {
  await page.goto("/");
  await page.getByRole("button", { name: /Open incident workspace/ }).click();
  await page.getByRole("tab", { name: "Verification" }).click();
  await expect(page.getByRole("heading", { name: /mitigation verification/ })).toBeVisible();
  await expect(page.getByText("Verification inconclusive")).toBeVisible();
  await expect(page.getByText("Recovery could not be decided")).toBeVisible();
  await expect(page.getByText(/Recovery is unproven until it runs again/)).toBeVisible();
  await expect(page.getByText("Recovery independently verified")).toHaveCount(0);
});

test("reliability case is not invented before mitigation verification", async ({ page }) => {
  await page.goto("/");
  await navigate(page, "Reliability Cases");
  await expect(page.getByRole("heading", { name: "Reliability Cases" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "No Reliability Case yet" })).toBeVisible();
  await expect(page.getByText("A case opens after mitigation is independently verified.")).toBeVisible();
  await expect(page.getByRole("button", { name: /Approve/ })).toHaveCount(0);
});

test("every citation identifies its source and opens stored provenance", async ({ page }) => {
  await page.goto("/");
  await page.getByRole("button", { name: /Open incident workspace/ }).click();

  const chip = page.locator(".operator-brief .provenance-row").getByRole("button", { name: /Cloud Monitoring on payments-api\/http_5xx_ratio/ });
  await expect(chip).toContainText("Cloud Monitoring on payments-api/http_5xx_ratio");

  await chip.click();
  const drawer = page.getByRole("dialog");
  await expect(drawer.getByText("Cloud Monitoring")).toBeVisible();
  await expect(drawer.getByRole("heading", { name: "Cloud Monitoring on payments-api/http_5xx_ratio" })).toBeVisible();
  await expect(drawer.getByText(/Raw content is fetched only through an authorized, redacted read/)).toBeVisible();

  await page.keyboard.press("Escape");
  await expect(page.getByRole("dialog")).toHaveCount(0);
});

test("incident impact remains bounded to committed incident and evidence facts", async ({ page }) => {
  await page.goto("/");
  await page.getByRole("button", { name: /Open incident workspace/ }).click();

  await expect(page.getByText(/Impact has been open for .* and is not yet closed/)).toBeVisible();
  await expect(page.getByText("SEV2 impact is recorded on payments-api.")).toBeVisible();
  await expect(page.getByText("No independent verification result yet.")).toBeVisible();
});

test("the evidence tab counts every record the incident stands on", async ({ page }) => {
  await page.goto("/");
  await page.getByRole("button", { name: /Open incident workspace/ }).click();
  await page.getByRole("tab", { name: "Evidence" }).click();
  await expect(page.getByRole("heading", { name: "6 stored records" })).toBeVisible();
  await expect(page.locator(".evidence-ledger-list li")).toHaveCount(6);
});

test("the queue can be triaged and filtered down to what needs a person", async ({ page }) => {
  await page.goto("/");
  await navigate(page, "Incidents");
  await expect(page.getByText("1 of 1 incident")).toBeVisible();
  await expect(page.getByRole("cell", { name: "SEV2 · connection exhaustion" })).toBeVisible();

  await page.getByRole("button", { name: /Waiting on a person/ }).click();
  await expect(page.getByText("0 of 1 incident")).toBeVisible();
  await expect(page.getByRole("cell", { name: "INC-1042" })).toHaveCount(0);

  await page.getByRole("button", { name: /Waiting on a person/ }).click();
  await page.getByRole("searchbox").fill("payments");
  await expect(page.getByText("1 of 1 incident")).toBeVisible();
  await expect(page.getByRole("cell", { name: "INC-1042" })).toBeVisible();
});

test("the catch-up brief does not fabricate entries when no committed events exist", async ({ page }) => {
  await page.goto("/");
  await page.getByRole("button", { name: /Open incident workspace/ }).click();
  await page.getByRole("button", { name: "Ask the ledger" }).click();
  await expect(page.locator(".ask-catchup")).toHaveCount(0);
  await expect(page.getByRole("heading", { name: "About INC-1042" })).toBeVisible();
});

test("asking the ledger yields cited statements, and offers a steer when it cannot answer", async ({ page }) => {
  await page.goto("/");
  await page.getByRole("button", { name: /Open incident workspace/ }).click();

  // The conversation is a rail opened beside the record, not a section of the
  // page: the incident stays readable while a question is being asked.
  await page.getByRole("button", { name: "Ask the ledger" }).click();
  const panel = page.locator(".ask-rail");
  await expect(panel.getByRole("heading", { name: "About INC-1042" })).toBeVisible();
  // Non-modal by construction — the record behind the rail is still reachable.
  await expect(page.getByRole("heading", { name: "Connection Exhaustion on payments-api" })).toBeVisible();

  // Suggested questions are enumerated per record state, never generated.
  await panel.getByRole("button", { name: /What was the impact\?/ }).click();

  // Every rendered statement is template-composed and stands on an exact,
  // resolvable citation immediately beside the sentence it supports.
  const claims = panel.locator(".ask-claim");
  await expect(claims.first()).toBeVisible();
  const citedSource = claims.first().locator(".source-chip").first();
  await expect(citedSource).toBeVisible();
  await citedSource.click();
  await expect(page.getByRole("dialog")).toBeVisible();
  await page.getByRole("button", { name: "Close evidence" }).click();
  await expect(panel.getByText(/verified statements from the ledger/).last()).toBeVisible();

  // A question the ledger cannot answer names the missing read and offers the
  // bounded step, rather than guessing.
  await panel.getByRole("textbox", { name: /Ask a question about this incident/ }).fill("what is the error rate right now");
  // The composer sends with an arrow inside the field; its accessible name
  // still says what it does, which is what this locator depends on.
  await panel.getByRole("button", { name: "Send question" }).click();
  // The transcript is durable across harness restarts, so assert against the
  // response to this turn rather than assuming the thread was empty.
  const steer = panel.locator(".ask-steer").last();
  await expect(steer).toBeVisible();
  await expect(steer.getByText("Needs your confirmation")).toBeVisible();
  // Nothing here can act: no approval control appears in a conversation.
  await expect(panel.getByRole("button", { name: /Approve/ })).toHaveCount(0);

  // A parked steer confirmation is its own durable message and replies to
  // nothing, so a transcript keyed purely off reply links dropped it: the card
  // lived in the ledger and never on screen after a reload.
  await panel.getByRole("button", { name: "Review bounded read" }).last().click();
  // The click starts an asynchronous durable write. Wait for the server's
  // acknowledgement before navigating; otherwise the test can cancel its own
  // request during reload and claim the transcript lost a row that never
  // committed.
  await expect(panel.getByRole("button", { name: "Confirm request" }).last()).toBeVisible();
  await page.reload();
  await page.getByRole("button", { name: /Open incident workspace/ }).click();
  await page.getByRole("button", { name: "Ask the ledger" }).click();
  await expect(page.locator(".ask-rail").locator(".ask-parked").last()).toBeVisible();
});

test("the ledger supports ordinary durable multi-turn conversation", async ({ page }) => {
  await page.goto("/");
  await page.getByRole("button", { name: /Open incident workspace/ }).click();
  await page.getByRole("button", { name: "Ask the ledger" }).click();
  const panel = page.locator(".ask-rail");
  const composer = panel.getByRole("textbox", { name: /Ask a question about this incident/ });

  await composer.fill("hello");
  await panel.getByRole("button", { name: "Send question" }).click();
  await expect(panel.getByText("Hello. Ask me about this incident, its impact, evidence, actions, or recovery.").last()).toBeVisible();
  // The delivery mark says only that the message reached the ledger, and it
  // says it to assistive technology rather than printing "Committed" beside a
  // governed surface, where it reads as an approval (spec 14 §19.1).
  await expect(panel.locator(".ask-message-user").last())
    .toContainText("Appended to the conversation ledger");
  // A finished answer carries no state badge: it is on screen, which is the
  // whole of what "completed" was telling anyone.
  await expect(panel.locator(".ask-message-liaison").last()).not.toContainText("completed");
  await expect(panel.getByText("Failed to fetch")).toHaveCount(0);

  await composer.fill("What caused the payment failures?");
  await panel.getByRole("button", { name: "Send question" }).click();
  await expect(panel.locator(".ask-claim").first()).toBeVisible();

  await composer.fill("why?");
  await panel.getByRole("button", { name: "Send question" }).click();
  await expect(panel.getByText(/Which earlier point do you mean/).last()).toBeVisible();

  // Action language never creates authority. With no durable action on this
  // incident, the conversation cannot manufacture an approval control.
  await composer.fill("rollback it");
  await panel.getByRole("button", { name: "Send question" }).click();
  await expect(panel.locator(".ask-approval-ref")).toHaveCount(0);
  await expect(panel.getByRole("button", { name: /Approve/ })).toHaveCount(0);
});

test("the ledger autocompletes only discoverable approved Skills by exact selector", async ({ page }) => {
  const autocompleteQueries: string[] = [];
  await page.route("**/v1/skills/autocomplete**", async (route) => {
    autocompleteQueries.push(new URL(route.request().url()).searchParams.get("query") ?? "");
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        items: [{
          selector: "/payments/connection-exhaustion",
          guidance_key: "payments.connection-exhaustion",
          version: "2",
          display_name: "Payment connection exhaustion",
          description: "Investigate a bounded payment-pool exhaustion signal.",
        }],
      }),
    });
  });

  await page.goto("/");
  await page.getByRole("button", { name: /Open incident workspace/ }).click();
  await page.getByRole("button", { name: "Ask the ledger" }).click();
  const panel = page.locator(".ask-rail");
  const composer = panel.getByRole("textbox", { name: /Ask a question about this incident/ });
  await composer.fill("/pay");

  const options = panel.getByRole("listbox", { name: "Approved Skills" });
  await expect(options.getByRole("option", { name: /payments\/connection-exhaustion/ })).toBeVisible();
  await composer.press("Enter");
  await expect(composer).toHaveValue("/payments/connection-exhaustion ");
  expect(autocompleteQueries).toContain("pay");
});

test("conversation collaboration and quarantine attachments stay explicit", async ({ page }) => {
  await page.goto("/");
  await page.getByRole("button", { name: /Open incident workspace/ }).click();
  await page.getByRole("button", { name: "Ask the ledger" }).click();
  const panel = page.locator(".ask-rail");
  const composer = panel.getByRole("textbox", { name: /Ask a question about this incident/ });

  // A thread must exist before membership controls can enumerate anything.
  await composer.fill("hello");
  await panel.getByRole("button", { name: "Send question" }).click();
  await expect(panel.getByText(/Hello\. Ask me about this incident/).last()).toBeVisible();

  await panel.getByRole("button", { name: "Manage conversation participants" }).click();
  const people = panel.getByRole("region", { name: "Conversation participants" });
  await expect(people.getByRole("heading", { name: "People" })).toBeVisible();
  await expect(people.getByText("local-development-reader")).toBeVisible();
  await people.getByRole("button", { name: "Close people panel" }).click();

  // The object is selected before Send, scanned server-side, and rendered only
  // as safe verdict metadata after the durable message exists.
  await panel.locator('input[type="file"]').setInputFiles({
    name: "bounded-note.txt",
    mimeType: "text/plain",
    buffer: Buffer.from("bounded incident note"),
  });
  await expect(panel.getByText("bounded-note.txt")).toBeVisible();
  await composer.fill("Please retain this bounded note with the thread.");
  await panel.getByRole("button", { name: "Send question" }).click();
  // The verdict is safe metadata about a durable object, and the wording says
  // what actually happened to it: scanned, then filed beside the message. It
  // was never input to the answer, and the surface no longer implies it was.
  await expect(panel.getByText("1 attachment scanned and filed to the conversation")).toBeVisible();
  await expect(panel.getByText(/text\/plain · filed to the conversation/).last()).toBeVisible();
});

test("the conversation rail can be resized from the keyboard and remembers it", async ({ page }) => {
  // Below 760px the rail takes the screen and the grip is removed: there is no
  // record left beside it to split against, so there is nothing to resize.
  test.skip((page.viewportSize()?.width ?? 0) < 900, "the rail is full-width on a narrow screen");
  await page.goto("/");
  await page.getByRole("button", { name: /Open incident workspace/ }).click();
  await page.getByRole("button", { name: "Ask the ledger" }).click();

  const rail = page.locator(".ask-rail");
  const width = async () => (await rail.boundingBox())!.width;
  const before = await width();

  // A splitter that only answers a mouse is one half the operators cannot use.
  const grip = page.getByRole("separator", { name: "Resize the ledger panel" });
  await grip.focus();
  await page.keyboard.press("ArrowLeft");
  expect(await width()).toBeGreaterThan(before);

  // The choice is per-device and survives a reload, like any display setting.
  const chosen = await width();
  await page.reload();
  await page.getByRole("button", { name: /Open incident workspace/ }).click();
  await page.getByRole("button", { name: "Ask the ledger" }).click();
  expect(Math.round(await width())).toBe(Math.round(chosen));
});

test("no queue cell overruns its column at any supported width", async ({ page }) => {
  await page.goto("/");
  await navigate(page, "Incidents");
  await expect(page.locator(".queue-table")).toBeVisible();

  // A fixed-layout table does not clip, so a nowrap badge in a narrow column
  // silently prints over its neighbour. Assert geometry, not appearance.
  for (const width of [1440, 1280, 1024, 960]) {
    await page.setViewportSize({ width, height: 900 });
    const spills = await page.evaluate(() => {
      const table = document.querySelector(".queue-table");
      if (!table) return ["missing table"];
      const found: string[] = [];
      table.querySelectorAll("tbody tr").forEach((row, rowIndex) => {
        Array.from(row.children).forEach((cell, cellIndex) => {
          const bounds = cell.getBoundingClientRect();
          cell.querySelectorAll("*").forEach((child) => {
            const inner = child.getBoundingClientRect();
            if (inner.width > 0 && inner.right > bounds.right + 0.5) {
              found.push(`row ${rowIndex} cell ${cellIndex}`);
            }
          });
        });
      });
      return found;
    });
    expect(spills, `overflow at ${width}px`).toEqual([]);
  }
});

test("patch approval is absent until a durable Reliability Case has an exact patch", async ({ page }) => {
  await page.goto("/");
  await navigate(page, "Reliability Cases");
  await expect(page.getByRole("heading", { name: "No Reliability Case yet" })).toBeVisible();
  await expect(page.locator(".patch-diff")).toHaveCount(0);
  await expect(page.getByText("Patch digest")).toHaveCount(0);
  await expect(page.getByRole("button", { name: /patch approval|Approve exact patch/ })).toHaveCount(0);
});

test("fleet governance and release evidence expose policy provenance without cloud overclaim", async ({ page }) => {
  await page.goto("/");
  await navigate(page, "Agent Fleet");
  await page.getByRole("tab", { name: "Capabilities & Policy" }).click();
  const capabilityTable = page.getByRole("table", { name: /Which Agent may reach which destination/ });
  await expect(capabilityTable).toBeVisible();
  // This asserted only that the first badge's `title` matched a lifecycle word,
  // which passed while every row wrongly read `Denied` and would have passed if
  // the logic inverted. Assert what the surface is for instead: a cell states a
  // verdict and names the authority that produced it, and opening the cell
  // shows the whole chain rather than the destination printed twice.
  const cell = capabilityTable.locator(".capability-chip").first();
  await expect(cell.locator(".status-badge")).toBeVisible();
  await expect(cell.locator(".capability-layer")).not.toBeEmpty();
  await cell.click();
  const chain = page.locator(".capability-provenance");
  await expect(chain).toBeVisible();
  await expect(chain.locator(".capability-layer-chain li")).toHaveCount(7);
  await expect(chain.locator("li.winning")).toHaveCount(1);
  await expect(chain.getByText("decided this")).toBeVisible();

  // The regression this whole surface exists to prevent. `execute_authorized_action`
  // binds no connection and so can hold no probe receipt; deriving permission from
  // probe freshness made it read `Denied` forever, asserting a control over
  // production mutation that no record supports.
  const executionRow = capabilityTable.locator("tbody tr", { has: page.getByRole("rowheader", { name: "Execution Agent" }) });
  const actuatorCell = executionRow.locator('td[data-label="solvan-actuator.internal"] .capability-chip');
  await expect(actuatorCell).toBeVisible();
  await expect(actuatorCell).not.toContainText("Denied");
  // Its connection and probe layers do not apply rather than refuse, which is
  // the distinction that stops an unprobed capability reading as a refusal.
  await actuatorCell.click();
  const actuatorChain = page.locator(".capability-provenance");
  await expect(actuatorChain.getByText("A capability that binds no connection has no external capability to probe.")).toBeVisible();
  await navigate(page, "Release Evidence");
  await expect(page.getByRole("heading", { name: "S1–S6 evidence matrix" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "PENDING_RECEIPTS" })).toBeVisible();
  await expect(page.getByText("NOT_RUN_ON_GCP")).toHaveCount(6);
  await expect(page.getByText(/No promotable bound receipt is available/)).toHaveCount(6);
});

test("incident header shows only the recovery phases actually reached", async ({ page }) => {
  await page.goto("/");
  await navigate(page, "Incidents");
  await page.getByRole("button", { name: "INC-1042" }).first().click();

  const rail = page.getByRole("list", {
    name: "Time spent in each phase of the recovery loop",
  });
  await expect(rail).toBeVisible();
  await expect(rail.getByText("Investigate")).toBeVisible();
  await expect(rail.getByText("Await approval")).toHaveCount(0);
  const current = rail.locator("li.current");
  await expect(current).toHaveCount(1);
  await expect(current).toContainText("Investigate");
  await expect(current.getByText("in progress")).toBeAttached();

  await navigate(page, "Reliability Cases");
  await expect(page.getByRole("heading", { name: "No Reliability Case yet" })).toBeVisible();
});

test("connecting an estate asks for grants to run, never for a credential", async ({ page }) => {
  await page.route("**/api/auth/step-up", async (route) => {
    const body = route.request().postDataJSON() as {
      operation: string;
      material_digest: string;
    };
    expect(body.operation).toBe("estate.connect");
    expect(body.material_digest).toMatch(/^sha256:[0-9a-f]{64}$/);
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        schema_version: 1,
        step_up_handle: "stc_01KZMEK6J01N4NZRBJM6TA38RT",
        destination: "op******@solvan.local",
        expires_in_seconds: 300,
      }),
    });
  });
  await page.route("**/api/auth/step-up/verify", async (route) => {
    expect(route.request().postDataJSON()).toEqual({
      step_up_handle: "stc_01KZMEK6J01N4NZRBJM6TA38RT",
      code: "12345678",
    });
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({ challenge: "fresh-admin-proof" }),
    });
  });
  await page.route("**/api/v1/connections/estate-grant-plan**", async (route) => {
    const requestUrl = new URL(route.request().url());
    // Planning is a read. It does not spend authority, and therefore must not
    // ask the browser for an approval token.
    expect(route.request().headers()["x-solvan-approval-token"]).toBeUndefined();
    expect(requestUrl.searchParams.get("customer_project_id")).toBe("acme-production");
    expect(requestUrl.searchParams.get("customer_reader_service_account")).toBe("solvan-reader@acme-production.iam.gserviceaccount.com");
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        posture: "FEDERATED_SHORT_LIVED",
        providers: ["CLOUD_AUDIT"],
        roles: ["roles/logging.privateLogViewer"],
        summary: "Grant short-lived impersonation of the customer-owned read-only identity.",
        secret_required: false,
        delegation_condition_digest: `sha256:${"3".repeat(64)}`,
        solvan_delegator_principal: "serviceAccount:solvan-reader@solvan.example",
        steps: [{
          purpose: "Allow the customer reader to inspect approved private audit logs.",
          command: "gcloud projects add-iam-policy-binding acme-production --member=serviceAccount:solvan-reader@acme-production.iam.gserviceaccount.com --role=roles/logging.privateLogViewer",
        }],
      }),
    });
  });
  await page.route("**/api/v1/connections/estates", async (route) => {
    const challenge = route.request().headers()["x-solvan-challenge"];
    expect(challenge).toBe("fresh-admin-proof");
    const body = route.request().postDataJSON() as {
      customer_project_id: string;
      customer_reader_service_account: string;
      providers: string[];
    };
    expect(body.customer_project_id).toBe("acme-production");
    expect(body.customer_reader_service_account).toBe("solvan-reader@acme-production.iam.gserviceaccount.com");
    expect(body.providers).toEqual(["CLOUD_AUDIT"]);
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        registered: [{
          provider: "CLOUD_AUDIT",
          connection_id: "con_01KZMEK6J01N4NZRBJM6TA38RT",
          connection_epoch: 1,
          probe_result: "SUCCEEDED",
          probe_reason_code: null,
        }],
      }),
    });
  });

  await page.goto("/");
  await navigate(page, "Integrations");
  await page.getByRole("button", { name: "Connect an estate" }).click();

  const flow = page.getByRole("region", { name: "Connect a customer estate" });
  await expect(flow.getByRole("heading", { name: "Solvan asks for grants, never for a credential" })).toBeVisible();

  // The form accepts no identity token and no customer credential. The later
  // mutation uses the signed-in session plus a one-use mailbox presence code.
  const sensitive = await flow.evaluate((root) =>
    Array.from(root.querySelectorAll("input")).map((input) => ({
      type: input.type,
      label: input.closest("label")?.textContent?.toLowerCase() ?? "",
    })),
  );
  expect(sensitive.filter((field) => field.type === "password")).toHaveLength(0);
  expect(sensitive.some((field) => field.label.includes("administrator identity token"))).toBe(false);
  expect(sensitive.some((field) => /customer.*(key|secret|token|password)/.test(field.label))).toBe(false);

  await flow.getByLabel("Customer read-only service account").fill("solvan-reader@acme-production.iam.gserviceaccount.com");
  await flow.getByLabel("Your Google Cloud project").fill("acme-production");
  await flow.getByLabel("Workload region").fill("europe-west2");
  for (const checkbox of await flow.getByRole("checkbox").all()) {
    if (await checkbox.isChecked()) await checkbox.uncheck();
  }
  await flow.getByRole("checkbox", { name: /Cloud Audit Logs/ }).check();
  await flow.getByRole("button", { name: "Show me the grants" }).click();

  // The generated command is exact, and names the role the probe would need.
  const command = flow.locator(".grant-command").first();
  await expect(command).toContainText("gcloud projects add-iam-policy-binding acme-production");
  await expect(command).toContainText("roles/logging.privateLogViewer");
  await expect(flow.getByText(/Run these once in your own project/)).toBeVisible();

  const register = flow.getByRole("button", { name: "Register and verify 1 connection" });
  // The form is intentionally tall on a phone. Dispatch the native button's
  // activation rather than making this security-flow assertion depend on
  // where a sticky mobile header leaves the emulated scroll viewport; pointer
  // and keyboard reachability are covered by the dedicated responsive tests.
  await register.evaluate((button: HTMLButtonElement) => button.click());
  const dialog = page.getByRole("dialog", { name: "Enter the code we emailed" });
  await expect(dialog).toBeVisible();

  const code = dialog.getByLabel("Verification code");
  await code.fill("12345678");
  // Submitting from the one-time-code control matches a mobile keyboard's
  // action key and avoids a browser-emulation hit-test defect where the modal
  // backdrop is incorrectly reported above its own child button.
  await code.press("Enter");
  await expect(flow.getByText("Every capability proven")).toBeVisible();
});

test("the GCP connection guide explains every field and keeps workload separate from control residency", async ({ page }) => {
  await page.goto("/?guide=gcp-connection");
  await expect(page.getByRole("heading", { name: "Connect a GCP project safely" })).toBeVisible();
  await expect(page.getByText("Administrator identity token", { exact: true })).toBeVisible();
  await expect(page.getByText("Customer read-only service account", { exact: true })).toBeVisible();
  await expect(page.getByText("Your Google Cloud project", { exact: true })).toBeVisible();
  await expect(page.getByText("Workload region", { exact: true })).toBeVisible();
  await expect(page.getByText(/It may differ from Solvan’s control-data region/)).toBeVisible();
  await expect(page.getByRole("heading", { name: "No customer secrets" })).toBeVisible();
  await page.locator("#main-content").getByRole("button", { name: "Integrations", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Integrations" })).toBeVisible();
  await page.getByRole("button", { name: "Connect an estate" }).click();
  await expect(page.getByRole("button", { name: "How to find these details and configure Google Cloud" })).toBeVisible();
});

test("the fleet shows the one seat that can mutate production beside the six that cannot", async ({ page }) => {
  await page.goto("/");
  await navigate(page, "Agent Fleet");

  // The claim used to be a paragraph above the fleet. It is now structural:
  // the actuator is a seat in the same grid, and the only one whose capability
  // is mutation. Asserting the shape rather than the sentence keeps the
  // invariant testable without pinning the prose.
  const cards = page.locator(".agent-card");
  await expect(cards).toHaveCount(7);

  const actuator = cards.filter({ hasText: "Action Actuator" });
  await expect(actuator).toHaveCount(1);
  await expect(actuator).toContainText("Not model-backed");

  // Its capability is enumerated, not described.
  await expect(actuator).toContainText("PAYMENTS_POOL_RECYCLE");
  await expect(actuator).toContainText("CLOUD_RUN_TRAFFIC_ROLLBACK");

  // Exactly one seat is not model-backed, and it is that one.
  await expect(cards.filter({ hasText: "Not model-backed" })).toHaveCount(1);

  // A deterministic seat never wears the agent tone: violet means a model is
  // executing, and this seat has no model.
  expect(await actuator.locator(".status-agent").count()).toBe(0);

  // Deployment is uniform, so it is stated once for the fleet rather than
  // repeated on every card.
  await expect(page.getByText("None is deployed", { exact: false })).toBeVisible();
  await expect(page.getByText("Implemented · not deployed")).toHaveCount(0);
});

test("integrations expose credential posture, observed capability, and the actuator boundary", async ({ page }) => {
  await page.goto("/");
  await navigate(page, "Integrations");
  await expect(page.getByRole("heading", { name: "Integrations" })).toBeVisible();

  // Graph discovery is a real target seam. Local development without a bound
  // production scope says unavailable and never substitutes its incident fixture.
  const graph = page.getByRole("region", { name: "Production Graph" });
  await expect(graph.getByRole("heading", { name: "Production Graph" })).toBeVisible();
  await expect(graph.getByText("Not discovered")).toBeVisible();
  await expect(graph.getByText(/No discovery has run/)).toBeVisible();

  // The development database is intentionally persistent, so this gate must
  // prove both valid states instead of assuming nobody has exercised estate
  // registration in the worktree. An empty projection says so explicitly; a
  // populated projection exposes one typed credential posture per connection.
  const registeredHeading = page.getByRole("heading", { name: /^\d+ registered$/ });
  await expect(registeredHeading).toBeVisible();
  const registeredCount = Number.parseInt((await registeredHeading.textContent()) ?? "", 10);
  expect(Number.isNaN(registeredCount)).toBe(false);
  const connectionCards = page.locator(".connection-grid > .connection-card");
  await expect(connectionCards).toHaveCount(registeredCount);
  if (registeredCount === 0) {
    await expect(page.getByText(/No estate is connected/)).toBeVisible();
  } else {
    for (const card of await connectionCards.all()) {
      await expect(
        card.getByText(/Federated · short-lived|Stored key · long-lived|No credential held/),
      ).toHaveCount(1);
    }
  }

  // The GitHub projection is visible but cannot grant merge authority. The
  // section is named for the source rather than for release delivery, because a
  // binding now roots investigation and conversation as well.
  await expect(page.getByRole("heading", { name: "GitHub", exact: true })).toBeVisible();
  await expect(
    page.getByText(/agents and browsers never receive a credential or merge authority/i),
  ).toBeVisible();
  await expect(
    page
      .getByText(/No GitHub repository binding is configured|solvan-demo\/payments-service/)
      .first(),
  ).toBeVisible();

  await expect(page.getByRole("heading", { name: "Solvant Relay" })).toBeVisible();
  await expect(page.getByText(/cannot receive their credentials or invoke a customer provider directly/i)).toBeVisible();

  // Mutation capability is never claimed by the control plane.
  await expect(
    page.getByRole("heading", { name: "Production capability lives here, not in Solvan" }),
  ).toBeVisible();
  await expect(page.getByText(/No actuator is registered, so nothing anywhere holds production mutation capability/)).toBeVisible();

  // No content may be clipped, and the page body must never scroll sideways.
  const overflow = await page.evaluate(() => {
    const width = document.documentElement.clientWidth;
    const visible = Array.from(document.querySelectorAll("main *")).filter(
      (element) =>
        element.getBoundingClientRect().right > width + 1 && element.closest("thead") === null,
    );
    return {
      body: document.documentElement.scrollWidth > width,
      elements: visible.length,
      clippedBadges: Array.from(document.querySelectorAll(".capability-matrix .status-badge"))
        .filter((badge) => badge.scrollWidth > badge.clientWidth + 1).length,
    };
  });
  expect(overflow).toEqual({ body: false, elements: 0, clippedBadges: 0 });
});

// These tests opt into the reviewed release projection explicitly. The normal
// browser path above remains database-backed and exercises truthful empty
// states; this projection exists only to cover UI states that require a fully
// progressed incident without making scripted data part of the product path.
test("operator overview renders the non-authoritative release fixture", async ({ page }) => {
  await useExplicitReleaseProjection(page);
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Production reliability, with proof" })).toBeVisible();
  await expect(page.getByText("No production authority")).toBeVisible();
  await expect(page.getByRole("heading", { name: /Elevated payment errors/ })).toBeVisible();
  await expect(page.getByText("Awaiting approval", { exact: true }).first()).toBeVisible();
});

test("keyboard operator can inspect and rehearse the exact approval without authority", async ({ page }) => {
  await useExplicitReleaseProjection(page);
  await page.goto("/");
  await page.getByRole("button", { name: /Open incident workspace/ }).click();
  await page.getByRole("tab", { name: "Actions" }).click();
  const review = page.getByRole("button", { name: "Review exact approval" });
  await review.focus();
  await page.keyboard.press("Enter");
  const dialog = page.getByRole("dialog");
  await expect(dialog).toBeVisible();
  await expect(dialog.getByRole("heading", { name: "Approve the exact rollback?" })).toBeVisible();
  await expect(dialog.getByText("Exact target", { exact: true })).toBeVisible();
  await expect(dialog.getByText("Digest", { exact: true })).toBeVisible();
  await expect(dialog.getByText("Verification profile", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Approve in local development" }).click();
  await expect(page.getByText("No durable approval or action authority was created.")).toBeVisible();
});

test("verification renders labelled intervals, table equivalence, and connector separation", async ({ page }) => {
  await useExplicitReleaseProjection(page);
  await page.goto("/");
  await page.getByRole("button", { name: /Open incident workspace/ }).click();
  await page.getByRole("tab", { name: "Verification" }).click();
  await expect(page.getByRole("heading", { name: /mitigation verification/ })).toBeVisible();
  const table = page.getByRole("table", { name: "Equivalent table for baseline and verification intervals" });
  await expect(table).toBeVisible();
  for (const interval of ["Healthy baseline", "Fault", "Mutation", "Warmup", "Observation"]) {
    // On narrow viewports the responsive table prefixes each cell's
    // accessible name with its data-label ("Interval Healthy baseline"), so
    // an exact role-name match finds nothing there. The label text itself is
    // what must render; assert on it directly in both layouts.
    await expect(table.getByText(interval, { exact: true })).toBeVisible();
  }
  await expect(page.getByText("The connector receipt did not decide this verdict.")).toBeVisible();
});

test("investigation map preserves plan, evidence, inference, and operator-brief provenance", async ({ page }) => {
  await useExplicitReleaseProjection(page);
  await page.goto("/");
  await page.getByRole("button", { name: /Open incident workspace/ }).click();
  await expect(page.getByText("Operator brief")).toBeVisible();
  await expect(page.locator(".operator-brief .provenance-row").getByRole("button").first()).toBeVisible();
  await page.getByRole("tab", { name: "Evidence" }).click();
  await expect(page.getByRole("heading", { name: "Investigation map" })).toBeVisible();
  await expect(page.getByText("Accepted durable plan · version 2")).toBeVisible();
  await expect(page.getByText("Confirm customer-path impact")).toBeVisible();
  await expect(page.getByText("Inferred — not validated", { exact: true })).toBeVisible();
  await expect(page.getByText(/chain[- ]of[- ]thought/i)).toHaveCount(0);
});

test("the incident axis is drawn from stored evidence and nothing else", async ({ page }) => {
  await page.goto("/");
  await page.getByRole("button", { name: /Open incident workspace/ }).click();
  await page.getByRole("tab", { name: "Evidence" }).click();
  await expect(page.getByRole("heading", { name: "Observed window" })).toBeVisible();

  // The caption states what the axis is made of: the signal, the bucket count
  // and the span. A chart that cannot say that is asserting a window.
  const figure = page.locator(".chart-block figcaption");
  await expect(figure).toContainText("HTTP_5XX_RATIO");
  await expect(figure).toContainText("15 buckets");

  // Every point is reachable by keyboard, not only by pointer.
  const firstPoint = page.locator(".chart-block .hit").first();
  await firstPoint.focus();
  await expect(firstPoint).toBeFocused();

  // The table is the equivalent the design system requires, and it carries the
  // same number of rows the caption claims.
  await page.getByRole("button", { name: /observations as a table/ }).click();
  await expect(page.locator(".chart-block tbody tr")).toHaveCount(15);

  // The axis cites the evidence it was composed from.
  await expect(page.locator(".chart-sources code").first()).toContainText("evd_");

  // The observed service revision is drawn as its own marker, named for what
  // Cloud Run reported rather than for a deployment event nobody recorded.
  await expect(page.locator(".chart-block").getByText(/^revision /)).toBeVisible();

  // The overview carries the same series as a sparkline. It is not in the
  // incident queue: that table is at its width budget and the repository
  // enforces that no cell overruns its column.
  await navigate(page, "Overview");
  await expect(page.locator(".active-incident-card .sparkline")).toBeVisible();

  // Every stat tile states its change over a named period and the trend it
  // moved along. A tile with neither is a figure with no history behind it.
  const tile = page.locator(".metric-card").first();
  await expect(tile.locator(".metric-delta")).toContainText("over 12 days");
  await expect(tile.locator(".trendline")).toBeVisible();
});

test("reliability case exposes exact patch review and calendar-separated continuity", async ({ page }) => {
  await useExplicitReleaseProjection(page);
  await page.goto("/");
  await navigate(page, "Reliability Cases");
  await expect(page.getByText("Awaiting human review")).toBeVisible();
  await expect(page.locator(".patch-diff")).toBeVisible();
  await expect(page.getByText("Patch digest")).toBeVisible();
  await expect(page.getByRole("button", { name: /Approve patch in local development|Approve exact patch/ })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Calendar-day ledger" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Day 1 · Aug 8" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Day 2 · Aug 9" })).toBeVisible();
  await expect(page.getByText("No process running · this is healthy")).toBeVisible();
});

test("overview, incident, and exact approval have no serious accessibility violations", async ({ page }) => {
  await useExplicitReleaseProjection(page);
  await page.goto("/");
  const overview = await new AxeBuilder({ page }).analyze();
  expect(overview.violations.filter((item) => ["serious", "critical"].includes(item.impact ?? ""))).toEqual([]);
  await page.getByRole("button", { name: /Open incident workspace/ }).click();
  const incident = await new AxeBuilder({ page }).analyze();
  expect(incident.violations.filter((item) => ["serious", "critical"].includes(item.impact ?? ""))).toEqual([]);
  await page.getByRole("tab", { name: "Actions" }).click();
  await page.getByRole("button", { name: "Review exact approval" }).click();
  const approval = await new AxeBuilder({ page }).analyze();
  expect(approval.violations.filter((item) => ["serious", "critical"].includes(item.impact ?? ""))).toEqual([]);
});

test("overview, incident, and pending verification have no serious accessibility violations", async ({ page }) => {
  await page.goto("/");
  const overview = await new AxeBuilder({ page }).analyze();
  expect(overview.violations.filter((item) => ["serious", "critical"].includes(item.impact ?? ""))).toEqual([]);

  await page.getByRole("button", { name: /Open incident workspace/ }).click();
  const incident = await new AxeBuilder({ page }).analyze();
  expect(incident.violations.filter((item) => ["serious", "critical"].includes(item.impact ?? ""))).toEqual([]);

  await page.getByRole("tab", { name: "Verification" }).click();
  const verification = await new AxeBuilder({ page }).analyze();
  expect(verification.violations.filter((item) => ["serious", "critical"].includes(item.impact ?? ""))).toEqual([]);
});

test("an operator can sign out, and is told so rather than silently returned", async ({ page }) => {
  // The local harness reports sign-in unavailable, so a deployment is stood in
  // for here. What is exercised is the console's half: the control is offered,
  // the server is asked to end the session, and the result is stated.
  let signedIn = true;
  await page.route("**/api/auth/session", (route) => signedIn
    ? route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ actor_id: "act_1", email: "operator@example.com", roles: ["OPERATOR"], absolute_expires_at: "2026-08-19T00:00:00Z" }) })
    : route.fulfill({ status: 401, body: "" }));
  let logoutCalls = 0;
  await page.route("**/api/auth/logout", (route) => {
    logoutCalls += 1;
    signedIn = false;
    return route.fulfill({ status: 200, contentType: "application/json", body: "{}" });
  });

  await page.goto("/");
  await shell(page).waitFor({ state: "attached" });
  await page.getByRole("button", { name: "Operator menu" }).click();
  await page.getByRole("button", { name: "Sign out" }).click();

  // Ending the session is the server's to do: the cookie is HttpOnly, so a
  // console that only dropped its own copy would leave it live for anyone
  // holding it.
  await expect(page.getByRole("heading", { name: /sign in to continue/ })).toBeVisible();
  expect(logoutCalls).toBe(1);
  await expect(page.getByText("You are signed out. Your session was ended on this device.")).toBeVisible();
});

test("the sign-in page is about Solvan, and names the provider only where it sends you", async ({ page }) => {
  // Written against a production provider, because a development host is the
  // case that made the page describe its identity provider instead of Solvan.
  await page.route("**/api/auth/session", (route) => route.fulfill({ status: 401, contentType: "application/json", body: "{}" }));

  await page.goto("/");
  // The product is named on the page; the provider only on the control.
  await expect(page.getByText("Solvan", { exact: true })).toBeVisible();
  await expect(page.getByRole("link", { name: /Continue with Google/ })).toBeVisible();
  // One control. Prose about what a session grants belongs where it is
  // enforced, not at a door where nobody has a reason to read it yet.
  await expect(page.getByRole("link")).toHaveCount(1);
  await expect(page.getByRole("textbox")).toHaveCount(0);
});

test("the sign-in page marks a provider that is not the production one", async ({ page }) => {
  // The naming rides on the refusal itself. It used to come from a separate
  // `/api/auth/mode` route, and that route's absence was what a console read as
  // "this deployment needs no sign-in" — the negotiation that informed the page
  // was also the way past it.
  await page.route("**/api/auth/session", (route) =>
    route.fulfill({
      status: 401,
      contentType: "application/json",
      body: JSON.stringify({ detail: { reason: "no session", provider: "the test identity provider", provider_is_production: false } }),
    }));

  await page.goto("/");
  // The marking is the control's own text. A note under the button is what a
  // person skimming a login page does not read; the button is what they click.
  await expect(page.getByRole("link", { name: /Continue with the test identity provider/ })).toBeVisible();
  await expect(page.getByRole("link", { name: /Continue with Google/ })).toHaveCount(0);
});

test("the sign-in page names Google when the refusal says nothing", async ({ page }) => {
  // Absent means production. A console must never present a test sign-in as the
  // real one because a field went missing, and the deployed provider is the
  // only one it may assume.
  await page.route("**/api/auth/session", (route) =>
    route.fulfill({ status: 401, contentType: "application/json", body: "{}" }));

  await page.goto("/");
  await expect(page.getByRole("link", { name: /Continue with Google/ })).toBeVisible();
  await expect(page.getByRole("link", { name: /test identity provider/ })).toHaveCount(0);
});

test("a console facing an API that serves no sign-in renders nothing", async ({ page }) => {
  // This replaces a case asserting that a console without sign-in rendered its
  // shell under a fixture reader and explained the missing sign-out. That state
  // was the hole: Terraform set none of the sign-in configuration, so the
  // deployed API reported "sign-in unavailable" and every browser that could
  // reach the console was admitted to it.
  //
  // A missing sign-in is now a broken deployment rather than a posture. The
  // console shows no records, and says which of the two it cannot tell apart.
  await page.route("**/api/auth/session", (route) => route.fulfill({ status: 404, body: "" }));

  await page.goto("/");
  await expect(page.getByRole("heading", { name: "This console cannot establish who you are" })).toBeVisible();
  await expect(shell(page)).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Operator menu" })).toHaveCount(0);
});
