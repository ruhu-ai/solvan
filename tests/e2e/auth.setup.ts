/** Sign in once, and let every case run as a real operator.
 *
 *  The console requires an identity before it renders, so a suite that did not
 *  authenticate would test the sign-in screen ninety times over. This performs
 *  the genuine flow — Solvan's login, the provider's account picker, the
 *  callback — and saves the session for the projects that follow.
 *
 *  It is a real sign-in, not an injected cookie: the session under test is one
 *  the server actually issued, so an expiry, a revocation, or a broken callback
 *  fails here rather than passing behind a fabricated credential.
 */
import { expect, test as setup } from "@playwright/test";

const SESSION_STATE = "tests/e2e/.auth/operator.json";

setup("sign in as a development operator", async ({ page }) => {
  await page.goto("/");

  // Unconditional. There used to be a branch here for a deployment that offered
  // no sign-in, because the console rendered its shell for one — which is the
  // hole this suite would have had to reproduce to catch. A console now shows
  // the shell only to a session it was actually issued, so reaching it means
  // signing in, every time.
  const signIn = page.locator(".sign-in-action");
  await expect(signIn).toBeVisible();
  await signIn.click();
  await page.locator("form button").first().click();

  await page.getByRole("navigation", { name: "Primary" }).waitFor({ state: "attached" });
  await page.context().storageState({ path: SESSION_STATE });
});
