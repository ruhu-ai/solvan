import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

/** The console is one origin, in development exactly as in deployment.
 *
 *  Deployed, `apps/console/server.mjs` serves the assets and proxies `/api` to
 *  the API service. Development used to skip the proxy and call the API's own
 *  origin directly, which meant the session transport under test was not the
 *  one that ships: cookies, the double-submit token and the OAuth callback all
 *  behaved differently, and only the untested arrangement was deployed.
 *
 *  Locally the two origins differ only by port, and cookies ignore ports, so
 *  the direct arrangement appeared to work while the deployed one could not.
 *  This proxy removes the difference rather than the symptom.
 */
export default defineConfig(({ command }) => {
  // Every worktree serves the API on a port derived from its own path, so there
  // is no default worth guessing. A guessed default is worse than none here: it
  // pointed at a port nothing was listening on, and every request through the
  // proxy became a 500 that read as "the API could not be reached" rather than
  // as "this console was started without being told where the API is".
  const apiOrigin = process.env.SOLVAN_API_ORIGIN;
  if (command === "serve" && !apiOrigin) {
    throw new Error(
      "SOLVAN_API_ORIGIN is required to serve the console, so that /api resolves to " +
        "this worktree's API. scripts/start exports it; a bare `vite` does not.",
    );
  }
  return {
    plugins: [react()],
    server: {
      strictPort: true,
      proxy: {
        "/api": {
          target: apiOrigin ?? "",
          // The sign-in flow is a chain of redirects the browser must follow
          // itself, so the proxy hands them back rather than resolving them.
          autoRewrite: false,
          followRedirects: false,
        },
      },
    },
  };
});
