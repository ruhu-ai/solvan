import { createReadStream, existsSync, statSync } from "node:fs";
import { createServer } from "node:http";
import { extname, join, normalize, resolve } from "node:path";
import { randomUUID } from "node:crypto";

const root = resolve("dist");
const port = Number.parseInt(process.env.PORT ?? "8080", 10);
const upstream = process.env.SOLVAN_API_UPSTREAM;
const audience = process.env.SOLVAN_API_AUDIENCE ?? upstream;
const githubIdentityUpstream = process.env.SOLVAN_GITHUB_IDENTITY_UPSTREAM;
const githubIdentityAudience = process.env.SOLVAN_GITHUB_IDENTITY_AUDIENCE ?? githubIdentityUpstream;
const maxRequestBytes = 1_048_576;
const tokenCaches = new Map();

const mediaTypes = {
  ".css": "text/css; charset=utf-8",
  ".html": "text/html; charset=utf-8",
  ".ico": "image/x-icon",
  ".js": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".png": "image/png",
  ".svg": "image/svg+xml",
  ".woff2": "font/woff2",
};

// Immutable caching is for content-hashed bundles only: Vite emits those under
// dist/assets. Every other file — favicons, brand assets — is unhashed and can
// change between releases, so it gets a short lifetime with revalidation
// rather than a year a returning browser will never recheck.
function cacheControlFor(file) {
  if (file.endsWith(".html")) return "no-cache";
  if (file.startsWith(`${root}/assets/`)) return "public, max-age=31536000, immutable";
  return "public, max-age=3600";
}

const securityHeaders = {
  "Content-Security-Policy": "default-src 'self'; connect-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
  "Cross-Origin-Opener-Policy": "same-origin",
  "Referrer-Policy": "no-referrer",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
};

// The host every Google client library reads for the same purpose, so a test
// can stand a stub in front of the metadata server and exercise this proxy as
// the deployed process rather than by reading its source. Unset in deployment,
// where the real metadata server answers.
const metadataHost = process.env.GCE_METADATA_HOST ?? "metadata.google.internal";

async function identityTokenForAudience(expectedAudience) {
  if (!expectedAudience) throw new Error("A service audience is required for proxying");
  const cached = tokenCaches.get(expectedAudience);
  if (cached?.expiresAt > Date.now() + 60_000) return cached.value;
  const url = new URL(`http://${metadataHost}/computeMetadata/v1/instance/service-accounts/default/identity`);
  url.searchParams.set("audience", expectedAudience);
  const response = await fetch(url, { headers: { "Metadata-Flavor": "Google" } });
  if (!response.ok) throw new Error(`metadata identity endpoint returned ${response.status}`);
  const value = await response.text();
  const payload = JSON.parse(Buffer.from(value.split(".")[1], "base64url").toString("utf8"));
  tokenCaches.set(expectedAudience, { value, expiresAt: Number(payload.exp) * 1000 });
  return value;
}

async function identityToken() {
  return identityTokenForAudience(audience);
}

// Every route the console may carry a human identity token to. The list is
// exhaustive on purpose and stays fail-closed: a path absent here is refused
// rather than forwarded, so a new command cannot quietly acquire a human
// credential channel. It previously named only the two approval routes while
// the console sent the header on alert commands, the Ask rail, relays, skills
// lifecycle, production-graph review and channels — so in the deployed
// topology every one of those refused here, before reaching the API, and the
// alert console could not be operated at all.
const humanTokenRoutes = [
  // Exact approval and review of a durable action or patch.
  /^\/api\/v1\/actions\/[^/]+:approve$/,
  /^\/api\/v1\/patches\/[^/]+:review$/,
  // Alert triage commands and operator feedback.
  /^\/api\/alerts\/[^/]+\/(?:request-retriage|request-incident-continuation|feedback)$/,
  // Conversational surface: asking, catching up, stopping a running answer,
  // and advancing a read cursor all act on a person's behalf.
  /^\/api\/v1\/liaison:ask$/,
  /^\/api\/v1\/liaison\/(?:questions|catchup)$/,
  /^\/api\/v1\/threads$/,
  /^\/api\/v1\/threads\/[^/]+\/(?:messages|read-cursor)$/,
  /^\/api\/v1\/threads\/[^/]+\/turns\/[^/]+:stop-and-send$/,
  /^\/api\/v1\/skills\/autocomplete$/,
  // Governed skills lifecycle and alert-policy simulation.
  /^\/api\/v1\/skills\/[^/]+(?:\/[^/]+)*$/,
  /^\/api\/fleet\/alert-policy-simulations$/,
  // Production graph review and promotion.
  /^\/api\/v1\/production-graph\/[^/]+\/review-material$/,
  /^\/api\/v1\/production-graph\/[^/]+:promote$/,
  /^\/api\/v1\/production-graph\/(?:status|reconciliations)$/,
  // Connections, actuators, relays and conversational channel bindings.
  /^\/api\/v1\/connections(?:\/[^/]+)*$/,
  /^\/api\/v1\/actuators(?:\/[^/]+)*$/,
  /^\/api\/v1\/direct-gcp-alert-sources$/,
  /^\/api\/v1\/direct-gcp-pilot:qualify$/,
  /^\/api\/v1\/relays(?:\/[^/]+)*(?::[a-z-]+)?$/,
  /^\/api\/v1\/channels\/(?:providers|bindings|enrollments)(?:\/[^/]+)*$/,
  /^\/api\/v1\/github\/reviewer-links(?:\/me|\/[^/]+)?$/,
  /^\/api\/v1\/code-delivery-profiles$/,
  /^\/api\/v1\/release-authority\/(?:posture|signer-keys|verifier-keys|targets)$/,
  /^\/api\/v1\/code-change-requests\/[^/]+\/decision-challenges\/(?:PR_CREATION|MERGE|DEPLOYMENT|ROLLBACK)$/,
  /^\/api\/v1\/code-change-requests\/[^/]+\/decisions$/,
  /^\/api\/v1\/code-change-requests\/[^/]+$/,
  /^\/api\/v1\/code-change-requests\/by-case\/[^/]+\/current$/,
  // GitHub connect: one-click investigate-only binding, and the per-repository
  // widening that grants anything more. Both carry a step-up challenge.
  /^\/api\/v1\/github\/installations:begin$/,
  /^\/api\/v1\/github\/installations\/[0-9]+:connect-all$/,
  /^\/api\/v1\/github\/repositories\/[^/]+\/authority$/,
  // GitHub conversation: admitting who may address Solvan on a repository, and
  // reading and deciding the exact words it proposes to publish there.
  /^\/api\/v1\/github\/conversation\/repositories\/[^/]+\/participants$/,
  /^\/api\/v1\/github\/conversation\/actions$/,
  /^\/api\/v1\/github\/conversation\/actions\/[^/]+$/,
  /^\/api\/v1\/github\/conversation\/actions\/[^/]+\/decision$/,
];

// Read routes that establish who is asking before returning scoped records.
// Every route whose handler resolves a principal from `X-Solvan-Identity-Token`
// belongs here; `tests/harness/test_console_transport_allowlist.py` derives the
// required set from the API and fails when one is missing. The Fleet
// Alert-policy reads were absent, so they would have been refused with 400
// before reaching an API that requires the header they were denied.
const identityHeaderRoutes = [
  /^\/api\/alerts(?:\/[^/]+)*$/,
  /^\/api\/fleet\/alert-policies(?:\/[^/]+\/revisions\/[^/]+)?$/,
  /^\/api\/fleet\/alert-capacity$/,
  /^\/api\/fleet\/alert-policy-templates$/,
  /^\/api\/fleet\/alert-policy-recommendations$/,
  /^\/api\/incidents\/[^/]+\/related-alerts$/,
];

function forwardableToken(value) {
  return typeof value === "string" && value.length <= 16_384 && !/[\r\n]/.test(value);
}

async function proxyApi(request, response, options = {}) {
  const selectedUpstream = options.upstream ?? upstream;
  const selectedAudience = options.audience ?? audience;
  if (!selectedUpstream || selectedUpstream === "DISABLED") {
    response.writeHead(503, securityHeaders).end("API upstream is not configured");
    return;
  }
  const target = new URL(request.url, selectedUpstream);
  const approvalToken = request.headers["x-solvan-approval-token"];
  // Named for the reader it carries, not for the header. `identityToken` shadowed
  // the workload-token function declared above, so `await identityToken()` below
  // called a request header, every proxied API request threw
  // `identityToken is not a function`, and the listener's catch turned it into a
  // bare 502. The deployed console could not reach the API on any route at all —
  // and a 502 is also what an unreachable upstream returns, so the transport
  // exercise that recorded 502 read the crash as a successful forward.
  const readerToken = request.headers["x-solvan-identity-token"];
  const approvalRoute = humanTokenRoutes.some((route) => route.test(target.pathname));
  if (approvalToken !== undefined && (!approvalRoute || !forwardableToken(approvalToken))) {
    response.writeHead(400, securityHeaders).end("Invalid approval identity token transport");
    return;
  }
  const identityRoute = identityHeaderRoutes.some((route) => route.test(target.pathname));
  if (readerToken !== undefined && (!identityRoute || !forwardableToken(readerToken))) {
    response.writeHead(400, securityHeaders).end("Invalid reader identity token transport");
    return;
  }
  // Cloud Run authenticates the console workload at the service boundary.
  // The one-time human token is distinct application-layer approval evidence.
  const token = await identityToken();
  const upstreamToken = selectedAudience === audience
    ? token
    : await identityTokenForAudience(selectedAudience);
  const chunks = [];
  let requestBytes = 0;
  for await (const chunk of request) {
    requestBytes += chunk.length;
    if (requestBytes > maxRequestBytes) {
      response.writeHead(413, securityHeaders).end("Request body is too large");
      return;
    }
    chunks.push(chunk);
  }
  const body = chunks.length === 0 ? undefined : Buffer.concat(chunks);
  const proxyHeaders = {
    Authorization: `Bearer ${upstreamToken}`,
    Accept: request.headers.accept ?? "application/json",
    "X-Trace-Id": request.headers["x-trace-id"] ?? randomUUID().replaceAll("-", ""),
  };
  if (approvalToken !== undefined) proxyHeaders["X-Solvan-Approval-Token"] = approvalToken;
  if (readerToken !== undefined) proxyHeaders["X-Solvan-Identity-Token"] = readerToken;
  // The session is an HttpOnly cookie the browser holds against this origin.
  // Carrying it only on the OAuth handshake meant the deployed console could
  // establish a session and then never present it: every later request arrived
  // unauthenticated, so `/api/auth/session` answered 401 forever and the
  // console showed a sign-in page to somebody who had just signed in.
  if (typeof request.headers.cookie === "string") {
    proxyHeaders.Cookie = request.headers.cookie;
  }
  // `x-solvan-csrf` is the double-submit token and `x-solvan-challenge` is the
  // one-use handle authorizing a single operation. Both are compared upstream,
  // so dropping them here refused every mutation with 403 before it arrived.
  for (const name of [
    "content-type",
    "idempotency-key",
    "if-match",
    "x-solvan-csrf",
    "x-solvan-challenge",
  ]) {
    const value = request.headers[name];
    if (typeof value === "string") proxyHeaders[name] = value;
  }
  const proxied = await fetch(target, {
    method: request.method,
    headers: proxyHeaders,
    body,
    redirect: "manual",
  });
  const headers = { ...securityHeaders };
  const contentType = proxied.headers.get("content-type");
  if (contentType) headers["Content-Type"] = contentType;
  const traceId = proxied.headers.get("x-trace-id");
  if (traceId) headers["X-Trace-Id"] = traceId;
  // `getSetCookie` rather than `get`: the callback sets the session and the
  // double-submit token together, and `get` joins repeated headers with a
  // comma — which is also legal inside a cookie's `Expires`, so the browser
  // receives one malformed cookie instead of two good ones.
  const setCookies = proxied.headers.getSetCookie();
  if (setCookies.length > 0) headers["Set-Cookie"] = setCookies;
  // The sign-in flow is a chain of redirects. Dropping `Location` left the
  // browser holding a 303 with nowhere to go, so sign-in could not start.
  const location = proxied.headers.get("location");
  if (location) headers.Location = location;
  headers["Cache-Control"] = "no-store";
  response.writeHead(proxied.status, headers);
  response.end(Buffer.from(await proxied.arrayBuffer()));
}

function serveStatic(request, response) {
  // `decodeURIComponent` throws on a malformed escape such as `/%zz`. This runs
  // inside the request listener, so an uncaught throw here ended the process:
  // one unauthenticated malformed path took the console down.
  let requestPath;
  try {
    requestPath = decodeURIComponent(new URL(request.url, "http://localhost").pathname);
  } catch {
    response.writeHead(400, securityHeaders).end("Invalid path");
    return;
  }
  const relative = normalize(requestPath).replace(/^\/+/, "");
  let file = resolve(join(root, relative));
  if (!file.startsWith(`${root}/`) && file !== root) {
    response.writeHead(400, securityHeaders).end("Invalid path");
    return;
  }
  if (!existsSync(file) || !statSync(file).isFile()) file = join(root, "index.html");
  response.writeHead(200, {
    ...securityHeaders,
    "Cache-Control": cacheControlFor(file),
    "Content-Type": mediaTypes[extname(file)] ?? "application/octet-stream",
  });
  // An unreadable file must not take the process down: createReadStream
  // reports EACCES/ENOENT asynchronously on the stream, outside the request
  // listener's try/catch, and an unhandled "error" event exits Node. A 500 is
  // the honest answer; the request listener's catch cannot see this failure.
  createReadStream(file)
    .on("error", () => {
      if (!response.headersSent) response.writeHead(500, securityHeaders);
      response.end("Console asset unavailable");
    })
    .pipe(response);
}

const server = createServer((request, response) => {
  const requestPath = new URL(request.url ?? "/", "http://localhost").pathname;
  const githubIdentityPath =
    requestPath === "/github/oauth/callback" ||
    /^\/api\/v1\/github\/reviewer-links(?:\/me|\/[^/]+)?$/.test(requestPath);
  if (githubIdentityPath) {
    proxyApi(request, response, {
      upstream: githubIdentityUpstream,
      audience: githubIdentityAudience,
    }).catch(() => {
      if (!response.headersSent) response.writeHead(502, securityHeaders);
      response.end("GitHub identity service unavailable");
    });
    return;
  }
  if ((request.url ?? "").startsWith("/api/")) {
    proxyApi(request, response).catch(() => {
      if (!response.headersSent) response.writeHead(502, securityHeaders);
      response.end("Projection API unavailable");
    });
    return;
  }
  // A static read is synchronous, but no request path may take the process
  // down: the proxy already had this guarantee and the static handler did not.
  try {
    serveStatic(request, response);
  } catch {
    if (!response.headersSent) response.writeHead(500, securityHeaders);
    response.end("Console asset unavailable");
  }
}).listen(port, "0.0.0.0");

for (const signal of ["SIGTERM", "SIGINT"]) {
  process.once(signal, () => {
    server.closeIdleConnections();
    server.close((error) => {
      process.exitCode = error ? 1 : 0;
    });
  });
}
