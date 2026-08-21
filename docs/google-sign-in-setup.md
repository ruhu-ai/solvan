# Configuring Google sign-in

Status: required contract
Governing record: [specification 05 §4.2](../specs/05-security-governance.md)

Google is the only issuer of human identity for Solvan. Every environment has
its own OAuth client, owned by that environment's Google Cloud project, and the
API refuses to start with Google Cloud authority unless one is configured.

This is what to create, and what to set once it exists.

## 1. Create the OAuth client

In the Google Cloud console, in **this environment's own project**:

1. **APIs & Services → OAuth consent screen.** Choose **Internal** if only your
   own Workspace signs in. Internal restricts sign-in to your Workspace at
   Google, which is a control you do not then have to enforce yourself. Choose
   External only when accounts outside your Workspace must sign in — then domain
   admission moves entirely to `admitted_workspace_domains`, and it is the only
   thing standing between a verified Google account and the door.
2. Scopes: `openid`, `email`, `profile`. Nothing else. Solvan requests no
   offline access, no refresh token, and no Google API scope, so a stolen
   session cannot be exchanged for someone's mail, drive, or calendar. Adding a
   scope here changes what a compromise costs.
3. **Credentials → Create credentials → OAuth client ID → Web application.**
   Web application, not Desktop: the code is exchanged by the backend using a
   client secret, and a Desktop client is a public client with no secret to
   hold.
4. **Authorised redirect URIs** — the console origin followed by
   `/api/auth/callback`, and nothing else:

   | Environment | Redirect URI |
   | --- | --- |
   | Deployment | `https://<console-service-url>/api/auth/callback` |
   | Local development | `http://127.0.0.1:<console-port>/api/auth/callback` |

   The callback lands on the **console**, which proxies it to the API. Pointing
   it at the API's own origin works locally only because cookies ignore ports,
   and cannot work in a deployment where the two are different hosts.

Google matches redirect URIs exactly. This worktree's console port is derived
from its path, so pin it before registering:

```sh
scripts/dev-env --shell            # shows this worktree's SOLVAN_CONSOLE_PORT
export SOLVAN_CONSOLE_PORT=30162   # then register that exact port with Google
```

## 2. Configure it

Local development — put these in `.env`, which is gitignored and which
`scripts/start` loads. Setting `SOLVAN_APPROVAL_AUDIENCE` is what switches the
harness off the test fixture and onto real Google:

```sh
cp .env.example .env    # then fill in the four values below
```

```ini
SOLVAN_CONSOLE_PORT=30162
SOLVAN_APPROVAL_AUDIENCE=<client-id>.apps.googleusercontent.com
SOLVAN_OAUTH_CLIENT_SECRET=<client-secret>
SOLVAN_ADMITTED_DOMAINS=ruhu.ai
SOLVAN_FOUNDING_ADMINISTRATOR=founder@ruhu.ai
SOLVAN_OPERATOR_STEP_UP_EMAIL_RELAY_URL=https://<private-email-relay>
SOLVAN_OPERATOR_STEP_UP_PEPPER=<at-least-32-random-bytes>
```

An explicit `export` wins over the file, so a one-off run can override any of
them without editing it. Run `scripts/start` and the fixture no longer starts.

Deployment — in `production.tfvars`:

```hcl
approval_token_audience      = "<client-id>.apps.googleusercontent.com"
oauth_client_secret_name     = "<secret-manager-secret-name>"
operator_step_up_email_relay_url    = "https://<private-email-relay>"
operator_step_up_pepper_secret_name = "<secret-manager-secret-name>"
admitted_workspace_domains   = ["ruhu.ai"]
founding_administrator_email = "founder@ruhu.ai"
```

The OAuth client secret and operator step-up pepper are separate Secret Manager
references under this environment's own project, never values in a variables
file and never downloaded key files. The pepper contains at least 32 random
bytes. The email relay is private and grants invocation to the API service
account; it returns a delivery receipt and never writes the code into Solvan's
conversation ledger.

## 3. The first sign-in

Admission is three separate things, and only the first two come from Google:

1. Google proves **who** somebody is.
2. `admitted_workspace_domains` decides whose accounts are **eligible**.
3. An explicit membership decides who is actually **admitted**. Eligibility is
   not admission — otherwise onboarding one colleague would admit their whole
   company.

That leaves a bootstrap problem: an invitation must be authored by an
administrator, and a new environment has none. `founding_administrator_email`
closes exactly that. On its first sign-in that one account is granted ADMIN, and
only while the environment has no administrator at all. Once anybody holds ADMIN
it can never grant again — so it cannot be used to regain access after a removal,
and changing it later grants nothing.

Everyone after the first is invited from **Settings → Operator access**. Each
invitation freezes the exact grant, emails the already signed-in administrator
a five-minute one-use code, rotates the session after the code is verified, and
authorizes only the grant that was shown. Google remains the identity issuer;
the code proves recent mailbox possession and cannot sign anybody in.

## Refusals you should expect

These are correct behaviour, not faults:

- *"This deployment carries Google Cloud authority and cannot sign anybody in"* —
  the API refused to start because a setting above is missing. It names each one.
- *"This account is verified but holds no access to this environment"* — Google
  proved the identity and no membership exists. Invite them.
- *"redirect_uri_mismatch"* from Google — the registered URI is not the console
  origin's `/api/auth/callback`, or the worktree port moved.
