# Governed GitHub conversation

Status: implementation in progress. This specification governs the
conversational GitHub surface — bounded issue, comment, search, and commit
reads; mention and label ingestion; and the three approval-gated publications
Solvan may make to a repository. The governed code-change and release path in
[implementation and deployment](07-implementation-deployment.md) is unchanged
and remains a separate authority path. This wording is not a production or
customer deployment receipt.

Related: [tenant integration](13-tenant-integration.md),
[security](05-security-governance.md),
[governed Tool Catalog](16-governed-tool-catalog.md),
[data, events, API](04-data-event-api.md),
[conversational surface](14-conversational-surface.md),
[target DDL](artifacts/github-conversation-schema.target.sql).

## 1. Scope

A repository binding may be granted, independently of any code-change
authority, the ability to take part in a repository's conversation: to read its
issues and pull-request threads, to be addressed by a mention or a label, and
to publish a bounded reply.

This is a distinct capability from code delivery. A binding that may comment
cannot thereby open a branch, and a binding that may merge does not thereby
gain a voice in a thread. The two allowlists are separate entries in the same
`allowed_operations` array, and each operation is admitted on its own.

## 2. Operations

Three publication operations join the existing code-delivery kinds:

| Operation | Effect | Body source |
| --- | --- | --- |
| `CREATE_ISSUE` | `POST /repos/{o}/{r}/issues` | claim template registry |
| `POST_ISSUE_COMMENT` | `POST /repos/{o}/{r}/issues/{n}/comments` | claim template registry |
| `SUBMIT_PULL_REQUEST_REVIEW` | `POST /repos/{o}/{r}/pulls/{n}/reviews` | claim template registry |

Four read capabilities join the existing bounded reads: repository and issue
search, one issue or pull-request thread with its comments, commit history
filtered by author and date, and a blob-verified file tree at a pinned commit.

### 2.1 `APPROVE` is not an available review event

`SUBMIT_PULL_REQUEST_REVIEW` accepts `COMMENT` and `REQUEST_CHANGES`. It
refuses `APPROVE` in the contract and again in the provider before the request
body is constructed.

The merge gate in `code_change_merge` admits a merge only when GitHub's
authoritative `reviewDecision` is `APPROVED` **and** the approving account's
node ID matches a linked human reviewer binding. If Solvan could publish an
approving review, it could satisfy its own merge precondition through its own
App identity. The refusal is what keeps the human in that gate, so it is not
configurable and no policy value may enable it.

## 3. Published text is rendered, never authored

Every published body is composed through the claim-template registry
(§7 of [conversational surface](14-conversational-surface.md)). The model
supplies a template id, a subject reference, and typed slot values. The
application:

1. resolves the template from the digest-pinned registry, which owns the claim
   kind, polarity, and sentence form;
2. resolves every record-bound slot by reading the cited record, discarding
   whatever the model supplied for it;
3. evaluates the template's predicate in code against the cited records;
4. renders the sentence, or replaces it with its holding form, or withholds it.

The composed body is stored with its `body_hash` and the registry digest that
produced it. A published body whose registry digest is not the pinned one is
refused, so a template edit cannot reach a repository without a reviewed pin
change in the same commit.

A conversational action carries at most one `MODEL_QUOTED` slot, and only
through a template whose predicate verifies that quote against a stored record.
A held template may carry none, unchanged from §7.

## 4. Who may address Solvan

Inbound mention and label events name a sender. A sender is not an authority.

`github_conversation_participants` records, per repository binding, which
GitHub logins may cause Solvan to act. The set denies by default: a binding
with no participant rows takes no action on any inbound event. An event from an
unlisted login is persisted with `admission = 'PARKED'` and projected to the
console for an operator to admit or dismiss; it never reaches an agent and
never carries authority.

Admission is per binding, not per account. A login admitted on one repository
has no standing on another, because GitHub logins are global while the decision
to let someone direct Solvan's attention is not.

An unadmitted sender's event is still projected — an operator cannot decide
who may address Solvan without seeing who is asking — but the thread records
`trigger_kind = 'NONE'`. The event is a sighting, not an address, and nothing
downstream can read an instruction out of it. Admission is checked in code, on
the ingest path, rather than being a property of the projection's absence.

There is no `allow_all` setting. An earlier draft of this section offered one,
described as admitting a sender's event into a thread projection without
granting anything further. That description could not hold: the projection is
written unconditionally, so the flag had nothing to widen except *acting* —
the one thing it was said not to widen. A permissive configuration value
guarding an authority decision is what this system refuses everywhere else, so
it has no column, no reader, and no parameter. Passing the gate does not
authorize a publication either: every publication passes §5 regardless of who
triggered it.

## 5. Approval

A publication is proposed, approved, and only then dispatched.

1. An agent returns a typed conversational proposal. It performs no mutation.
2. The coordinator records a `github_conversation_actions` row in state
   `APPROVAL_PENDING` holding the composed body, its hash, the registry digest,
   the target thread, and the immutable proposal hash.
3. An operator holding `CODE_CHANGE_APPROVER` decides against material that
   includes the exact rendered body. The material digest binds the body: an
   edited body invalidates the approval.

   The role is checked in the deciding transaction, against
   `solvan.actor_role_bindings` in this scope, and not at the API edge. A
   verified Google identity establishes *who* is asking and never that they
   may: a deployment mints approval tokens for more people than it grants this
   role to. Checking it in the store also means the role is revalidated
   against the moment of decision rather than the moment the page loaded, and
   that no later caller of these store methods can reach a decision without
   it. Admitting or dismissing a participant (§4) takes the same role, because
   letting someone direct Solvan's attention is the same class of decision.
4. On approval the coordinator creates the private command and dispatches it to
   the GitHub Provider, which revalidates the thread state and the body hash
   before constructing any request.

An approval is single-use and bound to one action row. A second dispatch of the
same action is refused by the idempotency key, not by convention.

## 6. Revalidation before publication

Before the provider constructs a publication request it re-reads the target and
refuses on any of:

- the thread is locked, or its state changed from the approved observation;
- the issue or pull request was closed after approval, for comment operations
  that were approved against an open thread;
- for a review, the pull request head SHA moved from the approved head, or the
  pull request merged after approval. This requires its own read: `GET
  /issues/{n}` serves pull requests but carries no head, so the provider reads
  `GET /pulls/{n}` as well. Passing `commit_id` is not sufficient on its own —
  GitHub accepts a `commit_id` that is any commit of the pull request and files
  the review as outdated, so a request for changes could land against code the
  author has already replaced and read as a live objection;
- the composed body hash differs from the approved body hash;
- the template registry digest differs from the pinned digest.

There is no dry-run for a comment, because a comment has no observable
pre-state to compare. Revalidation is the control. Publication is recorded with
its external comment or review ID so the operation is reconciled exactly once.

## 7. Rate limits

GitHub's documented primary and secondary rate limits apply to this surface far
more than to code delivery, because mention-triggered work is driven by outside
parties. The provider reads `X-RateLimit-Remaining` and `Retry-After` and
surfaces exhaustion as `PROVIDER_RATE_LIMITED`, which is a retryable
pre-issue outcome. A rate-limited publication is never partially applied: it
has either an external ID or none.

## 8. Inbound deliveries are routed by what they name

One GitHub App has one webhook URL, and every repository the App is installed
on delivers to it. Which binding a delivery belongs to is therefore a property
of the delivery, not of the receiving deployment's configuration.

The provider authenticates the delivery first — HMAC-SHA256 over the exact
bytes, no SHA-1 accepted — and only then reads the repository owner and name
out of the now-trusted payload and resolves them to a binding in this scope.
The identity is a lookup key and never authority: a delivery naming a
repository nobody bound is refused rather than binding one implicitly, and the
resolved binding's own owner, name, and installation are checked against the
envelope before the event is accepted.

Binding status is deliberately not filtered. A binding is written `PENDING`
and promoted only by the provider's own observation, so filtering on `ACTIVE`
would drop exactly the deliveries that arrive first.

Taking the binding from deployment configuration instead is not merely
incomplete, it degrades: every repository but the configured one has its
deliveries rejected, and GitHub disables a webhook that fails often enough —
which then costs the one repository that worked.

## 9. Connecting is one continuous flow

An operator begins an installation in the console, installs the App on
GitHub's own screen, and lands back in the console with the repositories
connected. GitHub carries them back with a redirect, and that redirect is an
ordinary browser GET: no CSRF header, no step-up challenge, and its one
interesting parameter, `installation_id`, is a number anybody can type.

So the authority is established before the operator leaves and carried across
as an opaque state.

1. `POST /installations:begin` spends a `github.bind` step-up challenge and
   mints one intent in `github_installation_intents`. Only the state's digest
   is stored: the state is a bearer value for the few minutes it lives, and a
   table holding it would let any reader of that table finish somebody else's
   installation.
2. The operator installs on GitHub, which returns the state unchanged.
3. `GET /installations/callback` claims the intent, verifies the
   `installation_id` against `GET /app/installations`, and binds every
   repository the installation reaches as investigate-only.

The challenge material names the authority and the classification but
deliberately not the account: which account to install on is chosen on
GitHub's screen after the challenge is spent, and is shown to the operator
there. A bulk install is never classified `RESTRICTED`, because that is a
judgement about one repository rather than about everything an installation
happens to reach.

Two properties make a forged redirect uninteresting rather than dangerous. The
state must match an intent this deployment minted, and `installation_id` is a
selector verified against GitHub rather than a fact, so a guessed number can at
most select a real installation of our own App — which is what the operator was
about to do anyway. Absent, expired, and already-spent links return one
identical outcome, because distinguishing them would make the endpoint an
oracle for valid states.

### 9.1 An intent is spent when it is presented

The intent moves `PENDING → CLAIMED` in a single conditional UPDATE at the
moment the redirect presents it — not when the installation it started
finishes. The two are minutes apart in the worst case and two GitHub round
trips apart in the ordinary one, and an intent left pending across that gap is
a link that still works: a double click, a browser link prefetch, or a GitHub
delivery retry would claim it a second time and race the first to create the
same bindings.

`CLAIMED → CONSUMED` records what the installation produced; `→ REFUSED`
records why it did not. An intent claimed by a request that then dies stays
`CLAIMED` and is never replayable, which is the direction to fail in: the
operator starts again and no unattended link survives.

The unique index on `state_hash` is not what provides this. It prevents the
same state being *minted* twice, which for a 32-byte random value does not
happen, and says nothing about the same state being *presented* twice.

## 10. What this surface may not do

- It may not push, force-push, delete a branch, or change repository settings.
- It may not approve a pull request (§2.1).
- It may not close, reopen, or lock a thread; `CLOSE_PULL_REQUEST` remains a
  declared operation kind with no implementation.
- It may not deliver a credential, token, or working copy to a workspace or
  model process. A repository's files reach an agent only through the
  blob-verified bounded tree read, which returns content and no authority.
- It may not publish a body the registry did not render.
