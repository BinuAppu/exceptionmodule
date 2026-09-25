# Security, AI boundaries, and risk review

## 1. Status and security objectives

This is a control specification and static baseline review, not a penetration-test report, ASVS certification, or production security approval. Source artifacts were available for review, but no executed or release-linked security evidence was supplied.

Security objectives, in priority order:

1. Only an active, authorized workforce identity can access protected data.
2. No requester can self-approve, and no UI/client assertion can override backend authorization.
3. Untrusted files and text cannot execute, escape quarantine, or trigger an external service.
4. AI output cannot grant authority, change workflow, invoke tools, or disclose data.
5. Security-relevant actions are attributable, append-only, tamper-evident, and exportable.
6. Failure of email, AI, scanner, or one worker does not create an unauthorized approval or lose an accepted domain transaction.
7. Secrets and sensitive content do not enter source, browser storage, ordinary logs, URLs, or notification bodies.

Target baseline: OWASP ASVS Level 2 controls, with Level 3 or equivalent added wherever risk classification, privileged operations, regulated data, or tenant isolation requires it. The exact ASVS release and requirement versions must be frozen in the release evidence.

## 2. Authentication architecture

### Normal workforce login

```mermaid
sequenceDiagram
    autonumber
    participant B as Browser
    participant A as FastAPI
    participant S as Server-side session/pending-login store
    participant E as Entra ID
    participant D as PostgreSQL

    B->>A: GET /api/v1/auth/login
    A->>S: Create state, nonce, PKCE verifier, return URL, expiry
    A-->>B: 302 to pinned Entra authorize endpoint
    B->>E: Authorization request + challenge
    E-->>B: Authorization code/state
    B->>A: GET callback + code/state
    A->>E: Back-channel code + verifier exchange
    E-->>A: Validated ID/access-token material
    A->>A: Verify signature, alg, iss, aud, tenant, exp/iat, nonce
    A->>D: Resolve/validate internal user and current role assignments
    A->>S: Consume pending login; create hashed opaque session
    A-->>B: Host-only Secure HttpOnly cookie + allowlisted redirect
```

### OIDC controls

Static gap: `begin_oidc_login()` creates state and nonce but does not visibly create a PKCE verifier/challenge, and `complete_oidc_login()` has no explicit tenant-claim pin. First login grants only the seeded `user` role; no reviewed Entra app-role/group-to-permission mapping was observed. These are production blockers, not assumed implementation details.

- Use Authorization Code flow with `S256` PKCE. Reject `plain`, unsupported algorithms, missing PKCE, implicit response, and hybrid tokens.
- Generate cryptographically random, single-use state and nonce. Store a hash or protected server-side pending-login record with a short expiry and one-time consumption.
- Pin exact issuer, tenant, client ID, redirect URI, and allowed response/type values. Discover metadata only from the configured trusted issuer and protect discovery from substitution.
- Validate cryptographic signature, approved algorithm, issuer, audience, authorized party/client ID, tenant, nonce, `exp`, `iat` with bounded clock skew, and authorized party where supported.
- Do not use an unverified email/profile claim as identity. The stable key is issuer plus subject (`sub`), mapped to a local user. Local account disabled/deleted state overrides token eligibility.
- Map only an allowlisted set of Entra app roles or verified group identifiers to internal permissions. Provider-issued role names are not accepted directly from arbitrary groups.
- Resolve group overage through an approved server-side mechanism if groups are used. Cache only for a bounded period, recheck on privilege-sensitive actions, and audit mapping/version.
- Normal UI never accepts a password. OIDC failure does not trigger local break-glass or a “development” fallback.
- Local logout revokes the server session. OIDC front-channel/back-channel logout is additional and must not be the only local revocation mechanism.
- Use Conditional Access, MFA, device/user policy, sign-in risk, and lockout controls in Entra; the application still validates the resulting token and its own session.

## 3. Opaque sessions, CSRF, and request integrity

- Generate at least 256 bits of entropy for the session secret using a cryptographically secure random source. Encode without ambiguous semantics and never derive it from user data.
- Store a keyed hash of the session secret, account, creation/expiry/revocation, and security context. The raw secret exists only in the host-only cookie and browser transport.
- Cookie: `Secure`, `HttpOnly`, approved `SameSite`, narrow `Path`, approved name without identity leakage, no `Domain` wildcard. Never store it in local/session storage, JavaScript-readable cookies, URLs, or logs.
- Apply absolute and idle expiry approved by the identity/security owner. Rotate on login, authentication-context change, and step-up. Revoke on logout, account disablement, role revocation that invalidates the context, and incident response.
- Scope the session to the correct environment/host and invalidate sessions across secret/cookie policy changes. Do not encode permissions in the opaque token.
- Require a cryptographically random anti-CSRF token bound to the server-side session for all state-changing browser requests. Deliver it through a protected response/session bootstrap, require a custom header, and compare in constant time. SameSite cookies are defense in depth, not the sole control.
- Validate `Origin`/`Referer` where reliable and enforce CORS allowlists. CSRF validation must also apply to login, callbacks with state, and break-glass actions as appropriate.
- Do not use GET, redirect, or callback query parameters for state-changing operations. Authorization codes, state, and nonce are short-lived and single-use.
- Protect session/break-glass state changes with rate limits, generic errors, and monitoring. Avoid revealing whether an account exists.

## 4. Separate local break-glass administrator

Break-glass is a controlled emergency recovery path, not a second routine sign-in method.

### Mandatory design

- Use a distinct route, identity record, UI entry point, credential verifier, session namespace/audience, audit event family, and operational owner from Entra authentication.
- Bind it to loopback or an explicitly approved hardened local/admin interface. Normal public ingress and network proxies must not expose it. Production configuration defaults to disabled.
- No default/shared password, environment fallback, hard-coded hash, or “if IdP unavailable” branch. Bootstrap material comes from an approved secret-management process and is rotated after use.
- Require a unique named identity, phishing-resistant MFA where feasible, managed local password hashing (Argon2id preferred), lockout/rate limits, short absolute session, idle timeout, step-up for high-risk actions, and immediate revocation/alerting.
- Recommend dual control: one operator authenticates while a second authorized responder enables the local path/approves sensitive operations. If policy permits single control, record the accepted risk and expiry.
- Scope permissions narrowly by default. Do not grant request approval, audit modification, raw secret export, storage bypass, or unrestricted SQL merely because the account is an administrator.
- Audit every attempt, failure, enablement, login, MFA challenge, session creation, action, denial, logout, and credential rotation. Emit an immediate independent alert. Link use to an incident/change record.
- After use: revoke all sessions, rotate affected credentials, review privileged actions and audit-chain continuity, remediate the cause, and close/retire the path. Recompile/redeploy from trusted source if local binaries/config may have changed.

The security and operations owners must approve the break-glass procedure. Until then, `IAM-09` remains open.

## 5. Authorization model

### Role-permission intent

`R` = normally allowed, `S` = scoped/conditional, `—` = denied. “Administrators” does not imply final decision authority.

| Capability | Requester | Reviewer | Approver | Auditor | Administrator | Break-glass |
|---|---:|---:|---:|---:|---:|---:|
| Create own draft | R | S | S | — | S | — |
| Read own request | R | S | S | R | S | S |
| Read assigned/all request | — | S | S | S | S | S |
| Upload own evidence | S | S | — | — | — | — |
| Submit/withdraw own | S | — | — | — | — | — |
| Start review/request changes | — | S | S | — | — | — |
| Recommend/comment | S | S | S | — | — | — |
| Approve/reject/revoke | — | — | S | — | — | — |
| Read audit/export | — | — | — | S | S | S |
| Manage policy metadata | — | — | — | — | S | S |
| Manage role assignments/users | — | — | — | — | S | S |
| Change/delete audit | — | — | — | — | — | — |
| Download clean evidence | S | S | S | S | S | S |
| Replay/DLQ outbox job | — | — | — | — | S | S |
| Release unscanned/blocked evidence | — | — | — | — | — | — |

### Enforcement rules

1. **Deny by default:** each route/action maps to a stable permission and object scope. Unmapped methods/actions fail closed.
2. **Backend enforcement:** frontend route/menu checks are usability only. Tests call APIs with each role directly.
3. **Object-level authorization:** request, attachment, transition, advice, audit, and export IDs are checked against account, assignment, classification, and action every time.
4. **Field-level authorization:** serializers use allowlists by permission; clients cannot request arbitrary ORM columns. Sensitive fields are omitted, not merely hidden in UI.
5. **Function-level authorization:** review, approve, revoke, admin, break-glass, AI, scan, and replay endpoints have distinct permissions.
6. **State-aware authorization:** role membership alone cannot bypass workflow state, expiry, request version, evidence requirements, or separation of duties.
7. **Separation of duties:** requester cannot be final decision actor. Enforce in the service and preferably with database constraints or transactionally checked assignment data.
8. **Step-up:** approval, revocation, role changes, break-glass use, audit export, and other approved high-risk actions require recent strong authentication.
9. **No client role trust:** ID-token role names are mapped server-side; API request role/user/owner fields are ignored for authorization.
10. **Session revocation:** privileged permission changes revoke or constrain affected sessions and are audited.
11. **Least privilege:** service accounts cannot impersonate users. Administrative support uses audited, purpose-bound workflows rather than direct production database editing.
12. **Fail closed:** missing role mapping, disabled policy, stale assignment, unavailable authorization dependency, or uncertain tenant blocks the action.

A route-permission-object-state matrix generated from code and compared with this design is required release evidence.

## 6. API, input, and output security

- Parse JSON with bounded depth/array/string sizes; reject duplicate/ambiguous fields and unknown mutation fields. Use allowlisted schema validation.
- SQLAlchemy parameterized queries are mandatory. Dynamic sorting/filtering uses an allowlist; no user-controlled SQL fragments.
- Store and render user text as data. Apply context-appropriate output encoding and a restrictive Content Security Policy. Do not use `dangerouslySetInnerHTML` for request text or AI output.
- Validate MIME by content inspection where attachments are accepted; do not trust filename extension or client `Content-Type`. Use safe download filenames and `X-Content-Type-Options: nosniff`.
- Apply route-specific body, query, search, pagination, upload, concurrency, job, and export limits at the edge and application. Return `429` safely and alert sustained abuse.
- Use constant-time verification for secrets/tokens where applicable. Do not expose whether a user, request, email, object, or token exists to an unauthorized caller.
- External callbacks/webhooks are signed, replay-protected, bounded, schema-validated, and idempotent. No arbitrary redirect target is reflected without an exact allowlist.
- Disable or protect interactive API documentation, debug endpoints, profiler, shell, database consoles, and source maps in production. Publish a minimal reviewed OpenAPI contract if needed.
- Set HSTS, `frame-ancestors`/CSP, `Referrer-Policy`, MIME sniffing protection, and a restrictive permissions policy at the appropriate server. CORS is an explicit origin/method/header list and never wildcard with credentials.

## 7. File and malware security boundary

ClamAV is an integration point, not proof that a file is safe in every context. The application must also enforce size/count/type, quarantine, exact-checksum/version binding, timeouts, blocked state, and authorized download.

- Random server-generated storage keys prevent traversal; original names are metadata only and are safely encoded on download.
- Prefer streaming through the API for the first release. If brokered direct upload is used, it must target a quarantine-only container, use a single-purpose short-lived authorization, avoid public ACLs, bind size/type limits, and trigger a trusted object-created event.
- Verify upload completion and checksum before scanning. Reject decompression bombs, excessive archives, unexpected MIME, and resource exhaustion. Scanner and application limits are independent.
- ClamAV connection uses private networking/mTLS where supported and an allowlisted endpoint. Scanner unavailability blocks release; it does not permit download.
- Bind verdict to attachment ID, object version/generation, SHA-256, engine version, signature version, and scan time. Any change invalidates the verdict.
- Scan results are structured and schema-validated. A scanner response is not executable, HTML, or an instruction.
- Quarantine and clean stores have separate least-privilege identities. Only the scanner/promotion worker can read quarantine; only the promotion worker writes clean; users never obtain storage credentials.
- Audit upload, scan, verdict, promotion, blocked state, download, deletion, and administrative actions. Do not copy content into logs.
- OpenClamAV must never be internet-exposed. Signature freshness, health, and error metrics are monitored and owned.

## 8. Azure OpenAI trust boundary

### Trust classification

| Item | Trust | Treatment |
|---|---|---|
| Versioned system policy and output schema | Trusted server configuration | Change-controlled, reviewed, hashed/versioned, not user selectable |
| Validated request facts and approved policy metadata | Semi-trusted application data | Typed and minimized; still checked against current domain rules |
| Request free text, filenames, comments, attachment text | Untrusted | Delimited as data, bounded/redacted, never treated as instructions |
| ClamAV/provider/email responses | Untrusted external data | Schema/type/allowlist validation; never authorization |
| Azure OpenAI response | Untrusted probabilistic content | Bounded, schema-validated, escaped, labeled, non-authoritative |
| Browser rendering of advice | Untrusted sink | Plain text/allowlisted components only; no HTML/script/link activation |

### Prompt boundary

1. The server owns model deployment, endpoint, system instructions, template, schema, budgets, and retention configuration. A browser cannot provide or override any of them.
2. User-controlled content is inserted as bounded data fields, never concatenated into system/developer instructions. Delimiters are defense in depth, not a guarantee against prompt injection.
3. The system prompt states that request text is evidence, not instruction; it defines no tools and no authority to decide. Architectural isolation, not prompt wording, enforces this.
4. Input is classified and minimized/redacted. Raw attachments, malware, secrets, credentials, unrelated records, and prohibited data classes are not sent by default.
5. Token, character, request concurrency, per-request cost, total daily cost, timeout, retry, and model-version budgets are enforced. Exhaustion yields `advice unavailable`, not approval.
6. The endpoint is configuration-controlled and egress-allowlisted. Model input cannot select a URL or invoke a retrieval/agent/tool chain.
7. The provider region, deployment, abuse-monitoring/retention behavior, private networking, credentials, and data-processing terms are approved and evidenced.

### Required output schema

A versioned schema such as the following is illustrative and must be implemented as strict server validation; it is not evidence of current code:

```json
{
  "schema_version": "1.0",
  "risk_level": "low | medium | high | critical | unknown",
  "summary": "bounded natural-language advisory summary",
  "missing_evidence": [
    {
      "category": "controlled category",
      "question": "bounded question for a human"
    }
  ],
  "policy_questions": [
    "bounded question requiring human interpretation"
  ],
  "suggested_human_checks": [
    "bounded check description"
  ],
  "confidence": "low | medium | high",
  "limitations": [
    "bounded limitation"
  ]
}
```

The schema has no `approve`, `decision`, `role`, `recipient`, `endpoint`, `tool`, SQL, HTML, callback, or workflow-command field. Enforce `additionalProperties: false`, string/array/count limits, controlled enums, and model/prompt/schema versions. Invalid, oversized, or unsupported output is rejected and recorded as an advice failure.

### Human-use boundary

- The UI displays “AI-generated advisory; not a decision” adjacent to the result and shows model/deployment and generation time.
- A human with existing authority invokes an explicit workflow command and supplies/accepts the required rationale. The application records that decision independently of advice.
- Advice may be absent, stale, wrong, or ignored without changing authorization. Refreshing advice does not refresh or modify a human decision.
- Reviewer training and tests cover prompt injection, fabricated citations, unsafe output, overreliance, and sensitive-data handling.

### Raw AI log retention: hard 24-hour bound

- Raw prompts, raw responses, and full provider diagnostic payloads are restricted encrypted diagnostic records with `created_at`, `expires_at <= created_at + 24 hours`, purpose, and owner.
- A continuously running deletion job removes expired records at least daily and on a bounded schedule suitable to the approved 24-hour maximum. The approved schedule must leave no possibility of routine retention beyond 24 hours; queue/backlog conditions alert as a breach.
- Provider-side abuse-monitoring/log retention must be disabled or configured to a shorter period where supported and contractually approved. Evidence is required.
- Structured minimized advice may remain under the request retention policy because it is a product artifact, not a raw diagnostic log. It must not contain raw provider output beyond the approved schema.
- Logs/events record advice ID, versions, token/cost counters, validation outcome, user initiation/use/non-use, and deletion proof without raw text.
- A timed test must show raw payload creation, expiry, deletion, inaccessible backup treatment, and provider configuration. Any inability to enforce the maximum is a `P0` gap.

## 9. Append-only chained audit

### Event and hash design

Each audit event contains at least: immutable event/sequence ID, previous chain hash, canonical event bytes, event hash, event type/version, UTC server time, actor type/ID, session ID reference, correlation/causation IDs, target type/ID, action, result/reason code, source context approved for audit, and data classification. Sensitive free text, tokens, secrets, raw AI payloads, and file contents are excluded; referenced IDs/checksums may be included.

For an authoritative single-tenant chain:

```text
event_hash = SHA-256(canonical_event_bytes || previous_event_hash)
```

- Canonicalization (field ordering, Unicode normalization, number/date representation) is versioned and tested. Hashing is performed before the audit event is sealed.
- A database-enforced monotonic sequence/previous-hash rule prevents forks and gaps. If high-volume partitioning is required, each approved chain has explicit genesis and signed checkpoints; the design must show how deletion/reordering is detected.
- Domain transaction inserts the audit event with the domain change/outbox event. A later asynchronous anchor copy must not be the only record.
- API/worker database roles have no `UPDATE`/`DELETE` on audit facts. Corrections are new linked events; privileged database access is separately controlled and logged.
- A verifier recomputes the chain, detects modification/deletion/reordering, compares external checkpoint anchors, and alerts on gaps. Verification output and anchor failures are security events.
- Periodically sign and copy chain heads/checkpoints to independently protected storage with separate credentials. A hash chain inside the same database detects accidental changes but does not, by itself, stop a privileged database rollback.
- Audit export includes chain context/proof, filters, requester, time, and checksum. Exports are encrypted, access-controlled, expiring, and themselves audited.

Minimum audited events include sign-in/session lifecycle, denied object/action attempts, break-glass lifecycle, role/policy changes, create/read/update/export of restricted data, attachment lifecycle/download, every workflow transition/decision, AI request/validation/use/deletion, outbox retry/DLQ/replay, key/config/secret-rotation outcomes, and audit verification/anchor status.

## 10. Secrets, cryptography, and logging

- Use Key Vault or an approved equivalent with workload identity and least-privilege read roles. Long-lived secrets in source, images, CI logs, repository `.env` files, or frontend bundles are prohibited.
- Where the platform supports managed identity plus a private Key Vault endpoint, prefer it. Otherwise store versioned secrets in Key Vault and deliver through the runtime’s approved secret mechanism; do not log resolved values.
- Separate API, worker, migration, scanner, and break-glass identities/roles. Break-glass does not receive standing data-plane secrets.
- Use platform TLS, approved password hashing (Argon2id), standard cryptographic primitives/libraries, and centrally managed keys. Algorithm/protocol/key choices require security approval and migration plans.
- Define rotation overlap and emergency revocation. A rotation test proves old credentials become unusable without uncontrolled plaintext copies.
- Structured logs include severity, service, environment, correlation/request ID, safe actor/session reference, action, result, latency, and dependency category. They exclude authorization headers, cookies, raw tokens, secrets, query strings containing sensitive values, request bodies by default, raw prompts/responses, and file content.
- Logs and audit are access-separated: operations may search telemetry; audit access is more restricted. Security-relevant logs are integrity protected and exported outside the primary workload failure domain.
- Debug tracing of OIDC, SQL, HTTP, storage, email, or AI payloads is prohibited in production. Error telemetry uses allowlisted codes and bounded safe metadata.

## 11. Threat model

The following is a baseline STRIDE review. Formal ratings and residual-risk acceptance require the named system/data/identity owners.

| ID | Threat / asset | Example attack or failure | Required controls | Verification |
|---|---|---|---|---|
| TH-01 | Spoofing — workforce session | Stolen opaque cookie, session fixation, XSS | Strong cookie flags, CSRF, CSP/encoding, session hash/storage, rotation/expiry/revocation, step-up | Browser/storage tests, XSS and session test |
| TH-02 | Spoofing — OIDC | Forged/mixed-up token, bad issuer/audience/nonce, code replay | Pinned metadata, signature/claim checks, one-use transaction/PKCE, tenant isolation | Negative OIDC corpus |
| TH-03 | Elevation — role mapping | Forged group claim, stale assignment, admin self-elevation | Server allowlist, DB current assignment, deny default, step-up/audit, session revocation | Claim/role/BOLA tests |
| TH-04 | Elevation — break-glass | Public endpoint, shared/default credential, silent fallback | Separate disabled local path, MFA, dual control, unique identity, rate limit/alert/audit | Network/config and exercise evidence |
| TH-05 | Tampering — workflow | Generic state update, skipped review, self-approval, stale concurrent decision | Explicit commands/state machine, row lock/version, SoD and policy recheck, append-only decision | State/property/concurrency tests |
| TH-06 | Tampering — attachment | Filename traversal, content swap after scan, malicious archive | Quarantine, random key, independent limits, checksum/version-bound verdict, clean-store ACL | EICAR, swap, traversal, polyglot tests |
| TH-07 | Tampering/repudiation — audit | Edit/delete/reorder/rollback audit or transition | Restricted DB permissions, canonical hash chain, external anchors, append-only correction | Tamper and privileged-role tests |
| TH-08 | Tampering/replay — outbox | Duplicate event, fake direct queue publish, replayed approval | Commit-only outbox, authenticated worker, stable IDs/idempotency, DLQ controls | Duplicate/replay/fault-injection tests |
| TH-09 | Information disclosure — files | Object-key/presigned URL sharing, direct bucket access, unsafe headers | Private bucket/no ACL, server authorization/download, opaque IDs, safe filename, audit | BOLA and network tests |
| TH-10 | Information disclosure — logs/email | Secrets/PII/raw evidence in logs or mail | Data inventory, redaction, minimized templates, restricted logs, no raw attachment, DLP | Log/mail capture and DLP tests |
| TH-11 | Information disclosure/SSRF — AI | User-selected endpoint, prompt injection exfiltration, unsafe provider output | Fixed egress/model, no tools, minimized input, strict output schema/escaping, 24-hour raw logs | Network and adversarial AI tests |
| TH-12 | Denial of service — upload | Huge/slow/multi-file/decompression-bomb upload | Edge/app limits, streaming, quotas, scanner isolation, timeouts, concurrency controls | Resource-exhaustion/load test |
| TH-13 | Denial of service — jobs/AI | Poison event, retry storm, expensive prompts | Bounded payloads/budgets/backoff/jitter/DLQ, circuit breakers, worker limits | Fault/load/cost test |
| TH-14 | Repudiation — email/provider | Provider says delivered while no human action; spoofed callback | DB is record, signed callbacks, stable message ID, delivery attempts/audit | Provider sandbox and reconciliation test |
| TH-15 | Supply chain | Vulnerable dependency/image, compromised build, leaked secret | Pinning, lockfiles, SBOM/scans, isolated CI identity, signing/provenance, protected runners | Signed build evidence |
| TH-16 | Misconfiguration | Public DB/ClamAV/docs, SQLite in production, permissive CORS | Private networking, production settings guard, config policy as code, startup validation | IaC/production startup scans |
| TH-17 | Privacy — data lifecycle | Excess AI/log retention, unrestricted export, unsafe backup | Classification/retention schedule, 24-hour raw AI TTL, DLP, legal hold, backup controls | DSR/retention/export/restore tests |
| TH-18 | Business logic — exception misuse | Duplicate/flood requests, overlapping approvals, use after expiry/revocation | Uniqueness/overlap policy, quotas, authoritative consumer checks, expiry scheduler, abuse alerts | Abuse-case and downstream-consumer tests |

## 12. OWASP ASVS baseline review

**Result:** every row remains an explicit `G` production gap. Static source expresses several intended controls, but no control is accepted without executed, release-linked evidence. The observations below are a source review, not a finding that the control works.

| ASVS area | Static intent observed | Explicit gap at baseline | Production gate |
|---|---|---|---|
| V1 Architecture | FastAPI/React/worker/storage/ClamAV/AI boundaries are represented in source/docs | No approved runtime, owner sign-off, abuse-case test, or deployed data-flow validation | Architecture review and abuse cases pass |
| V2 Authentication | Entra OIDC state/nonce transaction, issuer/audience checks, and local break-glass identity/recovery exist | Explicit PKCE generation/validation, Entra tenant/protocol tests, MFA for break-glass/approvers, and independent app registration evidence are absent; UI exposes a generic local-account tab | IAM-01–02 and IAM-09 pass independently |
| V3 Session Management | Random opaque token, stored hash, idle/absolute expiry, revocation, host cookie, and CSRF hash exist | No executed cookie/storage/fixation/revocation evidence; privileged step-up/session rotation policy is incomplete; API/client CSRF integration needs contract proof | IAM-03–06 and IAM-11 pass |
| V4 Access Control | Roles/permissions, scoped request queries, assignment checks, and self-approval checks exist | Admin receives wildcard permission; observed routes rely heavily on object helpers rather than a complete function-permission matrix; BOLA/field/SoD tests and independent auditor separation are absent | IAM-07–11 and object/function tests pass |
| V5 Validation and Sanitization | Pydantic bounds, SQLAlchemy queries, safe filenames, AI strict schemas, and React text rendering exist | Mutation schemas do not uniformly forbid extra fields; frontend/backend route and payload drift is visible; no injection/XSS/upload fuzz evidence | All mutation/display/security tests pass |
| V6 Stored Cryptography | Argon2id, SHA-256 token hashing, Fernet encryption, and HMAC-style audit digest intent exist | Key Vault/key-version design and rotation are unproven; private Fernet signing-key access is used; staging validator references an undeclared OIDC auth-mode field; no cryptographic tests | Approved design, secret scan, rotation, and negative tests pass |
| V7 Error Handling and Logging | Correlation IDs, safe domain errors, JSON formatter, and redaction helpers exist | Structured formatter includes exception stack text; no release log captures prove secret/PII safety; error format is not RFC 9457 problem details; no alerting evidence | No sensitive leakage; detection and safe-error tests pass |
| V8 Data Protection | Classification values, encrypted SecretRecord, data minimization, and retention defaults exist | Approved classification/retention/legal-hold policy, DSR behavior, raw AI diagnostic TTL, and independent key custody are absent | Privacy review and DSR/retention tests pass |
| V9 Communications | API sets several defensive headers; SMTP verifies default TLS context | No TLS ingress/HSTS deployment; Docker publishes API directly and trusts all proxy headers; private endpoints/certificate scans absent | Public TLS/header and private endpoint scans pass |
| V10 Malicious Code | Quarantine, content detection, ClamAV INSTREAM, and worker integration exist | No EICAR/signature-freshness/scanner-fault evidence; local compose is not a production scanner architecture; no independent signature ownership | FILE-03–04 and ClamAV service tests pass |
| V11 Business Logic | Detailed state map, assignments, stages, separation-of-duties, optimistic versions, expiry, extension, and jobs exist | No state/property/concurrency/flood/overlap tests; complete final-stage invariants and admin semantics require review; no downstream “exception is currently valid” consumer contract | All WF and TH-05/TH-18 cases pass |
| V12 Files and Resources | Random name, local quarantine/clean paths, per-file size/type checks, hash, and clean-only download exist | No aggregate count/rate enforcement, production object-store adapter, archive/decompression tests, object immutability, or EICAR evidence | FILE-01–08 pass |
| V13 API and Web Services | `backend/app/main.py`, auth/request/dashboard/notification/admin route modules, and schemas exist | Generated/reviewed OpenAPI and contract run are absent; frontend/backend paths and response shapes visibly differ; no CSRF client integration, fuzz, BOLA, or rate-limit evidence | Contract/security suites and fuzzing pass |
| V14 Configuration | Pydantic settings, `.env.example`, Dockerfile, Compose, Alembic config, and a static CI workflow exist | No supplied CI/secret/IaC run; production guard does not reject SQLite; startup validator references undeclared `oidc_auth_mode`; no Key Vault/private topology evidence | SEC-05–07 and OPS-01 pass |

## 13. OWASP Top 10:2021 review

Baseline version is stated explicitly; the release must also compare against the then-current published edition.

| OWASP category | Design/source response observed | Explicit current gap / release evidence |
|---|---|---|
| A01 Broken Access Control | RBAC/permission tables, scoped queries, assignment/owner checks, and workflow SoD exist statically | Wildcard admin, incomplete step-up, route/function drift, and no BOLA/field/negative-test evidence; require full matrix and retest |
| A02 Cryptographic Failures | Argon2id, opaque sessions, Fernet records, HMAC-style audit, and TLS SMTP intent exist | Key custody/rotation, production TLS, algorithm/key-version review, and executed negative/restore tests are absent |
| A03 Injection | ORM parameter binding, Pydantic bounds, safe filenames, and React text rendering exist | Unknown-field behavior, template/content/header edge cases, and SQL/command/XSS test evidence are absent |
| A04 Insecure Design | Explicit state/workflow, quarantine, advisory AI, and threat model exist in design/source | Design is unapproved; break-glass MFA/separation, admin wildcard, audit race/anchor, and abuse/business-logic tests remain open |
| A05 Security Misconfiguration | Settings/env/Docker/Compose exist | No production IaC/private network/Key Vault/secret scan; API port is published locally; SQLite production rejection and startup validation are unproven |
| A06 Vulnerable and Outdated Components | Pinned Python requirements and frontend lockfile are present | No SBOM/SCA/image scan, support policy, or zero-blocking-finding evidence |
| A07 Identification and Authentication Failures | OIDC and local recovery code exist; opaque sessions/CSRF exist | PKCE/tenant/negative protocol evidence, MFA, separate break-glass UX/route, and identity abuse tests are absent |
| A08 Software and Data Integrity Failures | Hash-linked audit intent, pinned dependencies, static CI, and an initial migration exist | No supplied CI run, artifact signing/provenance, protected runner/identity evidence, or successful migration; ORM audit guards do not prove privileged tamper resistance |
| A09 Security Logging and Monitoring Failures | JSON logs, correlation, audit events, job telemetry hooks exist | No protected telemetry deployment, alert rules, response exercise, or safe captured logs; exception text requires redaction review |
| A10 Server-Side Request Forgery | AI endpoint host/scheme validation and fixed provider patterns exist statically | No egress allowlist/private endpoint evidence; admin-configurable AI endpoint and redirect/header/provider SSRF tests require closure |

## 14. OWASP API Security Top 10:2023 review

| API risk | Explicit static review at baseline | Required production evidence |
|---|---|---|
| API1 Broken Object Level Authorization | Scoped request and assignment checks exist, but admin is global and endpoint/frontend contracts are incomplete | BOLA/IDOR suite over every object/action/role; notification, attachment, audit, backup/export and admin tests |
| API2 Broken Authentication | OIDC, opaque session, CSRF, lockout, and local recovery code exist | PKCE/claim/tenant, session, CSRF client integration, revocation, rate-limit, MFA and credential-abuse tests |
| API3 Broken Object Property Level Authorization | DTOs and serializer functions exist; several mutable schemas permit extra fields and response shapes are custom dictionaries | Strict-schema, unknown-field, field-role, ID-reference and response-allowlist tests |
| API4 Unrestricted Resource Consumption | Field bounds, page limits, file size, rate-limit service, timeouts, and job attempts exist | Aggregate upload, body, search/export, worker concurrency, AI cost, slow-client and load tests |
| API5 Broken Function Level Authorization | Role checks exist mainly inside route/service functions; no complete function-permission map | Function-role matrix and direct API negative tests; explicitly resolve wildcard admin authority |
| API6 Unrestricted Access to Sensitive Business Flows | Basic request/login rate buckets exist | Abuse tests for request flooding, approval links, exports, backups, break-glass and AI; alert/quotas |
| API7 Server Side Request Forgery | AI endpoint validation and SMTP/ClamAV configured endpoints exist | Egress policy plus SSRF/DNS/rebinding/redirect/private-address/provider failure tests |
| API8 Security Misconfiguration | Settings and defensive API middleware exist | Production route inventory, CORS/docs/debug/header/error/config scan; no direct API/DB/ClamAV exposure |
| API9 Improper Inventory Management | Main entry point, route modules, manifests, and static CI exist; no supplied executed contract/release inventory | OpenAPI/route diff, ownership, deprecation/support policy, SBOM and release inventory |
| API10 Unsafe Consumption of APIs | Authlib, SMTP, ClamAV, and Azure OpenAI adapters/workers exist statically | Provider contract/fuzz/timeout tests, signed webhook handling if added, classification limits, and safe telemetry |

## 15. Security production gates

Security approval requires all of the following; this list supplements, but does not replace, `06-acceptance-and-production-gates.md`:

- Threat model, data flow, data classification, and privacy impact review approved by security, privacy, and service owners.
- OIDC/session/CSRF/role/object/SoD suites pass against PostgreSQL and a production-like Entra tenant.
- Break-glass is proven unavailable on the public path and passes a controlled exercise with alerting and audit.
- Upload, EICAR, malware-result, storage-direct-access, content-limit, and scanner-outage tests pass.
- AI trust-boundary, prompt-injection, output-schema/XSS, egress, budget, privacy, and 24-hour deletion evidence pass.
- Audit chain mutation/deletion/reorder/rollback, database privilege, and external-anchor tests pass.
- SAST, secret scan, SCA/SBOM, container/IaC scan, DAST/API test, and artifact-signing evidence has no unaccepted blocker.
- Independent penetration test covers the deployed candidate and critical/high findings are remediated and retested.
- Detection scenarios produce timely alerts to the responsible on-call path, and response runbooks are exercised.
- No production credential, restricted evidence, raw AI content, or unreviewed diagnostic endpoint is present.

Until these artifacts exist, the system is **not production-approved**.
