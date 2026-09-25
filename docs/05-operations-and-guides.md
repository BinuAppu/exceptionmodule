# Operations and user guides

## 1. Status and operating principles

These are target runbooks and user procedures cross-checked against the static source snapshot. Commands and entry points below are **not verified procedures**: no clean-environment execution, test run, migration, deployment, or integration result was supplied, and some expected release artifacts were absent or incomplete at the review snapshot.

Operating principles:

- Production, staging, development, identity tenants, databases, storage, model deployments, and secrets are isolated.
- PostgreSQL is mandatory in production. SQLite is only for isolated local/unit tests and is rejected by production startup.
- The backend is the only business/data integration client. The browser never receives database, storage, scanner, email, AI, Key Vault, or queue credentials.
- Domain records are authoritative only after a PostgreSQL commit. Email and model output are not records of decisions.
- Quarantine, human decision, and audit controls fail closed.
- AI is optional/advisory and its raw diagnostic retention is bounded to 24 hours.
- Runbooks require named owners, change/incident records, evidence, and tested rollback/restore. A document alone does not close a gate.

## 2. Externalized configuration and secrets

### 2.1 Proposed configuration contract

Names below combine observed settings in `backend/app/core/config.py` / `.env.example` with required production settings that are not yet evidenced. Environment variable names are case-insensitive through Pydantic Settings.

| Setting / secret group | Purpose | Source | Validation and handling |
|---|---|---|---|
| `ENVIRONMENT` | `development`, `test`, `staging`, `production` (static setting) | Deployment configuration | Production must reject development flags and SQLite; this guard is not yet evidenced. |
| `DATABASE_URL` | SQLAlchemy PostgreSQL URL | Runtime secret/config | Secret username/password; TLS and approved host; never logged. |
| `SESSION_COOKIE_NAME`, `SESSION_COOKIE_SECURE`, `SESSION_IDLE_MINUTES`, `SESSION_ABSOLUTE_MINUTES` | Session policy (static names) | Nonsecret config | Production forces secure cookie; durations approved/bounded. |
| `OIDC_ISSUER`, `OIDC_CLIENT_ID`, `OIDC_REDIRECT_URI`, `OIDC_SCOPES` | Entra binding | Nonsecret config | Exact allowlisted issuer/client/redirect; HTTPS in production. |
| `OIDC_CLIENT_SECRET` or certificate reference | Backend OIDC authentication | Key Vault or approved workload mechanism | API/migration identities only; rotate/revoke; never frontend. |
| `OIDC_ROLE_MAPPING_VERSION` | Server role mapping | Versioned nonsecret config/database policy | Allowlist and review; provider claims never directly trusted. |
| `BREAK_GLASS_USERNAME`, `BREAK_GLASS_INITIAL_PASSWORD` (static) plus required enable/network policy | Emergency identity/bootstrap | One-time secret process and local/admin configuration | Initial secret removed after seed; required `BREAK_GLASS_ENABLED` default false is not present in static settings. |
| Break-glass bootstrap/hash and MFA keys | Emergency authentication | Approved secure bootstrap/Key Vault process | No default or standing plaintext; rotate after use. |
| `STORAGE_ROOT` (static local adapter) / production object-store endpoint and container names | File storage | Nonsecret plus private identity | Local only in development; production containers private/no public ACL with API/worker roles distinct. |
| `CLAMAV_HOST`, `CLAMAV_PORT`, `CLAMAV_TIMEOUT_SECONDS` (static) plus production limits | Malware scanner | Nonsecret private config | Allowlisted private endpoint; production requires private access/fail closed. |
| `AZURE_OPENAI_ENDPOINT`, deployment, API version | Model service | Nonsecret config/managed identity | Fixed allowlist/region; no user override; approved deployment. |
| Azure OpenAI credential | Model authorization | Key Vault/managed identity | Worker only; narrow token/secret; rotate. |
| `AI_RAW_LOG_RETENTION_HOURS` | Raw prompt/response TTL | Hard configuration bound | Must be `24` or less; production startup rejects greater value. |
| `AI_MAX_*`, `SMTP_*`/Graph settings, sender/reply-to | Email and AI budgets/provider | Nonsecret config plus secret | Length/time/cost/provider allowlists; no recipient supplied by model. |
| `AUDIT_ANCHOR_*`, `RETENTION_*` | Integrity/export/lifecycle policy | Nonsecret config | Values approved; anchor failure alerts; DB time source used. |
| Observability endpoints/credentials | Logs, metrics, traces, paging | Platform config plus Key Vault | Minimize labels/cardinality; no payloads; production restricted. |

Static gaps in this contract are production blockers: `backend/app/core/config.py` does not visibly reject SQLite for production, does not define the required break-glass enable switch, and references `oidc_auth_mode` inside a validator although the declared setting is `azure_openai_auth_mode`; Key Vault/private object storage/audit-anchor settings are absent. These observations require direct runtime tests and correction, not assumption.

### 2.2 Configuration rules

1. Settings are parsed into a typed, immutable application configuration at startup. Unknown security-critical settings fail rather than being ignored.
2. Nonsecret deployment values may come from environment/platform configuration; secret values come from Key Vault or the platform’s approved secret injection mechanism.
3. Mutable business policy is versioned in PostgreSQL and changed through audited admin commands, not hand-edited environment files.
4. Effective configuration metadata (name, version, nonsecret value where safe) is observable. Secret values, connection strings, tokens, and resolved provider credentials are never observable.
5. Startup validates environment, URLs/schemes, issuer/redirect, cookie policy, database dialect, retention, storage encryption mode, model endpoint/deployment, and provider timeouts.
6. Production refuses SQLite, local CORS, debug/docs, wildcard egress, anonymous break-glass, plaintext secrets, test model deployments, and unsafe retention.
7. Config reload, where supported, uses a versioned safe subset. Security/database/storage changes normally require a controlled restart or deployment.
8. Configuration changes run through peer review and IaC. Emergency local edits are not production change evidence.

## 3. Local development and testing

### 3.1 Prerequisites

The repository provides `install.sh`, `steps-to-install.txt`, pinned backend/frontend dependencies, `Makefile`, `Dockerfile`, and `docker-compose.yml`. The Docker path has been exercised for local build, migration, seed, startup, readiness, frontend serving, and break-glass login. It is still a local evaluation toolchain, not production release evidence. A developer will need:

- Supported Python and Node versions defined by the project.
- A local PostgreSQL instance for integration/worker/migration testing.
- An Entra test tenant/application or a test-only OIDC provider, with no production tenant/client/secret.
- A local ClamAV test service or isolated sandbox for file tests; unit mocks alone do not close the integration gate.
- Test-only object storage, email sink, and Azure OpenAI deployment approved for the selected tenant/region.
- An isolated Key Vault or local secret mechanism that cannot access production resources.
- Local directories `storage/attachments/`, `storage/backups/`, and `storage/exports/`, excluded from source control and populated only with synthetic data.

### 3.2 Expected startup flow

The supported local startup path is `install.sh`, which creates isolated local configuration, builds the FastAPI/React image, applies Alembic migrations, seeds synthetic local data, starts dependencies in health order, and verifies readiness. The equivalent manual flow is:

1. Create an isolated local environment and obtain test configuration from the approved secret process. Do not copy production environment exports.
2. Install backend dependencies using the pinned lock mechanism and frontend dependencies using the committed lockfile.
3. Start test PostgreSQL and apply migrations using `backend/alembic/versions/` through the project’s documented Alembic command.
4. Seed only synthetic users/roles/policies through a nonproduction fixture path. Never use a production database dump.
5. Start the API from `backend/` using the documented Uvicorn/FastAPI entry point. For a unit-test profile only, a temporary SQLite database may be selected; production startup must reject it.
6. Start Vite from `frontend/` using its documented script and proxy same-origin `/api` traffic to the API.
7. Run unit tests, then PostgreSQL integration, API contract, browser, file/ClamAV, outbox, AI, migration, and security suites.
8. Inspect logs and test stores to confirm no secret, raw AI payload, or non-synthetic data is exposed.

`Makefile` provides host-based development commands with the backend module path configured. Docker-based local evaluation should use `install.sh`; the Makefile and Vite scripts remain developer conveniences rather than production release evidence.

### 3.3 Local identity rules

- Prefer the isolated Entra test tenant to test OIDC behavior. Production issuer/client/secret values are prohibited locally.
- The break-glass path is separate, disabled by default, and accessible only on loopback/approved local interface. It requires unique synthetic credentials and MFA.
- Never make normal login fall back to break-glass when Entra is unavailable.
- Local role fixtures must represent least privilege and both allowed/denied assignments. A local “Admin” UI flag grants nothing.
- Use only synthetic requests, filenames, content, and email recipients. Do not test malware handling with real malware; use approved EICAR and safe test artifacts.

Static gap: `backend/app/api/routes/auth.py` reports local break-glass enabled unconditionally and reuses `/api/auth/login`, while `frontend/src/pages/auth/LoginPage.tsx` presents a generic local-account tab. The source shows recovery codes but no break-glass MFA challenge or explicit local-network guard. Keep the path unavailable outside an isolated development environment until IAM-09 is implemented and tested.

### 3.4 Test data and cleanup

- Generate data per test run; do not share mutable personal data.
- Delete local test databases, object prefixes, mail sinks, AI logs, and access tokens after the approved retention/debug window.
- Ensure CI artifacts and screenshots redact cookies, OIDC codes/tokens, prompts, email addresses, and evidence content.
- Production backups/exports must never be copied into repository `storage/` directories.

## 4. Deployment and release

### 4.1 Environments

Maintain separate Azure resources/subscriptions or equivalently isolated estates for development, test, staging, and production as required by policy. Each environment has distinct:

- Entra tenant/app registration/client/audience and role mappings.
- Database, storage containers, scanner, Key Vault/identities, email sender/provider, and AI endpoint/deployment.
- Session cookie, secrets, telemetry, backup, and support access.
- Quota/budget and data-classification controls.

Staging must resemble production network and identity topology closely enough to test private endpoints, role restrictions, migrations, outbox, malware scanning, and SSO.

### 4.2 Infrastructure baseline

The selected approved runtime must provide:

- At least two API instances across independent failure domains, or an equivalent availability design meeting the approved objective.
- Independently scalable workers with safe concurrent claiming and per-job resource limits.
- Managed PostgreSQL HA, private access, TLS, encryption, PITR/snapshots, automated backups, and tested point-in-time recovery.
- Private object storage with quarantine/clean/archive separation, versioning/lifecycle/immutability as required, and no public ACL.
- Private ClamAV service with bounded concurrency, current signatures, health monitoring, and no public endpoint.
- WAF/ingress, TLS, HSTS, security headers, WAF/rate policy, trusted-proxy handling, and no direct origin bypass.
- Restricted nonproduction/debug access through audited identity-aware access, not broad public URLs.
- Central telemetry and an independently protected audit anchor with separate credentials.

`docker-compose.yml` supplies PostgreSQL, ClamAV, an API image containing the built React frontend, and a worker for local integration only. It publishes a configurable loopback port by default, injects `.env`, and uses named local volumes. It still lacks WAF/TLS, private managed data services, Key Vault, production identity/email/AI, HA, tested backup operations, and complete observability. It must never be promoted unchanged to production.

### 4.3 Build and release sequence

1. **Approve candidate:** requirements/evidence index has no unaccepted P0 blocker; SBOM, scans, tests, migrations, threat/privacy reviews, and sign-offs are linked.
2. **Build once:** CI creates immutable backend/frontend artifacts from protected source, records provenance, signs artifacts, and publishes only after policy checks.
3. **Provision/apply IaC:** peer-reviewed infrastructure changes are applied to staging, validated, then production through approved change management.
4. **Expand migration:** apply backward-compatible schema changes with a single controlled migration identity. Do not deploy destructive schema yet.
5. **Deploy workers/API:** deploy version-compatible workers before producers and API before or with frontend. Workers support the current and previous event schema during rollout.
6. **Deploy frontend:** serve static assets with cache invalidation and no secret/configuration embedded beyond public nonsecret metadata.
7. **Smoke test:** liveness/readiness, OIDC test user, RBAC, create/submit/review, safe decision, outbox/email sink, upload/clean download, advice failure/success, audit verify, and metrics.
8. **Canary:** route an approved small cohort through a time-bounded canary; compare errors, latency, queue age, auth failures, and business invariants.
9. **Promote:** complete rollout only after the approved observation period and owner approval.
10. **Record:** attach artifact digests, migration version, configuration version, test/evidence links, approvals, and rollback point to the release record.

No production gate passes merely because an image built or a health endpoint returned `200`.

### 4.4 Rollback

- Application/frontend rollback is permitted only while schema and event contracts remain backward compatible.
- Workers must not process event versions they do not understand; pause/fence consumers before incompatible rollout.
- For destructive migration or corrupted data, use the approved point-in-time/object restore procedure rather than an unsafe down migration.
- Roll back on identity misbinding, authorization/SoD defect, data integrity/audit defect, sustained error/latency, queue divergence, security alert, or unavailable critical dependency.
- Preserve logs/audit/evidence before destructive remediation and follow incident command.

## 5. Microsoft Entra ID / OIDC administration

### 5.1 App registration

The identity owner should:

1. Create/register the application in the approved Entra tenant with a clear owner and emergency contact.
2. Add only exact backend redirect URIs for each environment. Do not add wildcard or frontend callback URIs.
3. Configure the application as confidential Web application using Authorization Code with PKCE; do not enable implicit grant.
4. Store the client secret/certificate in the approved secret mechanism. Prefer short-lived workload identity/certificates where supported; never place it in `frontend/src/`.
5. Pin issuer, tenant, client/audience, API scope, and authorized party. Protect discovery/JWKS retrieval with trusted configuration and safe caching.
6. Define stable app roles/groups for requester, reviewer, approver, auditor, and administrator permissions. Keep approval and administration separate.
7. Obtain least-privilege consent only for required Graph capabilities (for example, group overage if selected). Do not request mail/send-as or broad directory scopes unless separately approved.
8. Configure access/session/token lifetimes, Conditional Access, MFA, user lockout/risk, and allowed sign-in methods according to enterprise policy.
9. Record owner, tenant/client IDs, redirect URIs, role mapping version, secret/certificate expiry, rotation date, and rollback configuration in the secret/config inventory.

### 5.2 Assignment and access procedure

- Assign workforce access by approved group/app role; do not create per-user exceptions without owner approval.
- New users are provisioned on first validated OIDC login only if an approved policy allows JIT creation. Otherwise, pre-provision by verified immutable subject.
- Joiners, movers, and leavers use the identity/governance process. Disabling the Entra account must revoke application sessions and pending break-glass/bootstrap access.
- Review privileged roles and break-glass eligibility on the approved access-review cadence. Evidence belongs in the release/access-review system, not source.
- Test all allow and deny cases with synthetic identities before assigning real users.

### 5.3 Login validation and troubleshooting

Test: valid login; canceled/failed callback; expired/replayed state; bad nonce/signature/issuer/audience/tenant; unsupported algorithm/PKCE; disabled local account; unmapped app role; group overage; expired/revoked session; cookie rejection; clock skew; IdP outage; logout.

Operational checks:

- Confirm DNS/TLS/redirect and time synchronization before changing application code.
- Compare sanitized app/IdP correlation IDs and timestamps.
- Verify audience/issuer/client against environment configuration; do not copy a token into a ticket.
- Do not “fix” authentication by enabling break-glass or disabling validation. Use the emergency procedure only under its controls.

## 6. Email and notification operations

Email is a delivery of committed events, not a workflow engine. Approved provider choices are SMTP or Microsoft Graph; whichever is selected needs a sandbox, credentials in Key Vault, allowlisted templates, and tested failure behavior.

### Required configuration

- Verified sender identity/domain, reply-to/escalation mailbox, provider endpoint/region, credential/managed identity, rate limit, timeout, retry budget, suppression handling, and privacy policy.
- SPF, DKIM, and DMARC aligned with the enterprise domain. Email authentication does not replace application authorization.
- Approved templates for submission, changes requested, decision, revocation/expiry, attachment status, advice status, and security events.
- Templates reference the portal rather than embedding restricted free text, evidence, decision rationale, model output, or secrets.
- Application bounces/complaints update delivery state but never change a business decision or re-open/withdraw a request.

### Operational checks

- Use a sandbox recipient and inspect headers, template version, correlation ID, links, and data minimization.
- Test provider timeout, `429`, transient `5xx`, permanent failure, bounce, complaint, suppression, duplicate send, DLQ, and replay.
- Monitor pending age, success/failure/bounce rate, provider latency, DLQ count, and template version.
- Escalate critical security and expiry failures through paging/operations; do not depend on the business recipient opening email.
- Email addresses are sensitive infrastructure data. Redact them in logs/exports unless the recipient has a need and policy permits.

## 7. Object storage and ClamAV operations

### Production layout

Use private, separately controlled locations such as:

- **Quarantine:** API upload only; no user download; scanner worker read; short quarantine retention.
- **Clean:** promotion worker write; API authorized read/stream; lifecycle/retention policy.
- **Archive/delete staging:** only if approved; separate identity and retention/immutability policy.
- **Backups:** separate account/container/vault and recovery identity, not ordinary application delete access.

Container names are examples, not implemented values. Storage must enforce encryption, versioning/object lock where required, private networking, least-privilege managed identities, access logging, lifecycle, and nonpublic ACLs.

### Routine checks

- Reconcile attachment rows with object versions/checksums; quarantine unexpected/orphaned objects and clean objects without a valid current scan/attachment.
- Monitor ClamAV engine/signature freshness, scan latency/error/backlog, object count/bytes, lifecycle deletion, and denied download attempts.
- Block release when scanner health, signature age, verdict schema, or exact object binding is uncertain.
- Test EICAR, safe alternate stream, checksum/version swap, oversized/slow upload, unexpected MIME/polyglot, archive limits, direct bucket denial, and scanner outage.
- Follow malware/privacy incident procedure for infected content. Do not email, upload to AI, attach to tickets, or copy into shared developer storage.
- Keep a synthetic malware corpus under access control; never commit actual malware.

### Local storage

`storage/attachments/` is a development adapter only. The local adapter must reproduce quarantine/scan-state behavior for tests, reject production use, use synthetic data, and never be mounted into production. `storage/exports/` and `storage/backups/` are also local/test paths, not evidence or production targets.

## 8. Azure Key Vault and secret rotation

### Access intent

| Identity | Minimum Key Vault/data-plane intent |
|---|---|
| API workload | Read only specific OIDC/provider/config secrets and references required by API; no worker-only AI key; no broad secret list/read |
| Worker workload | Read only email/AI/storage/scanner configuration secrets required for its jobs; no OIDC client secret unless architecture requires it |
| Migration job | Read only database/migration secret for the approved window; no standing interactive access |
| CI/CD | Narrow release-time secret injection or workload access; no persistent production admin credential |
| Developer | No standing production secret read; approved just-in-time elevation with audit |
| Break-glass | No standing broad Key Vault role; emergency retrieval is separate, dual-controlled, audited, and temporary |

### Rotation procedure

1. Inventory owner, consumer, creation, expiry, algorithm/type, rotation interval, and dependent fallback.
2. Create the new version in Key Vault using an approved access path; do not paste it into tickets/chat/source.
3. Deploy consumers that accept overlap while continuing to use the old version.
4. Verify telemetry/health and a safe integration operation.
5. Disable/remove the old secret after the approved overlap; verify old-value authentication fails.
6. Rotate/revoke sessions, tokens, certificates, or encryption keys as applicable and test continuity.
7. Attach timestamps and outcomes to the change/evidence record; alert on unexpected access/failure.

Emergency revocation must be faster than routine rotation and must not require logging the secret. Key Vault availability/cache/refresh behavior and outage response are tested before production.

## 9. Backup, restore, and disaster recovery

### 9.1 Policy decisions still required

RPO, RTO, backup frequency/retention, point-in-time window, region strategy, service outage behavior, encryption-key recovery, and restore-drill cadence are `TBD` and block production approval. A generic “daily backup” is not sufficient evidence.

Static `backend/app/services/backups.py` demonstrates a local `pg_dump` command, optional encryption, and hash verification. It is not PITR, does not back up object files/configuration, has no restore routine, and therefore does not close this section. The backup encryption path must also be verified to use the intended `BACKUP_ENCRYPTION_KEY`; do not infer that from a hash record.

### 9.2 Required backup scope

- PostgreSQL: automated backups and PITR/snapshots with tested integrity, HA, encryption, and recovery credentials isolated from application operators.
- Object storage: versioning/PITR where supported, protected lifecycle, replication/immutability appropriate to the approved RPO, and clean/quarantine recovery semantics.
- Infrastructure/config: versioned IaC, nonsecret configuration, migration history, prompt/schema versions, templates, and policy metadata from source/control plane—not a developer machine.
- Secrets/keys: Key Vault recovery/backup and key-management configuration under a separate privileged process. Backups remain encrypted and inaccessible to normal admins.
- Audit: database events plus external chain checkpoints/anchors; restore verification must compare continuity and detect gaps.
- Outbox/jobs: included in the database backup. After restore, reconcile job leases, dedupe notifications/advice, and preserve DLQ rather than blindly replaying.

### 9.3 Backup controls

- Separate backup/recovery identities, immutable retention where required, encryption, access/audit logging, and deletion controls.
- Backup success alerts do not prove restorability. Automated restore verification and periodic human/automated full drills are required.
- Measure actual RPO/RTO and failure-detection time. Record failures and remediation.
- Keep backups in approved locations; never commit them under `storage/backups/`.
- Quarantined malware and restricted attachments follow legal/privacy retention; restoring them must preserve block state and never assume clean.

### 9.4 Restore runbook

1. **Declare and contain:** incident/change commander opens a record, freezes or fences writes/workers where needed, and preserves current logs/audit/provider state.
2. **Choose recovery point:** identify approved DB/object recovery point and expected RPO. Do not improvise against the live production database.
3. **Restore isolation first:** restore PostgreSQL and objects to an isolated network/account with restricted recovery identities. Confirm encryption/key access.
4. **Validate database integrity:** migrations/schema version, row/constraint checks, session revocation policy, audit continuity, outbox/job state, and no unexpected role/account changes.
5. **Validate objects:** reconcile attachment metadata, object versions/checksums/scan states; keep unreviewed or mismatched objects blocked.
6. **Validate identity/config:** pinned issuer/client, role mapping, secrets, egress, storage/scanner/email/model endpoints, and time synchronization.
7. **Run smoke tests:** synthetic OIDC/RBAC/SoD, create/submit/review/decision, quarantine/clean test, notification sink, advice failure/success, audit verify, and observability.
8. **Reconcile asynchronous work:** compare events/jobs/DLQ; replay only approved idempotent events; do not resend notifications merely because provider status is unknown.
9. **Approve cutover:** service owner, security, data owner, and incident/change commander sign the recovery evidence and communications plan.
10. **Cut over and monitor:** switch traffic through controlled configuration; monitor auth, errors, queue age, storage/scans, audit, and business invariants through the approved observation period.
11. **Close:** document actual RPO/RTO, gaps, customer/process impact, lessons, and follow-ups; revoke temporary access.

Destructive reset, public database repair, direct object ACL broadening, or disabling audit is not an acceptable restore shortcut.

## 10. Upgrade and schema-change procedure

1. Record current and target application, API/event, prompt/schema, migration, dependency, base-image, and configuration versions.
2. Review breaking changes, PostgreSQL migration lock/space/time impact, event producer/consumer compatibility, and rollback feasibility.
3. Take/confirm an approved recoverable backup and prove the prior release can read/write the expanded schema.
4. Test forward migration and application on a production-like PostgreSQL snapshot with representative sanitized volume.
5. Test the current and previous frontend/API clients; verify auth/session behavior across rollout.
6. Deploy expand schema → backward-compatible workers/API → frontend → optional backfill → soak.
7. Pause/fence incompatible workers before a breaking event/consumer change. Do not drop or rewrite historical audit/domain rows.
8. Observe metrics, then perform contract migrations in a later release. Down migrations are not assumed reversible.
9. If rollback is unsafe, use the restore runbook and obtain explicit data-owner approval.
10. Update docs, OpenAPI/event schemas, SBOM, threat model, test/evidence index, and operator training before closure.

For AI changes, version prompt template, output schema, model deployment, and evaluation corpus. A schema change requires dual-version validation or a safe rollout; old advice must not become executable or be mistaken for the current schema.

## 11. Observability and incident runbooks

### Required signals

- API/worker availability, latency/error/saturation, authentication failures, CSRF/authorization denials, role changes, break-glass alerts.
- PostgreSQL connections/transactions/locks/migrations/replica/PITR/backup health and outbox age/claim/retry/DLQ.
- Object upload/bytes/download failures and ClamAV backlog, engine/signature age, verdict/error distribution.
- Email pending age, provider errors, bounce/complaint/suppression and DLQ.
- AI request/validation/token/cost/latency failures, budget exhaustion, and raw-log deletion backlog/age.
- Audit append/verification/anchor failures and privileged database/storage access anomalies.
- Build/deployment/configuration/secret/certificate expiry and vulnerability findings.

Metrics and traces must not contain request text, tokens, cookies, prompts/responses, file content, or raw email addresses. Alert thresholds and paging routes are approved per service objective and exercised.

### Minimum incident playbooks

| Incident | Immediate safe action | Recovery/evidence focus |
|---|---|---|
| Entra/OIDC outage | Keep normal users signed out/fail closed; do not enable break-glass except approved emergency procedure | IdP metrics, callback errors, session creation, post-recovery login tests |
| Suspected session/role compromise | Revoke affected sessions, disable account, preserve identity/app/audit logs, scope role changes | Session/role/audit review, token/key rotation if needed |
| Break-glass use | Page security, link incident, restrict actions, monitor session live | Full action/audit review, credential/session rotation, post-use closure |
| Database outage/failover | Fence writes/workers as designed; do not split-brain or bypass workflow | Transaction/outbox recovery, PITR/failover evidence, data reconciliation |
| Storage/scanner outage | Stop release/download; keep uploads quarantined or reject cleanly | Backlog/quota, scan freshness, EICAR retest, safe backlog drain |
| Email outage | Preserve events; use in-app/operational escalation | Provider recovery, idempotent replay, DLQ/duplicate review |
| Azure OpenAI outage/budget | Mark advice unavailable; continue human workflow within policy | No state change, provider spend stop, safe re-enable/evaluation |
| AI data/unsafe output | Disable advice jobs/feature, preserve restricted evidence, invoke privacy/security response | Quarantine logs within policy, 24-hour deletion, input/output investigation |
| Audit chain/anchor failure | Stop privileged mutations if required by policy; preserve DB/anchors | Recompute/compare, identify gap/tamper, restore/incident decision |
| Malware detection | Block object/access, preserve IDs/checksums, invoke security/data procedure | No content copying, clean-store verification, scanner and access review |
| Secret/credential exposure | Revoke/rotate, invalidate sessions/tokens, restrict access | Scope, logs/artifacts, identity review, evidence sanitization |

## 12. Administrator guide

Administrators manage access and operational metadata; they do not routinely decide requests or edit production rows.

### Routine administration

- Review workforce status and role assignments from the approved application/API using their own audited admin session.
- Grant only approved roles, with expiry where appropriate. Never grant requester + approver to the same person to bypass separation of duties.
- Use step-up authentication and an incident/change reason for role, policy, retention, export, or replay actions.
- Manage policy metadata through versioned commands. Published versions used by requests cannot be edited; create a new version.
- Inspect outbox/DLQ jobs, retry/replay using the event’s stable idempotency key, and preserve original attempts.
- Block/review attachments through their state and security procedure. Do not mark content clean manually to bypass ClamAV.
- Run audit verification/anchor status and export only within approved scope.
- Follow source/IaC/config pipelines for infrastructure, dependency, prompt, schema, and secret changes. Direct production file/database edits are incident-only and require a compensating-control record.

### Prohibited shortcuts

- Sharing accounts or cookies.
- Editing audit, decision, requester, actor, hash, or timestamps directly.
- Granting self-approval or using break-glass routinely.
- Opening PostgreSQL/object storage/ClamAV to the public network.
- Disabling validation, malware fail-closed, CSRF, schema validation, or audit checks to make a task succeed.
- Sending restricted data through email, AI, tickets, or local exports.
- Replaying jobs without checking business state and provider reconciliation.

## 13. Break-glass runbook

Use only when normal identity/operations cannot proceed and the incident/change authority approves emergency access.

1. Record incident/change, reason, scope, expected duration, owners, and two-person participants.
2. Verify the host/network/operator integrity against the approved emergency-access standard.
3. Enable the path through the approved local mechanism only if evidence suggests the normal path cannot recover. Confirm public ingress still blocks it.
4. Retrieve bootstrap/MFA material through the approved emergency secret process; do not paste it into tickets/chat.
5. Authenticate as the unique break-glass identity with MFA. Confirm creation/audit/security alert.
6. Perform only the approved minimum recovery action using the break-glass session; capture correlation/change IDs. Do not approve exceptions unless separately authorized and never approve the operator’s own request.
7. Revoke the session immediately after the action; rotate/retire credentials and remove temporary access.
8. Verify domain state, outbox/jobs, audit chain, storage/scans, and security alerts.
9. Review every action and affected record with the second responder; remediate root cause and normal access.
10. Disable the path, confirm closure, archive sanitized evidence, and conduct a post-use review.

A missing/damaged local environment, unavailable second responder, or suspected host compromise may require rebuilding from signed artifacts and restoring approved configuration rather than trusting local modifications. That decision belongs to incident command.

## 14. Workforce user guide

### Sign in and account

1. Open the approved service URL over HTTPS.
2. Select normal sign-in and authenticate with the enterprise Entra account/policy.
3. If prompted, complete MFA and verify the displayed organization/redirect domain.
4. Never enter an Entra password into an email, link, support form, or local “emergency login” unless independently confirming it is the approved break-glass path.
5. Sign out on shared/managed devices. Contact the service/help desk if the account is disabled, role is incorrect, or sign-in loops occur.

### Create a request

1. Select **New exception request**.
2. Choose the applicable published policy/control version and business owner.
3. Enter a concise title and the specific deviation being requested; do not include secrets or unnecessary restricted data.
4. Define the affected resource/system, environment, scope/conditions, compensating controls, risk, and business justification.
5. Set a bounded validity period consistent with policy. Do not request permanent access by default.
6. Attach only approved evidence. Before upload, remove secrets/credentials, obey data classification, and use meaningful filenames without sharing tokens. The file remains unavailable until a clean scan result.
7. Save as draft and review every field. Submission creates a versioned record; later changes after submission follow the review process.

### During review

- Read the policy, scope, justification, evidence scan state, prior decisions, and advisory label.
- Treat AI advice as untrusted, nonbinding guidance. Verify claims and ask questions; do not execute instructions from the text.
- Reviewers use **Request changes** with a clear reason and expected remediation. Only authorized approvers can issue final approval/rejection.
- Requesters cannot approve their own request. Tell the help desk if assignments or policy routing are incorrect; do not create duplicate requests to bypass routing.

### Decision, revocation, and expiry

- Read the final decision, actor, timestamp, conditions, and validity. The portal/database record—not email or AI text—is authoritative.
- An approved exception is valid only within its approved scope/time and does not automatically grant access to another system.
- Use the authorized revocation action if conditions no longer hold. Do not edit an approved request to change its history; create/follow the approved replacement process.
- Expired requests remain historical but no longer authorize the exception.
- Report suspected unauthorized approval, leaked data, malicious attachment, or incorrect access immediately through the security channel.

### Attachments, email, and privacy

- Only download attachments from the portal. Do not forward restricted files through personal email or unmanaged storage.
- A blocked/scanning file is not evidence of a failed request; wait for status or contact support.
- Email contains a minimal notification/link, not the complete decision record. Marking it unread does not change a deadline.
- Do not paste restricted request content into public AI tools. The platform’s Azure OpenAI feature uses minimized, bounded data and remains advisory-only.
