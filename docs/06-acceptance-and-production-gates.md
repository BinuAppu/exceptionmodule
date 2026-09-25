# Acceptance evidence and production gates

## 1. Honest status statement

**The exception-management platform is not production-approved.** A static source snapshot contains backend/frontend/build artifacts, but no release-linked executable test result, migration run, deployment evidence, external-integration validation, security assessment, restore exercise, or acceptance package was supplied to verify this requirements set.

Production approval may be reconsidered only after the external integrations and tests below are implemented in the release candidate and independently validated. Design diagrams, intended paths, sample configuration names, and this document are not implementation evidence.

## 2. Evidence rules

Acceptance evidence must be:

1. **Release-specific:** linked to the exact commit, immutable backend/frontend artifact digests, frontend asset digest, migration revision, configuration/schema version, and deployment environment.
2. **Reproducible:** a reviewer can identify inputs, commands/procedure, expected result, actual result, timestamps, environment, and tool versions.
3. **Machine-verifiable where appropriate:** immutable CI/test/scan output, signed attestations, database/query evidence, or provider exports—not only screenshots or prose.
4. **Sanitized:** no production secrets, tokens, cookies, raw OIDC claims, restricted requests/evidence, email addresses where unnecessary, or raw AI prompt/response content.
5. **Independently reviewed:** author evidence is not sufficient approval for security, privacy, backup/restore, or high-risk workflow controls.
6. **Traceable:** each result links requirement IDs, environment, artifact, defect/exception IDs, and disposition.
7. **Retained:** according to approved evidence retention and legal/security policy. Repository `storage/backups/` and `storage/exports/` are not evidence repositories.

A pass is valid only for the tested artifact/configuration. A source change, dependency change, model/prompt/schema change, identity mapping change, or infrastructure change requires impact analysis and rerun of affected evidence.

## 3. Baseline evidence inventory

| Evidence area | Expected location | Baseline observation | Status / production effect |
|---|---|---|---|
| Architecture/requirements | `docs/01-requirements-and-traceability.md` through this document | Design documents now exist | `Specified`; not implementation proof |
| Backend source | `backend/app/` | Static core, model, schema, service, worker, route modules, and `backend/app/main.py` observed under active development; no release build/start result was supplied | `O/U`; all runtime claims remain blocked |
| Database migrations | `backend/alembic/`, `backend/alembic/versions/` | Alembic environment/config and an initial generated revision are present; no clean PostgreSQL/SQLite execution, schema diff, or upgrade evidence | `O/G`; data/upgrade gates blocked |
| Automated tests | `backend/tests/` and frontend test paths | No release test suite/result observed | `G`; functional/security gates blocked |
| Frontend source/build | `frontend/src/`, `frontend/package.json`, `frontend/dist/` | Static source and a local build tree are present; no provenance or API-contract test; source/backend contract drift was visible | `O/U`; UI claims blocked until aligned and tested |
| CI/CD | `.github/workflows/ci.yml` | Static workflow declares Ruff, Bandit, pytest, pip-audit, npm audit, and frontend build; no run result, SBOM, signing/provenance, PostgreSQL service, or coverage evidence supplied | `O/G`; build/provenance/scan gates blocked |
| Local containers | `Dockerfile`, `docker-compose.yml` | PostgreSQL/ClamAV/API/worker local topology is defined; not production IaC, HA, private networking, or deployment evidence | `O/U`; production deployment gate blocked |
| OIDC/Entra | `backend/app/core/config.py`, `backend/app/services/authentication.py`, `backend/app/api/routes/auth.py` | OIDC/session code exists statically; no tenant/protocol test; production PKCE/tenant controls require verification | `O/G`; IAM gates blocked |
| Email/SMTP | `backend/app/services/email.py`, `backend/app/workers/run.py` | SMTP/template code exists statically; no provider/DNS/delivery evidence | `O/G`; notification gate blocked |
| File quarantine/ClamAV | `backend/app/services/files.py`, `backend/app/workers/run.py`, `docker-compose.yml` | Local filesystem quarantine and ClamAV INSTREAM code exist; no object-store production adapter or malware/fault test evidence | `O/G`; file gate blocked |
| Azure OpenAI | `backend/app/services/ai.py`, `backend/app/workers/run.py` | Advisory service, prompt boundaries, strict schemas, and rolling 24-hour log-analysis window exist statically; no provider/privacy/evasive/retention test evidence | `O/G`; AI gate blocked |
| Key Vault/managed identity | Configuration/SecretRecord code; no deployment design observed | Static encrypted-secret/managed-identity intent exists; no Key Vault RBAC, private endpoint, or rotation evidence | `O/G`; secrets operations blocked |
| Audit integrity | `backend/app/services/audit.py`, `backend/app/models/entities.py` | HMAC-style linked events and ORM append-only guards exist statically; no independent anchor, database-privilege, concurrency, or tamper evidence | `O/G`; integrity gate blocked |
| Backup/restore | `backend/app/services/backups.py`, `storage/backups/` | Local `pg_dump`/encryption/hash intent exists; no managed PITR, object backup, isolated restore, or measured exercise | `O/G`; resilience gate blocked |
| Security review | `04-security-and-risk.md` | Static design/gap review only; no executed security suite or penetration report | `G`; penetration/ASVS closure blocked |
| Release evidence index | `docs/evidence/<release>/` | Absent | `G`; no candidate can be assessed |

## 4. Planned evidence package

The release owner should create a nonsecret evidence index at `docs/evidence/<release>/evidence-index.md` or link to the organization's approved evidence system. A practical layout is:

```text
docs/evidence/<release>/
  evidence-index.md
  test-results/
  security-scans/
  migrations/
  identity-and-access/
  workflow-and-authorization/
  files-and-malware/
  ai-boundary-and-retention/
  outbox-and-notifications/
  audit-integrity/
  deployment-and-observability/
  backup-restore-and-upgrade/
  approvals/
```

Binary artifacts, large sanitized reports, and sensitive provider exports may remain in the approved evidence repository if the index records their immutable digest, classification, location, retention, and access rule. Sanitized summaries may live under `docs/evidence/` only after security approval.

Every evidence item should record:

- Evidence ID and linked requirement/acceptance IDs.
- Release/commit and immutable artifact/migration/configuration versions.
- Environment and date/time zone.
- Owner, reviewer, and approver.
- Procedure/tool version and exact command or manual steps where safe.
- Expected and actual result.
- Artifact digest and storage classification.
- Defect, retest, and accepted-risk references.
- Expiry/revalidation date for configuration-dependent evidence.

## 5. Acceptance scenario matrix

All scenarios are `Not run` at baseline. A scenario passes only when its required evidence is reproducible and all blocking assertions succeed.

### 5.1 Build, database, and API

| ID | Scenario and procedure | Pass criteria | Required evidence | Status |
|---|---|---|---|---|
| AC-BLD-01 | Build protected commit with pinned dependencies; generate SBOM; scan source, dependencies, secrets, containers, and IaC; sign/provenance-check artifacts. | Reproducible artifacts; no secret; no unaccepted critical/high exploitable finding; signatures/provenance verify. | CI run, SBOM, scans, signature/attestation | Not run |
| AC-DB-01 | Run every Alembic migration from empty PostgreSQL and previous release; inspect constraints/indexes; test invalid states, duplicate joins, invalid intervals, and migration interruption/resume. | Clean/upgrade paths succeed; expected constraints reject invalid data; no production data loss/unbounded lock. | Migration logs, schema diff, negative SQL tests | Not run |
| AC-DB-02 | Exercise concurrent update/approve/expire commands against PostgreSQL with stale `If-Match`/version. | One valid winner; no duplicate transition/decision/audit/outbox; loser gets safe `409`. | Concurrency trace and database assertions | Not run |
| AC-API-01 | Compare implemented OpenAPI routes/schemas/permissions to approved contract; call unknown/unsupported methods, malformed JSON, duplicate fields, and missing CSRF. | Exact inventory; strict/bounded validation; no unsafe generic update; safe problem details; no stack/secret leakage. | Contract diff, schema/fuzz/API tests | Not run |
| AC-API-02 | Upload/download and list requests/attachments/advice/audit as every role with valid and guessed IDs. | Deny or minimize every out-of-scope object; no existence leak; response fields follow role; sensitive reads audited. | Role/object/field matrix and captured responses | Not run |
| AC-LIMIT-01 | Send bounded/oversized body, slow upload, search, export, advice, and parallel command traffic through edge/API. | Limits enforced before resource exhaustion; safe `413`/`429`; worker/model/DB pools protected; service remains healthy. | Load/resource telemetry | Not run |

### 5.2 Identity, session, and break-glass

| ID | Scenario and procedure | Pass criteria | Required evidence | Status |
|---|---|---|---|---|
| AC-IDP-01 | Complete valid Entra Authorization Code + PKCE login in an isolated test tenant. | Exact issuer/audience/tenant/nonce; secure cookie; minimal session; no token in URL/storage/log. | Sanitized protocol trace and browser inspection | Not run |
| AC-IDP-02 | Test forged signature, wrong algorithm, wrong issuer/audience/tenant/client, missing/bad nonce, expired/future token, state/code replay, canceled/failed callback, discovery substitution. | Every invalid case fails closed; no account/session; safe audit/telemetry. | OIDC negative test report | Not run |
| AC-IDP-03 | Test unmapped/disabled/deleted user, stale app-role/group mapping, group overage, and privilege removal. | No unintended role; disabled account cannot access; sensitive role change revokes/constrains session. | Role-mapping and lifecycle tests | Not run |
| AC-SES-01 | Inspect cookie flags/domain/path/name, local/session storage, logout, idle/absolute expiry, concurrent sessions, session rotation and fixation attempt. | Opaque token only in protected cookie; hash only server-side; expiry/revoke/rotation work; no persistence in web storage. | Browser/session-store evidence and tests | Not run |
| AC-SES-02 | Perform cross-site state-changing requests with valid session but missing/wrong CSRF token/Origin and test logout. | Unsafe requests rejected; legitimate CSRF/session controls work; logout revokes server-side. | CSRF test report | Not run |
| AC-BG-01 | With production ingress, scan for break-glass route; test disabled config, wrong local network, default credential, brute force, MFA, and public routing. | No public access; default-off; no shared/default credentials; MFA/rate limit/audit/alert enforced. | External/internal configuration and negative tests | Not run |
| AC-BG-02 | Execute approved dual-person emergency exercise: enable, login, minimal recovery action, revoke, rotate, review. | Minimal scope; complete immutable audit/alert; closure and credential/session rotation proven. | Signed exercise record | Not run |

### 5.3 Authorization and business workflow

| ID | Scenario and procedure | Pass criteria | Required evidence | Status |
|---|---|---|---|---|
| AC-AUTHZ-01 | Automate every role against every action/object/state in the approved matrix. | Exact allow/deny; backend enforces independently of UI; no unexpected wildcard permission. | Generated route map and test report | Not run |
| AC-AUTHZ-02 | Give one identity requester, reviewer, approver, administrator, and/or break-glass combinations; attempt self-decision and delegated emergency approval. | Self-approval denied; delegation explicit/time-bounded/audited; no role combination bypasses SoD. | SoD data and negative tests | Not run |
| AC-WF-01 | Create -> submit -> start review -> request changes -> edit/resubmit -> approve, with an assigned reviewer/approver. | Only legal transitions; every transition/decision/audit/outbox has exact version/actor; notifications reference committed events. | End-to-end database/UI/event evidence | Not run |
| AC-WF-02 | Attempt illegal skip/rollback/edit/reopen, expired validity, missing evidence, incorrect assignment, and direct generic status update. | All denied/validation errors; approved history immutable; no unauthorized active exception. | State-machine and abuse-case tests | Not run |
| AC-WF-03 | Withdraw/reject/revoke and expire approved requests; replay each command and run the expiry scheduler twice/concurrently. | One terminal transition; no resurrected state; duplicate commands/events harmless; downstream status if any reconciles. | Scheduler/concurrency/idempotency evidence | Not run |
| AC-IDEM-01 | Replay create, upload, decision, notification enqueue, and AI request with same/different idempotency keys and changed payloads. | Same intent is idempotent; reused key with different payload conflicts; no duplicate side effect. | API/database/provider assertions | Not run |
| AC-ABUSE-01 | Automated high-volume request creation, overlapping exceptions, search/export, and approval attempts. | Per-user/tenant quotas and anti-abuse controls protect service and policy; alerts fire; no mass assignment. | Abuse/load report and alert | Not run |

### 5.4 Outbox, notifications, and files

| ID | Scenario and procedure | Pass criteria | Required evidence | Status |
|---|---|---|---|---|
| AC-OUT-01 | Inject failure before commit, after commit/before publish, after side effect/before result, and during worker claim. | Domain/outbox atomicity holds; accepted work is retried; duplicate side effect is idempotent; no event loss. | PostgreSQL fault-injection evidence | Not run |
| AC-OUT-02 | Run concurrent workers, poison payload, retry storm, expired lease, DLQ, audited replay, and schema-version mismatch. | Safe claiming; bounded backoff/jitter; visible DLQ; no infinite retry/unauthorized replay; producer continues safely. | Queue/job trace and metrics | Not run |
| AC-MAIL-01 | Send each approved template to sandbox recipients; inspect payload/headers; test `2xx`, timeout, `429`, `5xx`, bounce, complaint, suppression, duplicate and DLQ. | Minimal approved content; stable idempotency; correct delivery state; no decision change/attachment/raw prompt leakage. | Provider messages, templates, callback tests | Not run |
| AC-FILE-01 | Upload safe synthetic files plus filename traversal/Unicode confusion, wrong MIME, oversized/slow/multi-file, archive/polyglot/decompression cases. | Random quarantine key; limits enforced; no execution/traversal; safe errors/audit; no clean promotion. | File test corpus/results | Not run |
| AC-FILE-02 | Upload EICAR; test infected, clean, unknown signature, stale signature, malformed verdict, timeout/unavailable scanner, and retry exhaustion. | Infected/unknown/failure blocked; exact checksum/version needed; scanner integration evidence valid. | ClamAV version/verdict and state tests | Not run |
| AC-FILE-03 | Replace/mutate object after scan; direct bucket/key/presigned access; download from blocked/unscanned/wrong request. | Changed/stale result invalid; direct access denied; only authorized current clean object streams safely. | Storage/network/content assertions | Not run |
| AC-FILE-04 | Test AV signature update, scan backlog/quota, orphaned object, clean object without row, and row without object. | Fail closed; reconciliation detects/orphans are blocked/quarantined; alerts and safe drain procedure work. | Operations exercise | Not run |

### 5.5 AI, privacy, and audit

| ID | Scenario and procedure | Pass criteria | Required evidence | Status |
|---|---|---|---|---|
| AC-AI-01 | Invoke advice for synthetic approved cases; capture server-built request, model/deployment/prompt/schema versions, costs, and stored sanitized output. | No browser-selected endpoint/model/tool; approved data only; no raw attachment/secret; bounded call; schema-valid advice. | Sanitized payload/schema/evidence | Not run |
| AC-AI-02 | Run prompt-injection, role-play, encoded instruction, indirect attachment, sensitive-data, malicious HTML/URL/SQL, and fabricated-citation corpus. | Instructions in content are data; unsafe output rejected/escaped; no tool/action/state; question/limitation shown. | Adversarial evaluation report | Not run |
| AC-AI-03 | Inject timeout, `429`, malformed/oversized/unknown-field output, budget exhaustion, model outage, and retry. | Advice marked unavailable; core human workflow unchanged; bounded spend/retry; invalid output never rendered. | Failure/evaluation/cost telemetry | Not run |
| AC-AI-04 | Create restricted raw prompt/response at a known time, advance beyond 24 hours, run deletion, inspect DB/object/search/backup/provider configuration. | No routine raw record older than 24 hours; automated deletion evidence; provider bound met; structured advice remains only as policy allows. | Timed retention/deletion/provider evidence | Not run |
| AC-AUD-01 | Generate representative auth, denied access, role, workflow, file, AI, outbox, export, break-glass and admin events. | Required fields/correlation/result present; sensitive content absent; one ordered append-only chain; all sensitive reads/actions represented. | Audit query/evidence | Not run |
| AC-AUD-02 | Modify, delete, reorder, insert a fork, truncate, and privileged-rollback audit rows; test DB roles. | Tampering/gap/rollback detected and alerted; API/worker cannot update/delete; privileged tamper visible through independent anchor. | Attack test and anchor comparison | Not run |
| AC-PRIV-01 | Exercise data export, correction, deletion, legal hold, retention expiry, and backup expiry for each approved class. | Authorized/approved behavior; audit; restricted AI raw TTL never exceeded; no orphaned or over-retained data. | Privacy/DSR/retention evidence | Not run |

### 5.6 Operations and resilience

| ID | Scenario and procedure | Pass criteria | Required evidence | Status |
|---|---|---|---|---|
| AC-DEPLOY-01 | Deploy signed artifacts/Infrastructure to staging and production-like isolated tenant; run smoke/canary. | Public exposure matches design; health/security headers/private endpoints correct; artifact/config versions recorded. | IaC plan, deployment and smoke evidence | Not run |
| AC-OBS-01 | Trigger auth failure, queue backlog, scan outage, email/AI outage, audit-anchor failure, secret expiry, DB saturation and break-glass use. | Correct safe behavior and timely independent alerts; no secret/content in telemetry; runbooks recover safely. | Alert/dashboard/tabletop evidence | Not run |
| AC-BACKUP-01 | Review managed PostgreSQL/object/config/key/audit backup policy and run automated restore verification. | Encrypted/protected/isolated; scope and measured recovery meet approved objectives; no gap hidden by backup-success metric. | Provider exports and control review | Not run |
| AC-RESTORE-01 | Restore PostgreSQL and objects to an isolated recovery environment at an approved point; run the full restore runbook. | Measured RPO/RTO pass; migrations/config/identity valid; audit/outbox/files reconciled; smoke/SoD/clean tests pass; signed cutover. | Full timed exercise | Not run |
| AC-ROTATE-01 | Rotate OIDC, AI, email, storage, scanner, database, and encryption credentials/keys with planned overlap. | Consumers update; old credentials fail; no plaintext leak; sessions/tokens revoked as required; continuity holds. | Rotation/change evidence | Not run |
| AC-UPGRADE-01 | Upgrade previous release through expand/backfill/contract with current/previous clients and event workers. | No incompatible producer/consumer; migration locks/space acceptable; rollback or restore succeeds; audit/history retained. | Timed upgrade and recovery evidence | Not run |
| AC-PERF-01 | Run agreed load, soak, burst, and failover tests at projected peak plus approved headroom. | Approved latency/error/throughput/pool/queue/backlog objectives pass; no data loss, duplicate business effect, or audit gap. | Signed capacity report | Not run |
| AC-DR-01 | Exercise approved database/provider/region/identity failure scenarios and operational degradation. | Approved failover/continuity behavior meets RTO/availability; no split brain, unsafe local fallback, or unreconciled side effects. | DR exercise and issues closed | Not run |

## 6. Production gates

Status is `G` (open/blocking) for every gate at baseline. Owners are the expected accountable roles and must be replaced with named individuals in the release record.

| Gate | Accountable owner(s) | Exit criteria | Linked requirements / evidence | Status |
|---|---|---|---|---|
| PG-01 Governance and architecture | Product owner, service owner, security, privacy/data owner | Scope, assumptions, data classification, tenant model, RPO/RTO, architecture, threat model, ADRs, and all open decisions approved | ARC-01–07, SEC-06, AC-BLD-01 | G |
| PG-02 Identity and sessions | Identity owner, security, service owner | Entra OIDC app/tenant and all positive/negative tests, opaque session/CSRF, role mapping, lifecycle, rate/abuse controls pass | IAM-01–06, AC-IDP-01–03, AC-SES-01–02 | G |
| PG-03 Break-glass and privileged access | Security, identity, operations | Public denial, default-off, unique/MFA/dual-control implementation, exercise, alerts, rotation, and post-use controls pass | IAM-09–11, AC-BG-01–02 | G |
| PG-04 Authorization and workflow | Product owner, service owner, security, data owner | Route/object/field/state matrix and all BOLA, SoD, state, concurrency, idempotency, expiry/revoke tests pass | IAM-07–10, WF-01–03, AC-AUTHZ-01–02, AC-WF-01–03, AC-IDEM-01 | G |
| PG-05 Data, migration, and audit | Data owner, DBA/service owner, security | PostgreSQL schema/migrations/constraints pass; append-only privileges, hash chain, external anchor, export and tamper tests pass | DAT-01–09, AC-DB-01–02, AC-AUD-01–02 | G |
| PG-06 Files and malware | Security, data owner, service owner | Private quarantine/clean topology, all upload/scan/download/fault tests, reconciliation, retention and incident runbook pass | FILE-01–08, AC-FILE-01–04 | G |
| PG-07 Outbox and notifications | Service owner, messaging owner | Atomicity, concurrent workers, retries/DLQ/replay, schema compatibility, template minimization and real provider sandbox pass | WF-04–08, AC-OUT-01–02, AC-MAIL-01 | G |
| PG-08 AI, privacy, and advisory isolation | AI owner, privacy, security, data owner | Approved use/region/provider terms; egress/no-tools/prompt/output controls; adversarial tests; 24-hour deletion; human-only decisions pass | AI-01–10, AC-AI-01–04, AC-PRIV-01 | G |
| PG-09 Secure supply chain | Engineering, security, release owner | Reproducible signed build, SBOM, zero unaccepted blocking scans, artifact/IaC provenance and source protections pass | SEC-04–05, AC-BLD-01 | G |
| PG-10 External integration security | Service owner, integration owners | Entra, email, storage, ClamAV, Azure OpenAI, Key Vault timeouts/contracts/ownership/egress and secret rotation pass in production-like environment | OPS-02, OPS-05, IAM/FILE/AI/WF controls | G |
| PG-11 Deployment and observability | Platform/service/SRE owner | Approved IaC, private topology, canary, headers/TLS, quotas, dashboards, alerts and incident exercises pass | ARC-04–07, SEC-01–03, OPS-06–07, AC-DEPLOY-01, AC-OBS-01 | G |
| PG-12 Capacity, backup, restore, upgrade | Service owner, DBA/data owner, SRE/change manager | Approved capacity, timed restore and upgrade/rollback/failover exercises meet objectives with issues closed | ARC-07, DAT-04, OPS-03–04, AC-BACKUP-01, AC-RESTORE-01, AC-UPGRADE-01, AC-PERF-01, AC-DR-01 | G |
| PG-13 Security assessment | Independent security reviewer | Penetration test and OWASP ASVS/Top 10/API closure; no unaccepted critical/high issue; all required retests pass | `04-security-and-risk.md` §§12–15 | G |
| PG-14 Documentation and release | Product, service owner, support, security, data owner | User/admin/ops/SSO/incident/restore guides are current; evidence index complete; all P0 gates signed for exact release | DOC-01–04 | G |

### Gate decision rule

Production approval requires:

- every `P0` requirement linked to passing, release-specific evidence;
- all `PG-01` through `PG-14` gates approved with named owners;
- no open critical/high security defect or unaccepted material availability/privacy/integrity risk;
- no exception to a `P0` requirement unless the named accountable authority documents a time-bounded compensating control before release; a `P0` exception is not presumed acceptable;
- external Entra, email, storage, ClamAV, Azure OpenAI, and Key Vault behavior validated outside mocks in a production-like environment;
- rollback and restore evidence for the same release/configuration;
- a final release decision that records artifact/configuration/migration/evidence versions.

A green unit suite, successful deployment, or completed design review cannot override a failed gate.

## 7. Gate-to-requirement coverage

| Requirement group | Minimum closing gates |
|---|---|
| ARC-01–07 | PG-01, PG-09, PG-11, PG-12 |
| IAM-01–06 | PG-02 |
| IAM-07–08, IAM-10 | PG-04 |
| IAM-09, IAM-11 | PG-03 |
| DAT-01–06, DAT-08–09 | PG-05, PG-08, PG-12 |
| DAT-07 | PG-05 |
| WF-01–03 | PG-04 |
| WF-04–06, WF-08 | PG-07 |
| WF-07 | PG-07 |
| FILE-01–08 | PG-06 |
| AI-01–10 | PG-08 |
| SEC-01–03 | PG-11 |
| SEC-04–05 | PG-09 |
| SEC-06 | PG-13 |
| SEC-07 | PG-11, PG-13 |
| OPS-01 | PG-11 |
| OPS-02 | PG-10 |
| OPS-03–04 | PG-12 |
| OPS-05 | PG-10, PG-12 |
| OPS-06–07 | PG-11 |
| OPS-08 | PG-03, PG-04 |
| DOC-01–04 | PG-14 |

## 8. Security and standards closure

The OWASP ASVS, OWASP Top 10:2021, and OWASP API Security Top 10:2023 tables in `04-security-and-risk.md` are explicit gap registers. At closure:

1. Freeze the exact OWASP release and application/API/deployment version.
2. Map each applicable requirement to one or more release-specific tests/scans/reviews.
3. Mark `pass`, `fail`, or `not applicable` with rationale and reviewer.
4. Open a tracked defect for every failure; do not hide it in prose.
5. Retest fixes and retain both failing and passing evidence according to policy.
6. Obtain independent security review for all critical/high paths.
7. Record accepted residual risk and expiry where formally permitted.

This mapping is not an OWASP certification and must not be represented as one.

## 9. Release sign-off template

| Role | Name | Decision | Date/time | Artifact/config/evidence versions | Conditions or expiry |
|---|---|---|---|---|---|
| Product owner | TBD | Pending | — | TBD | TBD |
| Service owner | TBD | Pending | — | TBD | TBD |
| Identity/security owner | TBD | Pending | — | TBD | TBD |
| Privacy/data owner | TBD | Pending | — | TBD | TBD |
| DBA/platform/SRE owner | TBD | Pending | — | TBD | TBD |
| Independent security reviewer | TBD | Pending | — | TBD | TBD |
| Operations/support owner | TBD | Pending | — | TBD | TBD |
| Change/release authority | TBD | Pending | — | TBD | TBD |

Blank or pending sign-off means production approval is not granted.

## 10. Risk-exception register template

An exception is not valid until the accountable authority accepts it.

| ID | Requirement/gate | Gap and impact | Compensating control | Owner | Expiry | Acceptance authority | Evidence | Status |
|---|---|---|---|---|---|---|---|---|
| TBD | TBD | TBD | TBD | TBD | TBD | TBD | TBD | Open |

No risk exception is pre-populated by this document. Open `P0` exceptions, missing external integration tests, missing restore evidence, or unclosed critical/high findings block approval.

## 11. Final approval statement

No production approval can be inferred from the presence of this documentation, the directory layout, the Mermaid diagrams, proposed API paths, or proposed environment-variable names. The external Entra ID/OIDC, email, object storage, ClamAV, Azure OpenAI, Key Vault, append-only audit anchoring, backup/restore, upgrade, authorization, workflow, file, AI, and security tests must be implemented and independently validated for the exact release candidate.

**Current decision: NOT PRODUCTION-APPROVED — all production evidence and gates are open.**
