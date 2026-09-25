# Requirements and traceability

## 1. Requirement method

Requirements use stable IDs. `P0` is mandatory for initial production release; `P1` is mandatory before the stated later milestone. Baseline `U` means **implementation is unverified**: a static source artifact may exist, but no release-linked reproducible evidence was supplied. Planned evidence paths are targets, not existing artifacts.

## 2. Architecture and configuration

| ID | Pri | Requirement | Design location / intended implementation | Required evidence | Baseline |
|---|---|---|---|---|---|
| ARC-01 | P0 | FastAPI shall be the sole authoritative business/API boundary. | `backend/app/api/routes/`, `backend/app/services/` | Route inventory, architecture test, API contract suite | U |
| ARC-02 | P0 | React/Vite shall render UI and call only same-origin application APIs; it shall contain no secrets, privileged tokens, or direct data-service credentials. | `frontend/src/` | Static bundle/secret scan, browser network test | U |
| ARC-03 | P0 | SQLAlchemy shall be the only supported relational access layer. Production shall use PostgreSQL; SQLite shall be rejected by production configuration. | `backend/app/db/`, `backend/app/core/` | Settings test, DB startup guard, PostgreSQL integration suite | U |
| ARC-04 | P0 | API and worker deployments shall be independently scalable and shall not share an ad hoc database connection. | `backend/app/`, deployment manifests TBD | Deployment test, load/soak report | U |
| ARC-05 | P0 | All mutable configuration shall be external to code; secrets shall come from an approved secret manager and shall never be logged or committed. | `backend/app/core/`, Key Vault adapter TBD | Secret scan, configuration inventory, rotation test | U |
| ARC-06 | P0 | Startup shall fail closed for missing/invalid security-critical settings and shall expose no secret values in errors. | `backend/app/core/` | Negative settings tests, log review | U |
| ARC-07 | P1 | Availability objectives, RPO, RTO, data residency, retention, and recovery cadence shall be approved before go-live. | `05-operations-and-guides.md` | Signed service objectives and recovery exercise | U |

## 3. Identity, sessions, and authorization

| ID | Pri | Requirement | Design location / intended implementation | Required evidence | Baseline |
|---|---|---|---|---|---|
| IAM-01 | P0 | Workforce authentication shall use Entra ID Authorization Code flow with PKCE, backend callback, state, and nonce. Implicit/hybrid and password collection through normal UI are prohibited. | `backend/app/api/routes/`, `backend/app/integrations/` | OIDC conformance and negative tests, registered redirect evidence | U |
| IAM-02 | P0 | The callback shall validate signature/algorithm, issuer, audience, tenant, nonce, time claims, and redirect binding before account/session creation. | `backend/app/services/`, OIDC adapter TBD | Claim-validation unit tests and captured sanitized test result | U |
| IAM-03 | P0 | Browser authentication shall use a cryptographically random opaque session identifier; only a hash of the identifier shall be stored server-side. JWTs shall not be persisted in browser storage. | `backend/app/models/`, `backend/app/core/` | Cookie/storage inspection, session-store inspection, rotation tests | U |
| IAM-04 | P0 | Session cookies shall be host-only, `Secure`, `HttpOnly`, appropriately path-scoped, use approved SameSite behavior, and rotate on login/privilege change. | Auth/session middleware TBD | Response-header and fixation tests | U |
| IAM-05 | P0 | Sessions shall have approved absolute and idle expiry, server-side revocation, logout cleanup, and re-authentication for privileged actions. | Session service TBD | Expiry/revocation tests and policy approval | U |
| IAM-06 | P0 | State-changing browser requests shall require a session-bound anti-CSRF token in addition to secure cookies. | API middleware TBD | Positive/negative CSRF tests | U |
| IAM-07 | P0 | Authorization shall be deny-by-default, enforced on every backend route and object, and based on server-side permissions—not UI visibility. | `backend/app/services/` | Route/permission matrix, BOLA/IDOR tests | U |
| IAM-08 | P0 | A requester shall not approve or reject their own request; final approval shall require an authorized approver and recorded separation of duties. | Workflow service TBD | Self-approval and concurrent-role tests | U |
| IAM-09 | P0 | Local break-glass authentication shall be separate from normal OIDC, disabled unless explicitly enabled, bound to an approved local/admin path, MFA-protected, rate-limited, uniquely attributable, and fully audited. It shall not be a fallback after OIDC failure. | `backend/app/api/routes/`, `backend/app/core/` | Configuration test, remote-denial test, MFA/audit exercise | U |
| IAM-10 | P0 | Role assignments and policy mappings shall be versioned, least-privilege, time-bounded where appropriate, and auditable. | RBAC tables, admin service TBD | Role review, assignment/audit tests | U |
| IAM-11 | P1 | Privileged/export/download/admin actions shall require step-up authentication and emit security alerts. | Policy TBD | Step-up and alert tests | U |

## 4. Data and audit integrity

| ID | Pri | Requirement | Design location / intended implementation | Required evidence | Baseline |
|---|---|---|---|---|---|
| DAT-01 | P0 | Business data shall be normalized; repeating groups, users, roles, transitions, decisions, and delivery attempts shall not be encoded as JSON or delimited strings in PostgreSQL. | `backend/app/models/`, ERD in `03-data-and-api.md` | Schema review, normalization tests | U |
| DAT-02 | P0 | Stable opaque identifiers shall be used; display names and sequential IDs shall not be authorization keys. | Models/migrations TBD | Schema and API tests | U |
| DAT-03 | P0 | Foreign keys, uniqueness, check constraints, state enums, and optimistic concurrency shall be enforced in PostgreSQL. | `backend/alembic/versions/` | Migration test on clean/upgraded DB | U |
| DAT-04 | P0 | Every schema change shall have a reviewed Alembic migration and a tested forward path; destructive changes shall use expand/contract deployment. | `backend/alembic/versions/` | CI migration matrix and rollback/restore plan | U |
| DAT-05 | P0 | Times shall be stored in UTC with timezone semantics; validity and expiry evaluation shall use server time. | Models/services TBD | Clock-boundary tests | U |
| DAT-06 | P0 | Request state, transition, and audit event shall commit atomically with its outbox event. | `backend/app/services/`, `backend/app/models/` | Forced-failure transaction test | U |
| DAT-07 | P0 | Audit events shall be append-only, canonicalized, hash-chained, and periodically anchored to independently protected storage. | Audit service/models TBD | Tamper/reorder/deletion/anchor tests | U |
| DAT-08 | P0 | Sensitive fields shall be encrypted in transit and at rest; approved fields shall use application-level envelope encryption where database encryption is insufficient. | Storage/DB configuration TBD | Configuration review and key-rotation test | U |
| DAT-09 | P0 | Retention, legal hold, deletion, anonymization, and export rules shall be data-classification specific and approved. | Operations/data inventory TBD | DSR test, retention job evidence, restore test | U |

## 5. Workflow, jobs, and notifications

| ID | Pri | Requirement | Design location / intended implementation | Required evidence | Baseline |
|---|---|---|---|---|---|
| WF-01 | P0 | Workflow transitions shall follow an explicit state machine; callers shall invoke commands, not submit arbitrary status/actor/role fields. | `backend/app/services/` | State-model/property tests and API schema review | U |
| WF-02 | P0 | Each transition shall re-check object authorization, current state, version, separation of duties, and validity under the database transaction. | Transaction service TBD | Concurrency and bypass tests | U |
| WF-03 | P0 | State-changing requests shall support idempotency and shall not create duplicate approvals, audit events, or notifications on retry. | API/service TBD | Duplicate/retry tests | U |
| WF-04 | P0 | Domain changes and their outbox records shall be one atomic PostgreSQL transaction. | `backend/app/services/`, `backend/app/models/` | Transaction fault-injection test | U |
| WF-05 | P0 | Outbox consumers shall claim work safely, use stable event IDs and idempotency keys, retry with bounded exponential backoff/jitter, and enter an operator-visible dead-letter state after the approved limit. | `backend/app/workers/` | PostgreSQL concurrency, retry, poison-message, DLQ tests | U |
| WF-06 | P0 | Workers shall be least-privileged and shall not assume browser/user authorization context. | Worker identities/configuration TBD | Worker permission test and identity review | U |
| WF-07 | P0 | Notifications shall be derived from committed events and shall contain only approved, minimized data; raw attachments, secrets, and restricted free text shall not be sent. | Templates/provider adapter TBD | Template review, content-capture tests | U |
| WF-08 | P0 | Email/provider delivery shall be idempotent and shall handle retry, bounce, complaint, suppression, and dead-letter outcomes. | `backend/app/integrations/`, `backend/app/workers/` | Provider sandbox contract test | U |

## 6. File quarantine and malware scanning

| ID | Pri | Requirement | Design location / intended implementation | Required evidence | Baseline |
|---|---|---|---|---|---|
| FILE-01 | P0 | Uploads shall enter a private quarantine container/prefix through a controlled backend or brokered upload; client filenames shall never form storage paths. | `backend/app/api/routes/`, storage adapter TBD | Path traversal and direct-access tests | U |
| FILE-02 | P0 | Uploads shall be bounded by count, per-file size, total size, allowed content type, extension, and decompression/resource limits before and during processing. | Upload service TBD | Boundary, slow-upload, archive/polyglot tests | U |
| FILE-03 | P0 | Objects shall remain unavailable to users until an automated ClamAV integration point returns a current `clean` result for the exact object checksum/version. | `backend/app/integrations/`, `backend/app/workers/` | EICAR, stale-result, checksum-change tests | U |
| FILE-04 | P0 | Scan timeout, unavailable scanner, malformed result, or unknown signature shall fail closed and place the object in a visible blocked state. | Scan worker TBD | Fault-injection tests | U |
| FILE-05 | P0 | Downloads shall be authorization-checked, streamed with safe headers, and served only from the clean store; object keys/URLs shall not grant access. | Download route/storage adapter TBD | BOLA, header, presigned-URL tests | U |
| FILE-06 | P0 | Object creation, scan, promotion, block, download, and deletion shall be audited; audit shall record IDs/checksums, not sensitive file contents. | Audit events TBD | Audit integration tests | U |
| FILE-07 | P0 | Object encryption, least-privilege identities, versioning/immutability where required, lifecycle, and malware-data handling shall be configured outside code. | Storage/Key Vault configuration TBD | Provider configuration export and restore test | U |
| FILE-08 | P1 | Operators must not bypass quarantine by default; any emergency bypass needs dual approval, expiry, incident linkage, and audit. | Admin procedure TBD | Tabletop/exercise evidence | U |

## 7. Azure OpenAI advisory boundary

| ID | Pri | Requirement | Design location / intended implementation | Required evidence | Baseline |
|---|---|---|---|---|---|
| AI-01 | P0 | Azure OpenAI shall be advisory-only: output shall never approve/reject, transition state, grant access, execute tools, send unrestricted communications, or change policy. | `backend/app/integrations/`, `backend/app/services/` | Architecture review and negative automation tests | U |
| AI-02 | P0 | Only server-side code shall hold model credentials/call the configured endpoint; egress destinations shall be fixed by configuration and allowlisted, never user controlled. | Integration adapter/deployment TBD | Bundle scan, egress policy, SSRF tests | U |
| AI-03 | P0 | System instructions, schemas, and policy text shall be separated from untrusted request text and attachment-derived content; embedded instructions shall be treated as data. | Prompt builder TBD | Prompt-boundary and injection test corpus | U |
| AI-04 | P0 | Model calls shall minimize/redact data by classification, enforce token/character/time/cost budgets, and shall not send raw attachments by default. | Prompt builder/logging TBD | Payload inspection and budget/fail-safe tests | U |
| AI-05 | P0 | Responses shall be treated as untrusted, length-bounded, schema-validated, allowlisted, and safely rendered; invalid output shall be rejected and never interpreted as code or HTML. | `backend/app/schemas/`, frontend renderer TBD | Schema fuzz tests and XSS tests | U |
| AI-06 | P0 | Advice shall be visibly labeled with model/deployment, prompt/schema version, generation time, and a human-decision disclaimer. | UI/API TBD | UI/API contract and accessibility review | U |
| AI-07 | P0 | Raw prompts, raw responses, and related diagnostic payloads shall be retained for no more than 24 hours, protected, and deleted by an automated, evidenced process; provider retention must meet or beat this bound. | AI logging/configuration TBD | Retention configuration, deletion job, provider evidence, time-bound test | U |
| AI-08 | P0 | Model timeout/failure shall not grant an exception or corrupt workflow state; retry must be bounded and idempotent. | AI worker TBD | Timeout/retry/failure-state tests | U |
| AI-09 | P0 | AI input, output, model/prompt changes, validation failures, and human use/non-use shall be auditable without retaining restricted raw content beyond policy. | Audit service TBD | Audit/privacy review and event tests | U |
| AI-10 | P1 | Before use, privacy/legal review shall approve tenant, region, deployment, data residency, DPA, and prohibited classifications. | Governance record TBD | Signed approval and provider configuration | U |

## 8. Security, logging, and assurance

| ID | Pri | Requirement | Design location / intended implementation | Required evidence | Baseline |
|---|---|---|---|---|---|
| SEC-01 | P0 | TLS termination, service-to-service encryption, HSTS/security headers, trusted proxy handling, and CORS policy shall be configured and tested. | Deployment/API configuration TBD | Automated header/TLS scans | U |
| SEC-02 | P0 | Structured logs shall use correlation IDs and redact secrets, tokens, cookies, raw prompts, restricted text, and object contents. | Logging configuration TBD | Log-capture secret/PII tests | U |
| SEC-03 | P0 | Security and business events shall be monitored, alerted, retained, and synchronized to a protected destination. | Monitoring TBD | Alert injection and retention evidence | U |
| SEC-04 | P0 | CI shall run tests, SAST, dependency/SBOM/container scans, secret scanning, IaC scanning, and artifact signing/provenance checks. | `.github/workflows/` | Signed CI run and scan reports with no blocking findings | U |
| SEC-05 | P0 | Dependencies and base images shall be pinned, supported, and scanned; critical/high exploitable findings block release. | Build manifests TBD | SBOM and vulnerability report | U |
| SEC-06 | P0 | An independent threat model and penetration test shall cover authn/authz, workflow, APIs, uploads, SSRF/egress, AI, and privileged paths. | `04-security-and-risk.md` | Approved report and remediation verification | U |
| SEC-07 | P0 | Debug endpoints, interactive OpenAPI/docs, default credentials, and unnecessary production metadata shall be disabled. | Settings/routes TBD | Production configuration scan | U |

## 9. Operations and lifecycle

| ID | Pri | Requirement | Design location / intended implementation | Required evidence | Baseline |
|---|---|---|---|---|---|
| OPS-01 | P0 | Local development shall use isolated credentials/data and SQLite only for tests; production startup shall reject SQLite. | `05-operations-and-guides.md` | Automated guard tests and local test record | U |
| OPS-02 | P0 | Entra ID, email, storage, ClamAV, Azure OpenAI, and Key Vault shall have documented owners, timeouts, health checks, and failure behavior. | Integration inventory TBD | Configuration review and sandbox smoke tests | U |
| OPS-03 | P0 | Database and object backups shall be encrypted, isolated, protected from ordinary admin credentials, and periodically restore-tested. | Backup design TBD | Restore exercise with measured RPO/RTO | U |
| OPS-04 | P0 | Schema/API/worker upgrades shall use version compatibility, expand/contract migrations, canary validation, and a tested rollback or restore path. | Release runbook TBD | Staging upgrade and rollback/restore record | U |
| OPS-05 | P0 | Key and certificate rotation shall be documented and rehearsed without exposing plaintext secrets. | Key Vault runbook TBD | Rotation evidence and service-continuity test | U |
| OPS-06 | P0 | Health, metrics, logs, traces, queue depth, scan backlog, outbox age, DLQ count, auth failures, and audit-anchor failures shall be observable. | Observability design TBD | Dashboard and alert exercise | U |
| OPS-07 | P0 | Incident runbooks shall cover identity outage, database outage, storage/scanner failure, notification failure, AI failure, audit-chain failure, and break-glass use. | `05-operations-and-guides.md` | Tabletops and post-incident evidence | U |
| OPS-08 | P0 | Administrative actions shall be separated from request decisions, individually attributable, time-bounded, and audited. | Admin RBAC/runbook TBD | Admin role and action audit review | U |
| DOC-01 | P0 | Architecture, API, data, threat, and operations documentation shall be versioned with the release. | `docs/` | Documentation review record | U |
| DOC-02 | P0 | User, administrator, SSO owner, support, backup, restore, and incident guides shall be approved for their audiences. | `05-operations-and-guides.md` | Audience sign-off | U |
| DOC-03 | P0 | Acceptance evidence shall be reproducible, release-linked, access-controlled, and free of production secrets/restricted data. | `docs/evidence/<release>/` | Evidence index and reviewer attestation | U |
| DOC-04 | P0 | Open gaps, accepted exceptions, owners, expiry, and compensating controls shall remain visible through release. | `06-acceptance-and-production-gates.md` | Signed exception register, empty or approved blockers | U |

## 10. Major-section coverage matrix

| Major section | Governing requirement IDs | Detailed specification | Acceptance proof |
|---|---|---|---|
| Scope, assumptions, roles | ARC-01–07 | `02-architecture.md` §§1–3 | Architecture decision and role review |
| Components and deployment | ARC-01–07, SEC-01, OPS-02, OPS-06 | `02-architecture.md` §§4–7 | Deployment/IaC review and runtime evidence |
| Data model and migrations | DAT-01–09 | `03-data-and-api.md` §§1–3 | PostgreSQL migration/schema tests |
| Workflow and state | WF-01–03, DAT-06 | `03-data-and-api.md` §§4–5 | State/property/concurrency tests |
| API boundaries | ARC-01–02, IAM-06–07, SEC-07 | `03-data-and-api.md` §6 | Contract, BOLA, schema, and header tests |
| Files and malware | FILE-01–08 | `02-architecture.md` §8; `03-data-and-api.md` §7 | EICAR and storage security evidence |
| Authentication and sessions | IAM-01–11 | `04-security-and-risk.md` §§1–3 | OIDC/session/MFA/RBAC tests |
| AI trust boundary | AI-01–10 | `04-security-and-risk.md` §5 | Prompt/schema/retention/adversarial tests |
| Outbox and notifications | WF-04–08, DAT-06 | `02-architecture.md` §9; `03-data-and-api.md` §8 | Fault-injection and provider tests |
| Audit and monitoring | DAT-07, SEC-02–03, OPS-06 | `04-security-and-risk.md` §6 | Hash-tamper and alert exercises |
| Local, deployment, integrations | ARC-03–06, OPS-01–02, OPS-05–07 | `05-operations-and-guides.md` §§1–9 | Runbooks, staging deployment, exercises |
| Backup, restore, upgrade | ARC-07, DAT-04, OPS-03–04 | `05-operations-and-guides.md` §§6–7 | Restore and upgrade records |
| Admin, break-glass, user | IAM-09–11, OPS-08, DOC-02 | `05-operations-and-guides.md` §§9–10 | Role review and scenario exercises |
| OWASP and threat review | SEC-01–07, IAM-01–11, AI-01–10, FILE-01–08 | `04-security-and-risk.md` §§7–10 | Independent security closure |
| Acceptance and release | All `P0`; DOC-03–04 | `06-acceptance-and-production-gates.md` | Signed gate record |

## 11. Explicit baseline gaps

At baseline, all requirements above are `U` (unverified). Static source may implement parts of a requirement, but no release-linked test, migration, deployment, integration, security, restore, or approval evidence substantiates `E` or `V`. This matrix is a release contract, not a compliance claim.
