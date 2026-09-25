# Documentation control and map

## Purpose

This documentation set defines the target enterprise architecture, security requirements, operating model, and release evidence for an exception-management platform. It deliberately separates **requirements**, **design intent**, and **verified evidence**.

## Baseline and evidence status

Documentation baseline date: **2026-09-23**.

A static source snapshot now contains FastAPI/Python modules under `backend/app/`, React/Vite source under `frontend/src/`, and local build/runtime definitions including `backend/requirements.txt`, `frontend/package.json`, `Dockerfile`, and `docker-compose.yml`. The snapshot was under active development during documentation review. No release-linked test result, migration run, external identity/integration validation, deployment, security assessment, backup/restore exercise, or acceptance package was supplied. Therefore:

- source artifacts are described as **observed intent**, not successful execution or completed implementation;
- every requirement remains unverified until linked to reproducible evidence for the exact release candidate;
- a file, route, model, diagram, or build artifact does not prove that it is reachable, secure, correctly configured, or integrated;
- `backend/tests/` had no tests and `.github/workflows/ci.yml` had no supplied run result at the review snapshot; a FastAPI entry point and an initial Alembic revision appeared during active development but had no clean migration/build/test evidence;
- filenames under `backend/`, `frontend/`, and `docs/evidence/` are source/evidence ownership locations unless this document explicitly identifies a reviewed artifact;
- “must” and “should” are normative requirements; diagrams and tables are design intent unless a test and approval record prove otherwise;
- production approval is explicitly withheld until every applicable gate in `06-acceptance-and-production-gates.md` passes.

This statement prevents a static code snapshot from being mistaken for an as-built report, test certification, or production approval.

## Normative language

- **Must / shall:** mandatory for production approval.
- **Should:** required unless a documented risk assessment and named approver accept an exception.
- **May:** optional design choice.
- **TBD:** must be resolved before the related production gate can close.

## Status vocabulary

| Code | Meaning |
|---|---|
| `S` | Specified only; no source artifact mapped to the requirement |
| `O` | Static source expresses design intent, but nothing has been executed or verified |
| `U` | Implementation unverified; source may be present or absent (default release-matrix status) |
| `P` | Partially implemented with tested evidence; evidence is incomplete or failing |
| `E` | Implemented with reproducible evidence attached |
| `V` | Independently reviewed and accepted for the named release |
| `G` | Open gap or explicit production blocker |

A design review alone never changes `S` to `E` or `V`.

## Document map

| Section | Primary contents | Other detailed sections |
|---|---|---|
| `01-requirements-and-traceability.md` | Normative IDs, priorities, acceptance evidence, requirement-to-section matrix | All |
| `02-architecture.md` | Assumptions, roles, component/deployment architecture, state and worker workflows, trust boundaries | `03`, `04`, `05` |
| `03-data-and-api.md` | Normalized ERD, constraints, API boundary, state invariants, event and notification contracts | `02`, `04` |
| `04-security-and-risk.md` | OIDC/session/break-glass controls, RBAC, AI trust boundary, audit chain, threat model, OWASP review | `02`, `03`, `05` |
| `05-operations-and-guides.md` | Configuration, local/deployment, SSO, email, storage, Key Vault, backup/restore, upgrade, admin/user procedures | `02`, `04` |
| `06-acceptance-and-production-gates.md` | Evidence inventory, acceptance scenarios, explicit gaps, production gates, sign-off | All |

## Scope

### In scope

- Browser-based exception requests, review, approval/rejection, change requests, withdrawal, revocation, and expiry.
- Runtime OIDC/SAML controls, local key-management limitations, and deployment notes: `07-runtime-sso.md`.
- Internal workforce identity through Microsoft Entra ID using OIDC.
- A separate, emergency-only local break-glass administrator path.
- Authorization, request state, normalized PostgreSQL data, attachments in quarantine, malware scanning, notifications, and audit history.
- Advisory-only Azure OpenAI output with strict input/output boundaries and no autonomous action.
- Transactional workflow changes, an outbox, idempotent workers, operational recovery, and release evidence.

### Out of scope unless separately approved

- Public or anonymous registration.
- Native/mobile clients.
- Direct browser access to PostgreSQL, object storage, ClamAV, email providers, Azure OpenAI, or Key Vault.
- Autonomous AI approval, remediation, entitlement changes, or notifications containing restricted data.
- Multi-tenancy and cross-organization federation. The baseline assumes one enterprise tenant; a tenant key must be added before multi-tenant deployment.

## Architecture decision records

Material choices listed here should become versioned ADRs when implementation begins: opaque sessions over browser JWTs; backend-mediated OIDC; normalized PostgreSQL as system of record; transactional outbox; quarantine-before-scan; human-only decisions; and 24-hour maximum retention for raw AI prompts/responses.

## Maintenance rule

Any change to identity, authorization, data classification, state transitions, external egress, prompt boundaries, retention, backup, or recovery must update the related requirement IDs, diagrams, threat model, tests, and evidence index in the same change.
