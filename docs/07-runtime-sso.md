# Runtime SSO security notes

Runtime SSO configuration is stored in the dedicated `sso_providers`,
`sso_provider_configs`, `sso_external_identities`, `sso_secret_records`, and
`sso_login_transactions` tables. Secrets and private keys are encrypted before
they are written and are never placed in `SystemConfig` or returned by an API.

## Protocols

* OIDC uses Authorization Code flow with PKCE S256. State, nonce, the PKCE
  verifier, browser binding, and SAML RelayState/request IDs are one-time
  values. Only their SHA-256 hashes are queryable; the protocol envelope is
  encrypted and transactions are claimed and consumed atomically.
* The active configuration version is captured in the transaction. A callback
  is rejected after an administrator rotates or disables that version.
* SAML is SP-initiated only. The ACS requires a signed response/assertion,
  exact destination, audience, issuer, ACS recipient, request ID, and current
  time window. IdP-initiated/unsigned/replayed responses fail closed. Raw
  `SAMLResponse` values are never logged or stored.

## Key management limitation

This local implementation uses the existing `APP_ENCRYPTION_KEY` as a
single Fernet key-encryption key for SSO secrets and for the generated SP
private key. It is suitable for a single-instance local deployment, but it is
**not** a production key-management system:

* there is no external KMS/HSM or per-secret data-encryption key;
* rotating `APP_ENCRYPTION_KEY` requires an explicit re-encryption/migration
  procedure and invalidates existing ciphertext if performed incorrectly;
* the temporary PEM files needed by PySAML2/xmlsec exist only for the lifetime
  of a request and are removed by the runtime;
* operators must restrict database and process access, use TLS, rotate the
  application key through a controlled migration, and monitor key-version
  changes.

Production deployments should replace this adapter with a KMS/HSM-backed
envelope-encryption provider and a managed certificate/key rotation process.
The native `xmlsec1` runtime is declared in the Python dependencies and
Docker image; SAML login fails closed if either PySAML2 or xmlsec is absent.

The legacy `OIDC_*` environment settings are a disabled bootstrap view only.
They cannot enable a login when a database SSO configuration exists (or when
no configuration exists); an administrator must create and review a versioned
database configuration first.
