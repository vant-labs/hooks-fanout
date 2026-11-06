# OWASP Security Report

Copyright (c) 2026 Vant Inc.

This is an OWASP Top 10 and API Security Top 10 alignment review of
`paystack-fanout`. It is an engineering assessment, not an OWASP certification
or a production penetration test. Production verification, infrastructure
controls, database permissions, TLS configuration, and secret rotation remain
deployment responsibilities.

## Reviewed evidence

- Outbound and provider URL validation: `src/app.rs::valid_public_http_url`,
  `src/provider.rs::safe_provider_url`, and request-time DNS resolution and
  address pinning in `src/security.rs::public_http_client`.
- Global response headers: `src/app.rs::add_security_headers`.
- Proxy trust: `src/app.rs::allowed_ip` and `AppState::trusted_proxy_cidrs`.
- Secret masking: `src/db.rs::mask_sensitive_headers` and
  `src/worker.rs::forwardable_header`.
- Authentication and CSRF: `src/auth.rs`, `src/dashboard.rs::login_submit`,
  and `api_authorized` in `src/app.rs`.
- Raw event access control: `src/dashboard.rs::event_detail` and
  `src/app.rs::get_event`.
- Exact-body relay authentication: `src/worker.rs::outbound_auth_value` and
  `tests/integration.rs::delivery_worker_uses_db_route_auth_and_exact_ingress_bytes`.
- CSV export formula neutralization: `src/dashboard.rs::csv_field` and
  `src/dashboard.rs::csv_tests::csv_formula_prefixes_are_neutralized`.
- Header coverage: `tests/dashboard.rs::security_headers_cover_dashboard_api_auth_failure_and_error_responses`.
- Dependency and secret scanning: `.github/workflows/ci.yml`,
  `.cargo/audit.toml`, and `.gitleaks.toml`.

## Findings

| ID | OWASP area | Severity | Finding | Remediation |
| --- | --- | --- | --- | --- |
| F-01 | A04 / API8 | Resolved | Public hostnames are syntactically validated, resolved at request time, rejected if any result is private/local, and pinned to the validated address for the request. | Retain network egress controls and revalidate this behavior when the HTTP client or resolver changes. |
| F-02 | A02 | Medium | `events.raw_body`, normalized payloads, headers, and response bodies remain plaintext in PostgreSQL. | Encrypt event data and backups, or provide equivalent database-level encryption and access controls. |
| F-03 | A07 | Medium | Login throttling is an in-memory per-process map and is not shared across replicas. | Use a shared limiter and require stronger administrator authentication policy. |
| F-04 | A03 | Resolved | CSV export prefixes values beginning with `=`, `+`, `-`, or `@` before CSV quoting. | Keep the neutralization test in place; prefer NDJSON when spreadsheet interoperability is unnecessary. |
| F-05 | A06 | Low | `cargo audit` has an allowed unmaintained `basic-toml` warning; the RSA advisory is limited to test-only key generation and explicitly ignored. | Replace the test dependency and monitor the Askama dependency chain. |
| F-06 | A05 | Low | HSTS is not emitted by the application, and API responses depend on the deployment edge for TLS policy. | Configure HSTS at the verified HTTPS edge; do not enable it for local HTTP. |

## Verified controls

The reviewed code verifies provider signatures before accepting events, limits
request size, uses parameterized SQL, encrypts configured secrets, masks
sensitive response fields, prevents inbound relay-header spoofing, disables
outbound redirects, requires trusted proxy CIDRs, uses CSRF protection, and
preserves exact ingress bytes for delivery.

The global response-header test covers dashboard success, API success, API
authentication failure, login authentication failure, and a 404 error. It also
asserts that HTTPS-default session cookies include `Secure`, `HttpOnly`, and
`SameSite=Lax`.

## Deployment-dependent controls

The application cannot prove from source alone that HTTPS termination, HSTS,
database encryption, restricted backend access, firewall rules, egress policy,
or production secret rotation are correctly configured. These must be verified
in deployment records before production approval.

The DNS control is application-level validation and pinning; it does not replace
an egress firewall or a deployment policy that denies private networks. The
dashboard formula control protects exported CSV values, but downstream spreadsheet
importers may apply additional interpretation rules.

## Production verification

Verification window: 2026-11-06 20:12–20:16 WAT (Africa/Lagos). The checks
below used low-volume public requests and redacted Railway metadata. No
credentials, cookies, tokens, raw provider bodies, or customer event payloads
are recorded here. This is evidence collection, not a production security
sign-off.

### Deployment and configuration evidence

| Control | Observed result | Redacted evidence | Limitation | Smallest remediation |
| --- | --- | --- | --- | --- |
| Deployed commit | Verified | Railway production deployment on `main`, commit `66ad769` (`Add login password visibility toggle (#33)`); deployment record created at `2026-11-06T19:12:22Z` and was `SUCCESS` when checked | This identifies the deployment but does not prove source-to-image provenance | Retain immutable build provenance and review the deployed commit before release |
| Public/backend networking | Partially verified | Public service domain maps to application port `8080`; one replica was configured in `europe-west4-drams3a` | No private backend restriction or firewall evidence was available from the read-only metadata | Restrict direct application access to the trusted edge and record the rule |
| Cookie security | Configured by default | `COOKIE_SECURE` was not present in the service variable names; application default is `true` | No authenticated session was available to inspect the live `Set-Cookie` header | Verify one approved login response contains `Secure; HttpOnly; SameSite=Lax` |
| Forwarded headers | Configured conservatively | `TRUST_PROXY` and `TRUSTED_PROXY_CIDRS` were not present; application defaults to not trusting forwarded client addresses | The actual Railway edge path was not independently inspected | Keep proxy trust disabled unless the direct peer and CIDR allowlist are documented |
| Authentication debug logging | Not compliant with the documented default | `FANOUT_DEBUG_AUTH=1` was present in the production variable names and is enabled by value | A follow-up cleanup was not authorized during this review | Unset it after the approved troubleshooting window and confirm logs no longer contain debug records |
| Database and encryption key configuration | Presence only | Database and encryption-key variable names were present; values were not inspected or recorded | PostgreSQL encryption at rest, backups, access policy, and key rotation were not verifiable from the application endpoint or metadata | Provide provider-level encryption, backup, access, and rotation evidence |

### Public HTTPS and response-header evidence

Each row was requested separately over the public production endpoint during the
verification window. `Strict-Transport-Security` was not observed in these
responses; this does not prove the entire TLS edge configuration without access
to the edge policy.

| Request | Result | Observed headers |
| --- | --- | --- |
| HTTP `/` | `301` to HTTPS | `Location: https://…/` |
| HTTPS `/healthz` | `200` | `X-Content-Type-Options: nosniff`; `Referrer-Policy: no-referrer`; `Content-Security-Policy: frame-ancestors 'none'`; `X-Frame-Options: DENY` |
| HTTPS `/readyz` | `200` JSON | Same global headers |
| HTTPS `/login` | `200` HTML | Full same-origin CSP with `form-action 'self'`, plus the global headers |
| HTTPS `/not-a-route` | `404` | Same global headers |
| HTTPS `/admin/routes` without a session | `401` | Same global headers |
| HTTPS `/dashboard/events/live` without a session | `401` | Same global headers |
| HTTPS `/dashboard/overview/live` without a session | `401` | Same global headers |
| HTTPS `/metrics` | `200` text | Same global headers |
| HTTPS `/docs/` | `200` HTML | Same global headers |

TLS negotiation used HTTP/2 with certificate verification successful. The
certificate presented for the public hostname was issued by Let's Encrypt and
was valid from `2026-09-27` through `2026-12-26` at verification time.

### Authorization, sessions, and throttling

Unauthenticated access to admin routes and both dashboard SSE endpoints was
rejected with `401`. No authenticated browser session was available in the
verification environment, so the following remain unverified in production:

- live `Set-Cookie` attributes after login;
- CSRF rejection on a mutating dashboard request;
- Owner/Admin/Viewer source and route permissions;
- authenticated SSE data access and session expiry;
- masking of production event headers and payloads.

Repository evidence for these controls remains `src/auth.rs`, `src/app.rs`,
`src/dashboard.rs`, and `tests/dashboard.rs`.

The service metadata showed one production replica. The login limiter is an
in-memory process-local map in `src/dashboard.rs`, so there is no evidence of a
shared limiter across replicas. No brute-force, lockout, load, or failure
injection test was attempted.

### Storage, backups, and operational access

No production database shell, backup policy, log-retention policy, or access
control evidence was available through the read-only surfaces used here. These
controls are therefore **unverified**, not failed. HTTP headers and repository
code cannot prove database-at-rest encryption, backup encryption, restricted
database access, log retention, log-reader permissions, or secret rotation.

The last 100 available structured Railway log records contained no matching
Google authentication-debug or webhook-authentication-failure record. This is
not evidence that such records do not exist outside that window.

### Provider delivery verification

No redacted provider-test record with a matching Timamu receipt was available
through the public endpoint or the available Railway log window. No production
event was replayed and no new provider notification was sent.

If fresh verification is approved, send exactly one test for each path:

1. Google source `google_production`, route `timamu-google-play`, destination
   `/v1/webhooks/google`; expected result is provider-test acceptance with no
   entitlement grant.
2. Apple source `apple_sandbox`, route `timamu-apple-pay-sandbox`, destination
   `/v1/webhooks/apple`; expected result is test-notification acceptance with
   no entitlement grant.

Approval must precede those requests because they create events, logs, and
delivery attempts. Exact-body and relay-signature acceptance can only be
claimed when Timamu receiver-side evidence confirms HMAC verification over the
received bytes and confirms the test notification did not change entitlement
state. An HTTP `200` alone is insufficient.
