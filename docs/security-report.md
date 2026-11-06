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
