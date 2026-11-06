# OWASP Security Report

Copyright (c) 2026 Vant Inc.

This is an OWASP Top 10 and API Security Top 10 alignment review of
`paystack-fanout`. It is an engineering assessment, not an OWASP certification
or a production penetration test. Production verification, infrastructure
controls, database permissions, TLS configuration, and secret rotation remain
deployment responsibilities.

## Reviewed evidence

- Outbound and provider URL validation: `src/app.rs::valid_public_http_url`,
  `src/provider.rs::safe_provider_url`.
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
- Header coverage: `tests/dashboard.rs::security_headers_cover_dashboard_api_auth_failure_and_error_responses`.
- Dependency and secret scanning: `.github/workflows/ci.yml`,
  `.cargo/audit.toml`, and `.gitleaks.toml`.

## Findings

| ID | OWASP area | Severity | Finding | Remediation |
| --- | --- | --- | --- | --- |
| F-01 | A04 / API8 | Medium | Public hostnames are validated syntactically, but DNS results are not checked or pinned before outbound requests. DNS rebinding could reach a private address. | Resolve and validate every destination/provider address, then enforce egress controls or pin the validated address. |
| F-02 | A02 | Medium | `events.raw_body`, normalized payloads, headers, and response bodies remain plaintext in PostgreSQL. | Encrypt event data and backups, or provide equivalent database-level encryption and access controls. |
| F-03 | A07 | Medium | Login throttling is an in-memory per-process map and is not shared across replicas. | Use a shared limiter and require stronger administrator authentication policy. |
| F-04 | A03 | Low | CSV export quotes fields but does not neutralize spreadsheet formula prefixes. | Prefix values beginning with `=`, `+`, `-`, or `@`, or use NDJSON as the only raw export. |
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
