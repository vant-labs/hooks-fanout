# Hooks Fanout

[![CI](https://github.com/vant-labs/hooks-fanout/actions/workflows/ci.yml/badge.svg)](https://github.com/vant-labs/hooks-fanout/actions/workflows/ci.yml)

Maintained by Vant Inc.

One durable webhook ingress for a single business account. It verifies Paystack, Apple, and Google Play notifications, stores the original request, and forwards those same bytes to the product endpoint selected by your routes.

Formerly Paystack Fanout. The GitHub repository moved from `vant-labs/paystack-fanout` to `vant-labs/hooks-fanout` because this process already accepts more than Paystack. The rename covers the repository only. The Rust package, release binary, and container entrypoint remain `paystack-fanout`. Provider ids, the default source slug `paystack_main`, header names, and environment variables are unchanged. The crate manifest still records `repository = "https://github.com/abdulhakim/paystack-fanout"`, and the OpenAPI document title remains `paystack-fanout API`.

## The problem

Paystack, App Store Server Notifications, App Store Connect, and Google Play each expect a URL, while several products may share one account. Hooks Fanout is that URL. Ingress checks the provider, writes the event to Postgres, and acknowledges the caller. A worker then delivers the stored body. Products keep their own endpoints and, for Paystack, their own signature check.

Sources, routes, and secrets for that one deployment live in Postgres and can be changed from the dashboard after the first boot.

```mermaid
flowchart LR
    P[Paystack] -->|raw POST| I["POST /in/{slug}"]
    AS[App Store Server Notifications V2] --> I
    GP[Google Play RTDN] --> I
    AC[App Store Connect webhooks] --> I
    I --> V[Provider verification]
    V --> D[(Postgres events)]
    D --> Q[(Postgres deliveries)]
    Q --> W[Delivery worker]
    W --> T[Configured HTTPS routes]
    D --> AD[Bearer admin API]
    B[Browser console] --> H[Cookie session]
    H --> AD
```

## Providers

Configure a source with one of these provider ids. `known_providers()` is what config validation accepts.

| Provider id | Ingress |
| --- | --- |
| `paystack` | JSON webhook. HMAC-SHA512 of the raw body in `x-paystack-signature`. An empty `allowed_ips` list accepts any peer; a non-empty list checks the TCP peer, or the first `X-Forwarded-For` address when `TRUST_PROXY=true` and that peer is inside `TRUSTED_PROXY_CIDRS`. |
| `apple_server_notifications` | App Store Server Notifications V2. The signed payload is checked against the bundled Apple root at `src/certs/apple/AppleRootCA-G3.cer`. A shared secret is not required. |
| `apple_connect_webhooks` | App Store Connect webhooks. `x-apple-signature` must be `hmacsha256=<hex>` over the raw body. |
| `google_play_rtdn` | Google Play real-time developer notifications delivered as an authenticated Pub/Sub push. A shared webhook secret is not required. The source needs `audience` and `service_account`. |

`provider_for` also resolves the aliases `apple` to App Store Server Notifications and `google` or `google_play` to Google Play RTDN. Config validation and `POST /admin/sources` accept the four ids in the table, so use those when creating a source.

Store notifications are mapped onto the shared kinds `purchase`, `renew`, `cancel`, `expire`, `grace`, `refund`, `revoke`, `upgrade`, and `downgrade`. Which kinds appear depends on the provider notification. Normalized store events set `provider` to `apple` or `google` for route matching. Paystack events keep the provider `event` string, and Paystack routing fields do not set `provider`. App Store Connect events keep the webhook `type` and `id` and are forwarded as the original body.

Setup for the store adapters is in [Apple App Store setup](docs/apple-store-setup.md) and [Google Play setup](docs/google-play-setup.md).

### App Store Connect webhooks

Create a source with provider `apple_connect_webhooks`. The adapter checks the body with that source secret, then forwards the body and `x-apple-signature`. The event type is `type` or `eventType`, the event id is `id` or `eventId`, and `app_identifier` is taken from an app id or bundle id on the payload, including `data.attributes.appId`.

In App Store Connect, open Users and Access, then Integrations, then Webhooks. Use the payload URL `/in/{slug}`, choose the app, set a secret, and select triggers. Current fixture families are build upload state, app version state, beta feedback crash, and beta feedback screenshot. Match a route on `app_identifier`, or set the fallback to `route:<name>` for the whole source. Keep these routes apart from payment routes.

Apple's current signing notes: [Manage webhooks](https://developer.apple.com/help/app-store-connect/manage-your-team/manage-webhooks), [Configuring and parsing webhook notifications](https://developer.apple.com/documentation/appstoreconnectapi/configuring-webhook-notifications), and [WebhookEventType](https://developer.apple.com/documentation/appstoreconnectapi/webhookeventtype).

## Routing

The first matching route wins, in this order:

1. `data.metadata.app`, or a `data.metadata.custom_fields` item whose `variable_name` is `app`.
2. Plan code prefix from `data.plan.plan_code`, `data.subscription.plan.plan_code`, or a string `data.plan`. For a normalized store event, the mapped licence is compared as the plan code.
3. Prefix of `data.reference`, then `data.subscription_code`, then `data.customer_code`.
4. `app_identifier`, compared with a bundle id or package name.
5. `environment`, which must be `production` or `sandbox` when set.
6. `provider`, compared with the normalized values `apple` or `google`.

A route that sets both `app_identifier` and `environment` must match both. A configured `provider` must match as well. Legacy Paystack matchers are optional: a store route can omit `metadata_app` and the prefixes.

`fallback.mode = "unrouted"` stores the event with no delivery and sends an alert when an alert URL is configured. `fallback.mode = "route:<name>"` delivers to that route. Google Play RTDN fills a missing environment from the source configuration, or from a source slug that ends in `_production` or `_sandbox`.

Paystack refund examples use `transaction_reference` rather than `reference`. The router reads `reference`, `subscription_code`, and `customer_code`, so a refund needs `metadata.app`, a fallback, or another matching field. Paystack's public event shapes differ by family; the router does not decode one fixed event struct. Payloads are stored as raw bytes. Field names used by the matchers are documented by [Paystack webhooks](https://paystack.com/docs/payments/webhooks/), [subscriptions](https://paystack.com/docs/payments/subscriptions/), [charge](https://paystack.com/docs/api/charge/), [transfers](https://paystack.com/docs/transfers/single-transfers/), and [refunds](https://paystack.com/docs/payments/refunds/).

[config.example.toml](config.example.toml) is a first-boot seed with a Paystack source, sample routes, and store sources. The blocks below are copied from that file. They are not the whole file. Replace destination URLs and identifiers before use.

```toml
[source.paystack_main]
provider = "paystack"
secret_env = "PAYSTACK_SECRET_KEY"
allowed_ips = ["52.31.139.75", "52.49.173.169", "52.214.14.220"]

[[route]]
name = "timamu"
destination_url = "https://your-destination.example/v1/webhooks/paystack"
match = { metadata_app = "timamu", plan_code_prefix = "PLN_tm", reference_prefix = "tm_" }

[fallback]
mode = "unrouted"
```

## Quick start

Rust and Docker are required. Postgres 16 is the version used by [docker-compose.yml](docker-compose.yml) and CI.

```sh
git clone https://github.com/vant-labs/hooks-fanout.git
cd hooks-fanout
cp .env.example .env
docker compose up -d postgres
git config core.hooksPath .githooks
```

`cargo` does not load `.env`. Export the variables the process and the Postgres tests expect. `MASTER_ENCRYPTION_KEY` must be 32 bytes, hex or base64. `FANOUT_ENCRYPTION_KEY` is accepted as an alternate name for that key. `PAYSTACK_SECRET_KEY` is the first-boot secret for the example Paystack source and is also required by the signed integration tests.

```sh
export DATABASE_URL=postgres://fanout:fanout@localhost:5432/fanout
export MASTER_ENCRYPTION_KEY="$(openssl rand -hex 32)"
export ADMIN_BOOTSTRAP_TOKEN="$(openssl rand -hex 24)"
export PAYSTACK_SECRET_KEY=sk_test_replace_me
export PUBLIC_BASE_URL=http://localhost:8080
cargo test
cargo run -- --role all
```

Every command, including `create-owner`, requires `DATABASE_URL`, `MASTER_ENCRYPTION_KEY` or `FANOUT_ENCRYPTION_KEY`, and `ADMIN_BOOTSTRAP_TOKEN` or `ADMIN_TOKEN`. The listener binds `0.0.0.0` and reads `PORT`, default `8080`. With the default source, the Paystack URL is `${PUBLIC_BASE_URL}/in/paystack_main`.

`--role` is `all` (default), `ingest`, or `worker`. `all` and `ingest` serve HTTP. `all` and `worker` run delivery, retention, and store reconciliation.

Create the first owner after migrations. The command refuses to run when an owner already exists, prompts twice, and requires a password of at least 12 characters. `FANOUT_OWNER_PASSWORD` and `FANOUT_OWNER_PASSWORD_CONFIRM` supply the password without a prompt.

```sh
cargo run -- create-owner --email owner@example.com
```

Open `/login`. `COOKIE_SECURE` defaults to true, so the session cookie is `Secure`. Set `COOKIE_SECURE=false` for local HTTP. `docker compose` sets that for the bundled `app` service. The image entrypoint is `/usr/local/bin/paystack-fanout`. Logging uses the crate target, for example `RUST_LOG=paystack_fanout=info`.

`POST /admin/bootstrap` with the bootstrap bearer token can create that first account as well. Send `{"email":"...","password":"..."}`.

## Configuration

`FANOUT_CONFIG` is optional. When it is unset or missing, startup seeds one Paystack source named `paystack_main`, no routes, fallback `unrouted`, and 45-day retention. That default source has an empty IP allowlist, so it accepts any peer until you set `allowed_ips`.

`secret_env` and other `*_env` keys are copied into encrypted Postgres columns while those stored values are still empty. Dashboard and admin edits after that replace the stored secret. The request body limit is 256 KiB.

Set `PUBLIC_BASE_URL` to the public origin. The Sources panel shows `https://your-host/in/{slug}` from that value. Source and route APIs:

- `GET` and `POST /admin/sources`, `PATCH` and `DELETE /admin/sources/{slug}`
- `GET` and `POST /admin/routes`, `PATCH` and `DELETE /admin/routes/{name}`

`RETENTION_DAYS` overrides retention and must be from 1 to 45. The default is 45. Delivered and dead delivery rows are removed after 30 days. Raw event bodies are cleared after the retention window, and delivered events are deleted after it.

`[alerts] webhook_url_env` names an env var such as `ALERT_WEBHOOK_URL`. The alert body is a short JSON object like `{"text":"..."}`.

Purchase bearer checks run in order. A token that decodes with `PURCHASE_JWT_SECRET` (HS256; `JWT_SECRET` is an alternate name) supplies the account from `sub` or `account_id`, which must agree when both are present. A bearer that matches `PURCHASE_BEARER_TOKEN`, `ADMIN_TOKEN`, or `ADMIN_BOOTSTRAP_TOKEN` uses `PURCHASE_BEARER_ACCOUNT_ID`. Any other bearer is sent to `GET {TIMAMU_API_BASE_URL}/v1/account/session`, which defaults to `http://localhost:8080`, and the account is read from `accountId` or `account_id`.

### Dashboard

The console is server-rendered in the same binary. Pages after sign-in:

- `/admin` queue health for 24 hours and 7 days
- `/dashboard/events`, plus CSV and NDJSON export
- `/dashboard/events/{id}` raw payload, masked headers, the response returned to the provider, the routing decision, and delivery attempts (admin and owner)
- `/dashboard/retries` and `/dashboard/unrouted`
- `/dashboard/config` sources, routes, write-only secrets, and matcher tests
- `/dashboard/users` (admin and owner), `/dashboard/audit`, and `/dashboard/settings`

Overview and Events subscribe to `/dashboard/overview/live` and `/dashboard/events/live` with the session cookie. The proxy in front of the process must pass `text/event-stream` through without buffering. A `401` means the session is missing or expired.

| Role | Read lists, queues, and non-raw export | Replay, retry, edit routes and sources, raw event detail, raw export | Manage users |
| --- | --- | --- | --- |
| Viewer | Yes | No | No |
| Admin | Yes | Yes | Yes |
| Owner | Yes | Yes | Yes |

Passwords use Argon2id. Login attempts are rate limited in memory on each process. A TOTP code is required when that user has one configured. Mutating forms send a session-bound CSRF value. Sessions use an HttpOnly, SameSite=Lax cookie and rotate on sign-in.

Light mode:

![Fanout console overview in light mode](docs/screenshots/dashboard-light.png)

Dark mode:

![Fanout console overview in dark mode](docs/screenshots/dashboard-dark.png)

### Purchases and entitlements

`POST /v1/purchases/verify` and `GET /v1/entitlements` use the bearer identity above. The verify body accepts `provider`, `receipt` or `purchaseToken`, and optional `productId`. Unknown JSON fields are rejected. `X-Timamu-Account-Id` is not read.

```http
POST /v1/purchases/verify
Content-Type: application/json
Authorization: Bearer <account JWT>

{"provider":"apple","receipt":"<transaction-id-or-signed-transaction>"}
```

For Apple, the verified `appAccountToken` must equal the bearer account. A purchase identity belongs to one account; a second account receives `409`.

Store credentials such as `key_id`, `issuer_id`, `private_key`, and `service_account_key` belong in the encrypted credentials JSON. Non-secret `provider_config` holds `app_identifier`, `environment`, `api_base_url`, and `product_licence.<product-id>`.

## Delivery

The worker claims rows with `FOR UPDATE SKIP LOCKED`. A 2xx response marks the delivery delivered. Other responses and network errors follow this delay while `attempt` is still below the route's `max_attempts`: 30s, 2m, 10m, 30m, 1h, 3h, 6h, 12h, and 24h. Jitter scales each delay to between 80% and 120%. There is no delay after attempt 9. The routes table defaults `max_attempts` to 10. `POST /admin/routes` stores `3`. The dashboard accepts 1 through 10. Attempt records keep at most 2048 bytes of the response body.

Webhook ingest forwards the original ingress bytes. A delivery created by `POST /v1/purchases/verify` has `forward_original_body` off, so the worker sends the normalized event JSON when that body is stored. Each attempt adds `x-fanout-event-id` and `x-fanout-attempt`. Forwarded headers are limited to `content-type`, `x-paystack-signature`, `x-apple-signature`, `x-apple-notification-signature`, `x-apple-connect-signature`, `x-google-signature`, and `x-goog-signature`. Inbound `Authorization` and `x-fanout-signature` are not copied.

Route outbound authentication is stored in Postgres:

- `none` leaves the forwarded provider headers as they are.
- `static_header` sends the encrypted secret as the configured header value.
- `hmac_sha512` sends a lowercase hex HMAC-SHA512 of the exact forwarded bytes.

The configured header replaces a same-named inbound header. Saved secrets are masked and are not returned by the admin API. A blank secret on edit keeps the stored value. Existing routes stay on `none` until an administrator changes them. The worker reads the current route settings when it claims a delivery.

Admin API destinations must be public `https` URLs without embedded credentials. Redirects are disabled. Private or local DNS answers are rejected and the validated public address is pinned for that request. See [docs/security-report.md](docs/security-report.md) for the engineering review of those controls. That document is a review of this repository, with residual findings, and it is not a certification.

Duplicate events for one source return `200` and do not enqueue another delivery. Paystack's duplicate key is a hash of the raw body. Invalid provider authentication returns `401` and is not stored.

### Operations

`/healthz` is liveness. `/readyz` returns `503` when Postgres is unreachable. It returns `200` with `ready_with_missing_settings` when a source that requires a secret has none stored and none in its `secret_env`. `/metrics` is Prometheus text: `fanout_received`, `fanout_verified_failed`, `fanout_duplicates`, `fanout_delivered`, `fanout_retries`, `fanout_dead`, `fanout_unrouted`, `fanout_would_unrouted`, and a delivery latency histogram.

`/docs` redirects to `/docs/`, which links to the OpenAPI document at `/api-docs/openapi.json`.

Send `Authorization: Bearer $ADMIN_TOKEN` to:

- `GET /admin/events?status=&route=&type=&since=&limit=&offset=`
- `GET /admin/events/{id}`
- `POST /admin/events/{id}/replay` with optional `{"route":"timamu"}`
- `POST /admin/replay?status=dead&route=timamu`
- `GET` and `POST /admin/routes`, `PATCH` and `DELETE /admin/routes/{name}`
- `GET` and `POST /admin/sources`, `PATCH` and `DELETE /admin/sources/{slug}`
- `GET /admin/deliveries?reference=...`
- `GET /admin/settings`, `PUT /admin/settings/{key}`, and `DELETE /admin/settings/{key}`

```sh
curl -X POST "$APP_URL/admin/routes" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H 'content-type: application/json' \
  -d '{"name":"store-payments","target_url":"https://your-destination.example/v1/webhooks/paystack","ref_prefix":"app_","metadata_app":"your-app","enabled":true}'
```

The same body accepts `outbound_auth_mode`, `outbound_auth_header`, and write-only `outbound_auth_secret`. `target_url` must be `https`, and at least one matcher field is required. Authorization failures are `404` on some event reads and `401` on route and source writes. When you are checking a deployment, use the status from `/api-docs/openapi.json` for that path.

For a short Google RTDN troubleshooting session, set `FANOUT_DEBUG_AUTH=1`, send one notification, and read the logs. The extra line includes the authorization scheme, selected JWT header and payload claims, JWKS URL and fetch result, key-id lookup, and verification step. It does not include the bearer value or the JWT signature. Unset `FANOUT_DEBUG_AUTH` when the check is finished.

Responses include `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `X-Frame-Options: DENY`, and `Content-Security-Policy` with `frame-ancestors 'none'`. Terminate TLS at the edge. Enable HSTS there after HTTPS is confirmed. Set `TRUST_PROXY=true` only when the direct peer is listed in `TRUSTED_PROXY_CIDRS`.

## Deploy

The [Dockerfile](Dockerfile) builds a release binary and starts `/usr/local/bin/paystack-fanout`. Required runtime variables are `DATABASE_URL`, `MASTER_ENCRYPTION_KEY`, and `ADMIN_BOOTSTRAP_TOKEN`.

On Railway:

1. Add Postgres and deploy this repository. Railway builds the Dockerfile.
2. Set `DATABASE_URL` from the Postgres service, for example `${{Postgres.DATABASE_URL}}`.
3. Set `MASTER_ENCRYPTION_KEY` from `openssl rand -hex 32` and set `ADMIN_BOOTSTRAP_TOKEN`.
4. Set the health check path to `/readyz`.
5. Call `POST /admin/bootstrap` with that token, then sign in and turn on TOTP.
6. Put the public URL in Paystack test mode, then create `google_production`, `apple_production`, and `apple_sandbox` from Sources. Paste the URLs the dashboard renders, such as `${PUBLIC_BASE_URL}/in/google_production`.

Keep live hostnames, provider secrets, service-account JSON, private keys, and database URLs out of forks, issues, and commits.

## Tests

`cargo test` runs signature, routing, fixture, and retry-schedule tests without Postgres. Integration tests run when `DATABASE_URL` and, where they sign Paystack fixtures, `PAYSTACK_SECRET_KEY` are set. CI starts Postgres 16 and runs formatting, lint, tests, a Docker smoke check, a dependency audit, a secret scan, and a repository text check. A local signed request can use `tests/fixtures/charge.success.json` against `POST /in/paystack_main` with `x-paystack-signature`.

## Contributing

There is no separate contributing guide. Enable the repository commit hook before you commit:

```sh
git config core.hooksPath .githooks
```

CI on pull requests is [.github/workflows/ci.yml](.github/workflows/ci.yml).

## License

[MIT](LICENSE). Copyright (c) 2026 Vant Inc.
