# Google Play setup

This service consumes Google Play Real-time developer notifications (RTDN),
looks up the current purchase through the Google Play Developer API, and
feeds the result into the existing fanout event and entitlement path.

## Prerequisites

- A Google Play application with the package name and products configured.
- A Google Cloud Pub/Sub topic for RTDN.
- A service account with permission to access the Google Play Developer API
  and publish RTDN messages to the topic.
- A service-account JSON key stored in a secret, never in the repository.
- A product-to-licence mapping in the source configuration.
- An HTTPS push endpoint such as
  `https://your-public-host.example/in/google_production`.

## Production source

In the dashboard, open Sources → Add source and enter:

- Name: `Google production`
- Path slug: `google_production`
- Provider: `google_play_rtdn`
- Audience: `https://your-public-host.example/in/google_production`
- Push service account: the Pub/Sub service-account email
- Provider settings: the package name, environment, and product/licence map
- Encrypted credentials: the service-account JSON under `service_account_key`

The resulting paste URL is `https://your-public-host.example/in/google_production`.
This writes the source to Postgres and does not require a redeploy. The
first-boot configuration seed remains available for local setup:

```toml
[source.google_production]
provider = "google_play_rtdn"
audience = "https://your-host/in/google_production"
service_account = "pubsub-push@your-project.iam.gserviceaccount.com"

[source.google_production.provider_config]
app_identifier = "com.example.timamu"
environment = "production"
service_account_key_env = "GOOGLE_SERVICE_ACCOUNT_JSON" # legacy first-boot import
"product_licence.timamu_monthly" = "timamu_pro"
```

The `service_account` value is the email used by Pub/Sub to sign the push
JWT. The configured audience must exactly match the push subscription URL.
The adapter verifies the JWT signature, audience, issuer, service-account
email, and verified-email claim before accepting the message.

Keep test-track traffic on a separate source if it must be isolated from
production. A production source rejects Google test purchases.

## Pub/Sub and Play Console configuration

1. Create the RTDN topic in Google Cloud Pub/Sub.
2. Grant the Play service account permission to publish to the topic.
3. Create a wrapped push subscription targeting the configured source URL.
4. Enable authenticated push delivery and set its audience to the exact URL.
5. Set the push service account to the email in `service_account`.
6. Configure the topic in Play Console under Monetize with Google Play →
   Monetization setup → Real-time developer notifications.
7. Configure a route matching the package name in `app_identifier` and set
   `environment = "production"`.

RTDN envelopes are deduplicated using the Pub/Sub `messageId`. The adapter
decodes the notification, looks up the current subscription or product state,
acknowledges pending purchases within the store deadline, and maps changes to
the normalized `purchase`, `renew`, `expire`, `grace`, `refund`, `revoke`, or
`upgrade` events. The periodic reconciliation job repeats the store lookup for
stored purchases so missed notifications are recovered.

## Client verification

The client sends the purchase token to the server:

```http
POST /v1/purchases/verify
Authorization: Bearer <account-JWT>
Content-Type: application/json

{"provider":"google","purchaseToken":"<purchase-token>","productId":"timamu_monthly"}
```

The adapter checks the configured package name, product mapping, and
environment, then acknowledges the purchase when required. The bearer
identity is the only source of the Timamu account ID; body, query, and
`X-Timamu-Account-Id` values are not trusted. The app reads
`GET /v1/entitlements` with the same bearer token.

Set `PURCHASE_JWT_SECRET` for HS256 account JWTs, or set
`PURCHASE_BEARER_TOKEN` and `PURCHASE_BEARER_ACCOUNT_ID` for a static
account-bound bearer identity.

## References

- [RTDN reference](https://developer.android.com/google/play/billing/rtdn-reference)
- [Pub/Sub push delivery](https://cloud.google.com/pubsub/docs/push)
- [Authenticated push subscriptions](https://cloud.google.com/pubsub/docs/authenticate-push-subscriptions)
- [Google Play Developer API](https://developers.google.com/android-publisher)
