use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Instant,
};

use anyhow::Context;
use axum::{
    Json, Router,
    body::Bytes,
    extract::{ConnectInfo, OriginalUri, Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, patch, post, put},
};
use chrono::{DateTime, Utc};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::time::{Duration, sleep};
use utoipa::{OpenApi, ToSchema};
use utoipa_swagger_ui::SwaggerUi;
use uuid::Uuid;

use crate::{
    config::{Config, ExtendedRouteMatcher, RouteConfig as ConfigRoute},
    db::{
        Database, DatabaseRoute, DatabaseRouteRecord, DatabaseRouteResponse,
        DatabaseSourceResponse, InsertResult, PurchaseApplyResult,
    },
    metrics::Metrics,
    provider::{
        AuthenticationFailureReason, NormalizedEvent, Provider, ProviderRuntimeSettings,
        ProviderSettings, PurchaseVerificationRequest, provider_for,
    },
    routing::{MatchSource, database_route_records, decide_with_fields, reference},
    security::bearer_matches,
};

#[derive(Clone)]
pub struct AppState {
    pub config: Config,
    pub db: Database,
    pub metrics: Arc<Metrics>,
    pub http: reqwest::Client,
    pub trust_proxy: bool,
    pub admin_token: Option<String>,
    pub bootstrap_token: Option<String>,
    pub purchase_jwt_secret: Option<String>,
    pub purchase_bearer_token: Option<String>,
    pub purchase_bearer_account_id: Option<String>,
    /// Existing PressLit sessions are opaque tokens.  This origin is used
    /// only after the JWT/static purchase credentials do not match.
    pub timamu_api_base_url: String,
    pub cookie_secure: bool,
    pub login_limits: Arc<std::sync::Mutex<HashMap<String, (u32, Instant)>>>,
    pub runtime_config: Arc<tokio::sync::RwLock<Config>>,
    pub runtime_secrets: Arc<tokio::sync::RwLock<HashMap<String, String>>>,
    pub runtime_credentials: Arc<tokio::sync::RwLock<HashMap<String, HashMap<String, String>>>>,
    pub runtime_alert_url: Arc<tokio::sync::RwLock<Option<String>>>,
    pub runtime_loaded_at: Arc<tokio::sync::RwLock<Instant>>,
    pub route_cache: Arc<tokio::sync::RwLock<RouteCache>>,
    alert_url_override: Option<String>,
}

pub type RouteCache = Option<(Instant, Vec<DatabaseRouteRecord>)>;

impl AppState {
    pub fn new(config: Config, db: Database) -> anyhow::Result<Self> {
        Self::new_with_alert_url(config, db, None)
    }

    pub fn new_with_alert_url(
        config: Config,
        db: Database,
        alert_url_override: Option<String>,
    ) -> anyhow::Result<Self> {
        let runtime_config = config.clone();
        Ok(Self {
            config,
            db,
            metrics: Arc::new(Metrics::default()),
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()?,
            trust_proxy: std::env::var("TRUST_PROXY")
                .is_ok_and(|value| value.eq_ignore_ascii_case("true")),
            admin_token: std::env::var("ADMIN_TOKEN").ok(),
            bootstrap_token: std::env::var("ADMIN_BOOTSTRAP_TOKEN")
                .ok()
                .or_else(|| std::env::var("ADMIN_TOKEN").ok()),
            purchase_jwt_secret: std::env::var("PURCHASE_JWT_SECRET")
                .ok()
                .or_else(|| std::env::var("JWT_SECRET").ok()),
            purchase_bearer_token: std::env::var("PURCHASE_BEARER_TOKEN").ok(),
            purchase_bearer_account_id: std::env::var("PURCHASE_BEARER_ACCOUNT_ID").ok(),
            timamu_api_base_url: std::env::var("TIMAMU_API_BASE_URL")
                .unwrap_or_else(|_| "https://api.timamu.app".to_owned())
                .trim_end_matches('/')
                .to_owned(),
            cookie_secure: std::env::var("COOKIE_SECURE")
                .map(|value| !value.eq_ignore_ascii_case("false"))
                .unwrap_or(true),
            login_limits: Arc::new(std::sync::Mutex::new(HashMap::new())),
            runtime_config: Arc::new(tokio::sync::RwLock::new(runtime_config)),
            runtime_secrets: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            runtime_credentials: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            runtime_alert_url: Arc::new(tokio::sync::RwLock::new(None)),
            runtime_loaded_at: Arc::new(tokio::sync::RwLock::new(Instant::now())),
            route_cache: Arc::new(tokio::sync::RwLock::new(None)),
            alert_url_override,
        })
    }

    pub async fn reload_runtime_config(&self) -> anyhow::Result<()> {
        let (config, secrets, credentials) = self.db.load_runtime_config(&self.config).await;
        *self.runtime_config.write().await = config;
        *self.runtime_secrets.write().await = secrets;
        *self.runtime_credentials.write().await = credentials;
        *self.runtime_alert_url.write().await = self.db.alert_url_setting().await;
        *self.runtime_loaded_at.write().await = Instant::now();
        Ok(())
    }

    pub async fn refresh_runtime_if_stale(&self) {
        if self.runtime_loaded_at.read().await.elapsed() >= Duration::from_secs(30)
            && let Err(error) = self.reload_runtime_config().await
        {
            tracing::warn!(error = %error, "runtime settings refresh failed");
        }
    }

    pub async fn alert(&self, text: String) {
        let Some(url) = self
            .alert_url_override
            .clone()
            .or_else(|| {
                self.runtime_alert_url
                    .try_read()
                    .ok()
                    .and_then(|value| value.clone())
            })
            .or_else(|| self.config.alert_url())
        else {
            return;
        };
        let result = self
            .http
            .post(url)
            .json(&json!({"text": text}))
            .send()
            .await;
        if let Err(error) = result {
            tracing::warn!(error = %error, "alert delivery failed");
        }
    }

    pub async fn clear_route_cache(&self) {
        *self.route_cache.write().await = None;
    }

    pub async fn cached_route_records(&self) -> Vec<DatabaseRouteRecord> {
        if let Some((loaded_at, routes)) = self.route_cache.read().await.as_ref()
            && loaded_at.elapsed() < Duration::from_secs(30)
        {
            return routes.clone();
        }
        match self.db.list_database_route_records().await {
            Ok(routes) => {
                let routes = routes
                    .into_iter()
                    .filter(|route| route.route.enabled)
                    .collect::<Vec<_>>();
                *self.route_cache.write().await = Some((Instant::now(), routes.clone()));
                routes
            }
            Err(error) => {
                tracing::warn!(error = %error, "route refresh failed; using cached routes");
                self.route_cache
                    .read()
                    .await
                    .as_ref()
                    .map(|(_, routes)| routes.clone())
                    .unwrap_or_default()
            }
        }
    }

    pub async fn cached_routes(&self) -> Vec<DatabaseRoute> {
        self.cached_route_records()
            .await
            .into_iter()
            .map(|record| record.route)
            .collect()
    }
}

pub fn build_router(state: Arc<AppState>) -> Router {
    Router::new()
        .merge(crate::dashboard::router())
        .merge(
            SwaggerUi::new("/docs")
                .url("/api-docs/openapi.json", crate::openapi::ApiDoc::openapi()),
        )
        .route("/in/{source}", post(ingest))
        .route("/v1/purchases/verify", post(verify_purchase))
        .route("/v1/entitlements", get(list_entitlements))
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/metrics", get(metrics))
        .route("/admin/events", get(list_events))
        .route("/admin/events/{id}", get(get_event).post(replay_event))
        .route("/admin/replay", post(bulk_replay))
        .route(
            "/admin/routes",
            get(list_admin_routes).post(create_admin_route),
        )
        .route(
            "/admin/routes/{name}",
            patch(update_admin_route).delete(delete_admin_route),
        )
        .route(
            "/admin/sources",
            get(list_admin_sources).post(create_admin_source),
        )
        .route(
            "/admin/sources/{path_slug}",
            patch(update_admin_source).delete(delete_admin_source),
        )
        .route("/admin/deliveries", get(list_admin_deliveries))
        .route("/admin/settings", get(list_admin_settings))
        .route(
            "/admin/settings/{key}",
            put(set_admin_setting).delete(delete_admin_setting),
        )
        .route("/admin/bootstrap", post(bootstrap_admin))
        .layer(axum::extract::DefaultBodyLimit::max(256 * 1024))
        .with_state(state)
}

#[derive(Debug, Clone, Default)]
pub(crate) struct ResolvedProviderRuntime {
    app_identifier: Option<String>,
    environment: Option<String>,
    api_base_url: Option<String>,
    token_url: Option<String>,
    key_id: Option<String>,
    issuer_id: Option<String>,
    private_key: Option<String>,
    service_account_key: Option<String>,
    product_licences: HashMap<String, String>,
}

impl ResolvedProviderRuntime {
    pub(crate) fn borrowed<'a>(
        &'a self,
        source: &'a crate::config::SourceConfig,
    ) -> ProviderRuntimeSettings<'a> {
        ProviderRuntimeSettings {
            app_identifier: self.app_identifier.as_deref(),
            environment: self.environment.as_deref(),
            api_base_url: self.api_base_url.as_deref(),
            token_url: self.token_url.as_deref(),
            key_id: self.key_id.as_deref(),
            issuer_id: self.issuer_id.as_deref(),
            private_key: self.private_key.as_deref(),
            service_account_key: self.service_account_key.as_deref(),
            service_account: source.service_account.as_deref(),
            product_licences: Some(&self.product_licences),
        }
    }
}

pub(crate) fn resolve_provider_runtime(
    source: &crate::config::SourceConfig,
    secret: &str,
    credentials: &HashMap<String, String>,
) -> ResolvedProviderRuntime {
    let value = |key: &str| source.provider_config.get(key).cloned();
    let env_value = |key: &str| {
        (!source.secret_env.is_empty())
            .then(|| source.provider_config.get(key))
            .flatten()
            .and_then(|name| std::env::var(name).ok())
    };
    let credential = |key: &str| credentials.get(key).cloned();
    let mut product_licences = HashMap::new();
    for (key, value) in &source.provider_config {
        if let Some(product) = key.strip_prefix("product_licence.") {
            product_licences.insert(product.to_owned(), value.clone());
        }
    }
    ResolvedProviderRuntime {
        app_identifier: value("app_identifier"),
        environment: value("environment"),
        api_base_url: value("api_base_url"),
        token_url: value("token_url"),
        key_id: value("key_id")
            .or_else(|| credential("key_id"))
            .or_else(|| env_value("key_id_env")),
        issuer_id: value("issuer_id")
            .or_else(|| credential("issuer_id"))
            .or_else(|| env_value("issuer_id_env")),
        private_key: credential("private_key")
            .or_else(|| env_value("private_key_env"))
            .or_else(|| (!secret.is_empty()).then(|| secret.to_owned())),
        service_account_key: credential("service_account_key")
            .or_else(|| env_value("service_account_key_env"))
            .or_else(|| (!secret.is_empty()).then(|| secret.to_owned())),
        product_licences,
    }
}

#[axum::debug_handler]
#[utoipa::path(
    post,
    path = "/in/{source}",
    params(("source" = String, Path, description = "Configured source name")),
    request_body(content_type = "application/json", content = Value),
    responses(
        (status = 200, description = "Webhook accepted for durable processing"),
        (status = 400, description = "Verified body was not valid JSON"),
        (status = 401, description = "Signature verification failed"),
        (status = 403, description = "Source IP is not allowed"),
        (status = 404, description = "Source was not found")
    ),
    tag = "Webhook"
)]
pub(crate) async fn ingest(
    State(state): State<Arc<AppState>>,
    OriginalUri(uri): OriginalUri,
    Path(source): Path<String>,
    headers: HeaderMap,
    remote: ConnectInfo<SocketAddr>,
    body: Bytes,
) -> Response {
    state.refresh_runtime_if_stale().await;
    let active_config = state.runtime_config.read().await.clone();
    let active_secrets = state.runtime_secrets.read().await.clone();
    let active_credentials = state.runtime_credentials.read().await.clone();
    let Some(source_config) = active_config.source.get(&source) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Some(provider) = provider_for(&source_config.provider) else {
        tracing::error!(source = %source, provider = %source_config.provider, "unsupported source provider");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    if !provider.implemented() {
        tracing::warn!(source = %source, provider = provider.name(), "webhook provider is not implemented");
        return StatusCode::UNAUTHORIZED.into_response();
    }
    if !allowed_ip(
        source_config.allowed_ips.as_slice(),
        state.trust_proxy,
        &headers,
        Some(remote.0.ip()),
    ) {
        tracing::warn!(
            source = %source,
            provider = provider.name(),
            reason = AuthenticationFailureReason::AllowlistDenied.as_str(),
            "webhook authentication failed"
        );
        return StatusCode::FORBIDDEN.into_response();
    }
    let signature = provider.authenticated_header(&headers);
    let secret = if provider.secret_required() {
        match active_secrets
            .get(&source)
            .cloned()
            .or_else(|| active_config.secret_for(&source).ok())
        {
            Some(secret) => secret,
            None => {
                tracing::error!(source = %source, "source secret unavailable");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        }
    } else {
        String::new()
    };
    let settings = ProviderSettings {
        audience: source_config.audience.as_deref(),
        service_account: source_config.service_account.as_deref(),
    };
    let authentication = provider
        .authenticate_with_settings_diagnostic(secret.as_bytes(), &headers, &body, settings)
        .await;
    if !authentication.authenticated {
        state
            .metrics
            .verified_failed
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if state.metrics.should_log_signature_failure() {
            tracing::warn!(
                source = %source,
                provider = provider.name(),
                reason = authentication
                    .reason
                    .unwrap_or(AuthenticationFailureReason::Other)
                    .as_str(),
                expected_aud = ?authentication.expected_aud,
                expected_sa = ?authentication.expected_sa,
                jwt_aud = ?authentication.jwt_aud,
                jwt_email = ?authentication.jwt_email,
                jwt_iss = ?authentication.jwt_iss,
                "webhook authentication failed"
            );
        }
        if google_auth_debug_enabled(provider) {
            tracing::warn!(
                source = %source,
                provider = provider.name(),
                reason = authentication
                    .reason
                    .unwrap_or(AuthenticationFailureReason::Other)
                    .as_str(),
                expected_aud = ?authentication.expected_aud,
                expected_sa = ?authentication.expected_sa,
                authorization_present = authentication.debug.authorization_present,
                authorization_scheme = %authentication.debug.authorization_scheme,
                jwt_alg = ?authentication.debug.jwt_alg,
                jwt_kid_present = authentication.debug.jwt_kid_present,
                jwt_kid = ?authentication.debug.jwt_kid,
                jwt_header = ?authentication.debug.jwt_header,
                jwt_payload = ?authentication.debug.jwt_payload,
                jwks_url = ?authentication.debug.jwks_url,
                jwks_fetch_ok = ?authentication.debug.jwks_fetch_ok,
                jwks_error = ?authentication.debug.jwks_error,
                kid_in_jwks = ?authentication.debug.kid_in_jwks,
                verify_step = ?authentication.debug.verify_step,
                "google RTDN authentication debug"
            );
        }
        return StatusCode::UNAUTHORIZED.into_response();
    }
    state
        .metrics
        .received
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let payload: Value = match serde_json::from_slice(&body) {
        Ok(payload) => payload,
        Err(error) => {
            tracing::warn!(source = %source, error = %error, "verified webhook was not valid JSON");
            return StatusCode::BAD_REQUEST.into_response();
        }
    };
    let provider_runtime = resolve_provider_runtime(
        source_config,
        &secret,
        &active_credentials.get(&source).cloned().unwrap_or_default(),
    );
    let initial_normalized = provider.normalize_event_with_settings(
        &payload,
        &body,
        provider_runtime.borrowed(source_config),
    );
    let mut normalized = match initial_normalized {
        Some(event) => provider
            .enrich_normalized_event(
                event.clone(),
                provider_runtime.borrowed(source_config),
                &state.http,
            )
            .await
            .ok()
            .or(Some(event)),
        None => None,
    };
    if let Some(event) = normalized.as_mut()
        && event.account_id.is_none()
        && let Some(purchase_key) = event.purchase_key()
    {
        event.account_id = sqlx::query_scalar::<_, String>(
            "SELECT account_id FROM store_purchases
             WHERE provider = $1 AND purchase_key = $2 AND account_id IS NOT NULL",
        )
        .bind(&event.provider)
        .bind(purchase_key)
        .fetch_optional(&state.db.pool)
        .await
        .ok()
        .flatten();
    }
    let event_type = normalized
        .as_ref()
        .map(|event| event.event_type().to_owned())
        .unwrap_or_else(|| provider.event_type(&payload));
    let event_id = normalized
        .as_ref()
        .map(|event| event.event_id.clone())
        .unwrap_or_else(|| provider.event_id(&payload, &body));
    let routing_fields = normalized
        .as_ref()
        .map(NormalizedEvent::routing_fields)
        .unwrap_or_else(|| provider.routing_fields(&payload));
    let database_routes = state.cached_route_records().await;
    let database_match = database_route_records(&database_routes, &routing_fields);
    let database_route_id = database_match.map(|route| route.route.id);
    let decision = if let Some(route) = database_match {
        crate::routing::RouteDecision {
            source: crate::routing::match_source(&route.matcher, &routing_fields)
                .unwrap_or(MatchSource::Fallback),
            route: Some(ConfigRoute {
                name: route.route.name.clone(),
                destination_url: route.route.target_url.clone(),
                matcher: crate::config::RouteMatcher::from_extended(route.matcher.clone()),
            }),
        }
    } else {
        decide_with_fields(&active_config, &payload, &routing_fields)
    };
    let matched_route = decision.route.as_ref().map(|route| route.name.as_str());
    if matches!(decision.source, MatchSource::Fallback) && matched_route.is_some() {
        state
            .metrics
            .would_unrouted
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
    let status = if matched_route.is_some() {
        "pending"
    } else {
        "unrouted"
    };
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("application/json");
    let stored_headers = headers_to_json(&headers, provider);
    let request_url = request_url(&headers, &uri);
    let normalized_body = normalized
        .as_ref()
        .and_then(|event| serde_json::to_vec(event).ok());
    let dedupe = normalized
        .as_ref()
        .map(|event| event.event_id.clone())
        .unwrap_or_else(|| provider.dedupe_key(&payload, &body));
    let inserted = match state
        .db
        .insert_event_with_provider_event_id_and_normalized_with_request(
            &source,
            &event_type,
            &body,
            normalized_body.as_deref(),
            content_type,
            signature.unwrap_or_default(),
            &stored_headers,
            &dedupe,
            &event_id,
            matched_route,
            Some(match decision.source {
                MatchSource::AppIdentifier => "app_identifier",
                MatchSource::Environment => "environment",
                MatchSource::Provider => "provider",
                MatchSource::MetadataApp => "metadata.app",
                MatchSource::PlanCode => "plan_code",
                MatchSource::Reference => "reference",
                MatchSource::Fallback => "fallback",
            }),
            status,
            decision
                .route
                .as_ref()
                .map(|route| route.destination_url.as_str()),
            Some("POST"),
            Some(request_url.as_str()),
        )
        .await
    {
        Ok(result) => result,
        Err(error) => {
            tracing::error!(source = %source, event_type = %event_type, error = %error, "storing webhook failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    match inserted {
        InsertResult::Duplicate => {
            state
                .metrics
                .duplicates
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        InsertResult::Inserted { event_id } => {
            if let Err(error) = state
                .db
                .annotate_delivery(
                    event_id,
                    &event_type,
                    reference(payload.get("data").unwrap_or(&payload)).as_deref(),
                    database_route_id,
                    matched_route.is_some(),
                )
                .await
            {
                tracing::error!(error = %error, event_id = %event_id, "recording delivery metadata failed");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
            if matched_route.is_none() {
                state
                    .metrics
                    .unrouted
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let state_clone = state.clone();
                let provider_label = if provider.name() == "paystack" {
                    "Paystack"
                } else {
                    provider.name()
                };
                tokio::spawn(async move {
                    state_clone
                        .alert(format!(
                            "{} event {event_id} was stored as unrouted",
                            provider_label
                        ))
                        .await;
                });
            }
        }
    }
    StatusCode::OK.into_response()
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct VerifyPurchaseBody {
    provider: String,
    #[serde(default)]
    receipt: Option<String>,
    #[serde(alias = "purchaseToken", default)]
    purchase_token: Option<String>,
    #[serde(alias = "productId", default)]
    product_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PurchaseIdentityClaims {
    #[serde(default)]
    sub: Option<String>,
    #[serde(default, alias = "accountId")]
    account_id: Option<String>,
}

fn identity_account_id(claims: PurchaseIdentityClaims) -> Option<String> {
    if let (Some(subject), Some(account_id)) = (&claims.sub, &claims.account_id)
        && subject != account_id
    {
        return None;
    }
    claims
        .account_id
        .or(claims.sub)
        .filter(|value| !value.trim().is_empty())
}

async fn verified_purchase_account_id(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<String, StatusCode> {
    let Some(authorization) = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
    else {
        return Err(StatusCode::UNAUTHORIZED);
    };
    let Some(token) = authorization
        .strip_prefix("Bearer ")
        .filter(|value| !value.is_empty())
    else {
        return Err(StatusCode::UNAUTHORIZED);
    };

    if let Some(secret) = state.purchase_jwt_secret.as_deref() {
        let validation = Validation::new(Algorithm::HS256);
        if let Ok(token_data) = decode::<PurchaseIdentityClaims>(
            token,
            &DecodingKey::from_secret(secret.as_bytes()),
            &validation,
        ) {
            return identity_account_id(token_data.claims).ok_or(StatusCode::FORBIDDEN);
        }
    }

    let static_token = state
        .purchase_bearer_token
        .as_deref()
        .or(state.admin_token.as_deref())
        .or(state.bootstrap_token.as_deref());
    if static_token.is_some_and(|expected| bearer_matches(expected, Some(authorization))) {
        return state
            .purchase_bearer_account_id
            .clone()
            .filter(|value| !value.trim().is_empty())
            .ok_or(StatusCode::FORBIDDEN);
    }

    // PressLit account sessions are intentionally opaque and are not a
    // second purchase credential. Introspect the already-authenticated
    // session at Timamu, then use only the returned account id for Fanout's
    // store-account binding.
    let response = state
        .http
        .get(format!("{}/v1/account/session", state.timamu_api_base_url))
        .bearer_auth(token)
        .send()
        .await
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    if !response.status().is_success() {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let body: serde_json::Value = response
        .json()
        .await
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    body.get("accountId")
        .or_else(|| body.get("account_id"))
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or(StatusCode::FORBIDDEN)
}

#[utoipa::path(
    post,
    path = "/v1/purchases/verify",
    request_body = VerifyPurchaseBody,
    responses(
        (status = 200, description = "Verified purchase accepted"),
        (status = 401, description = "Bearer authentication failed"),
        (status = 403, description = "Authenticated identity does not own the store account"),
        (status = 409, description = "Purchase belongs to another account"),
        (status = 422, description = "Store verification failed")
    ),
    security(("admin_bearer" = [])),
    tag = "Purchases"
)]
pub(crate) async fn verify_purchase(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<VerifyPurchaseBody>,
) -> Response {
    let account_id = match verified_purchase_account_id(&state, &headers).await {
        Ok(account_id) => account_id,
        Err(status) => return status.into_response(),
    };
    state.refresh_runtime_if_stale().await;
    let provider_name = match body.provider.as_str() {
        "apple" | "apple_server_notifications" => "apple_server_notifications",
        "google" | "google_play" | "google_play_rtdn" => "google_play_rtdn",
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "provider must be apple or google"})),
            )
                .into_response();
        }
    };
    let active_config = state.runtime_config.read().await.clone();
    let Some((source_name, source_config)) = active_config
        .source
        .iter()
        .find(|(_, source)| source.provider == provider_name)
    else {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({"error": "provider is not configured"})),
        )
            .into_response();
    };
    let provider = provider_for(provider_name).expect("validated provider name");
    let secret = state
        .runtime_secrets
        .read()
        .await
        .get(source_name)
        .cloned()
        .or_else(|| active_config.secret_for(source_name).ok())
        .unwrap_or_default();
    let credentials = state
        .runtime_credentials
        .read()
        .await
        .get(source_name)
        .cloned()
        .unwrap_or_default();
    let runtime = resolve_provider_runtime(source_config, &secret, &credentials);
    let receipt = body
        .receipt
        .or(body.purchase_token)
        .filter(|value| !value.trim().is_empty());
    let Some(receipt) = receipt else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "receipt or purchaseToken is required"})),
        )
            .into_response();
    };
    let request = PurchaseVerificationRequest {
        receipt,
        product_id: body.product_id,
    };
    let mut event = match provider
        .verify_purchase(&request, runtime.borrowed(source_config), &state.http)
        .await
    {
        Ok(event) => event,
        Err(error) => {
            tracing::warn!(provider = provider.name(), error = %error, "purchase verification failed");
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(json!({"error": "purchase could not be verified"})),
            )
                .into_response();
        }
    };
    let verified_provider_account_id = event.account_id.clone();
    if provider_name == "apple_server_notifications"
        && verified_provider_account_id.as_deref() != Some(account_id.as_str())
    {
        return (
            StatusCode::FORBIDDEN,
            Json(
                json!({"error": "Apple appAccountToken does not match the authenticated account"}),
            ),
        )
            .into_response();
    }
    if provider_name == "google_play_rtdn"
        && verified_provider_account_id
            .as_deref()
            .is_some_and(|provider_account_id| provider_account_id != account_id)
    {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "store account does not match the authenticated account"})),
        )
            .into_response();
    }
    event.account_id = Some(account_id.clone());
    if event.licence.is_none() {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({"error": "product is not mapped to a licence"})),
        )
            .into_response();
    }
    match state.db.apply_normalized_event(&event).await {
        Ok(PurchaseApplyResult::CrossAccountReplay) => {
            return (
                StatusCode::CONFLICT,
                Json(json!({"error": "purchase belongs to another account"})),
            )
                .into_response();
        }
        Ok(PurchaseApplyResult::Applied) => {}
        Ok(PurchaseApplyResult::Unowned | PurchaseApplyResult::UnmappedProduct) => {
            return StatusCode::UNPROCESSABLE_ENTITY.into_response();
        }
        Err(error) => {
            tracing::error!(error = %error, "storing entitlement failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    }
    let raw_body = serde_json::to_vec(&json!({
        "provider": body.provider,
        "receipt": request.receipt,
        "product_id": request.product_id,
        "account_id": account_id,
    }))
    .unwrap_or_default();
    let normalized_body = serde_json::to_vec(&event).unwrap_or_default();
    if let Err(error) = store_normalized_event(
        &state,
        source_name,
        provider,
        &event,
        &raw_body,
        &normalized_body,
    )
    .await
    {
        tracing::error!(error = %error, "storing verified purchase event failed");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    (
        StatusCode::OK,
        Json(json!({"status": "verified", "event_id": event.event_id})),
    )
        .into_response()
}

#[utoipa::path(
    get,
    path = "/v1/entitlements",
    responses((status = 200, description = "Current entitlements", body = Value)),
    security(("admin_bearer" = [])),
    tag = "Purchases"
)]
pub(crate) async fn list_entitlements(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    let account_id = match verified_purchase_account_id(&state, &headers).await {
        Ok(account_id) => account_id,
        Err(status) => return status.into_response(),
    };
    match state.db.list_entitlements(&account_id).await {
        Ok(entitlements) => {
            Json(json!({"account_id": account_id, "entitlements": entitlements})).into_response()
        }
        Err(error) => {
            tracing::error!(error = %error, "listing entitlements failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn store_normalized_event(
    state: &AppState,
    source: &str,
    provider: &dyn Provider,
    event: &NormalizedEvent,
    raw_body: &[u8],
    normalized_body: &[u8],
) -> anyhow::Result<()> {
    let fields = event.routing_fields();
    let database_routes = state.cached_route_records().await;
    let database_match = database_route_records(&database_routes, &fields);
    let database_route_id = database_match.map(|route| route.route.id);
    let active_config = state.runtime_config.read().await.clone();
    let decision = if let Some(route) = database_match {
        crate::routing::RouteDecision {
            source: crate::routing::match_source(&route.matcher, &fields)
                .unwrap_or(MatchSource::Fallback),
            route: Some(ConfigRoute {
                name: route.route.name.clone(),
                destination_url: route.route.target_url.clone(),
                matcher: crate::config::RouteMatcher::from_extended(route.matcher.clone()),
            }),
        }
    } else {
        decide_with_fields(&active_config, &Value::Null, &fields)
    };
    let matched_route = decision.route.as_ref().map(|route| route.name.as_str());
    let status = if matched_route.is_some() {
        "pending"
    } else {
        "unrouted"
    };
    let source_secret = state.runtime_secrets.read().await.get(source).cloned();
    let secret = std::env::var("PAYSTACK_WEBHOOK_SECRET")
        .ok()
        .or(source_secret)
        .or_else(|| std::env::var("PAYSTACK_SECRET_KEY").ok())
        .context("Fanout forward secret is not configured")?;
    let signature = crate::security::sign_forward(secret.as_bytes(), normalized_body);
    let headers = json!({
        "content-type": "application/json",
        "x-fanout-signature": signature,
    });
    let inserted = state
        .db
        .insert_event_with_provider_event_id_and_normalized(
            source,
            event.event_type(),
            raw_body,
            Some(normalized_body),
            "application/json",
            "",
            &headers,
            &event.event_id,
            &event.event_id,
            matched_route,
            Some("provider_verification"),
            status,
            decision
                .route
                .as_ref()
                .map(|route| route.destination_url.as_str()),
        )
        .await?;
    if let InsertResult::Inserted { event_id } = inserted {
        state
            .db
            .annotate_delivery(
                event_id,
                event.event_type(),
                Some(&event.product_id),
                database_route_id,
                matched_route.is_some(),
            )
            .await?;
    }
    let _ = provider;
    Ok(())
}

fn allowed_ip(
    allowed: &[IpAddr],
    trust_proxy: bool,
    headers: &HeaderMap,
    remote: Option<IpAddr>,
) -> bool {
    if allowed.is_empty() {
        return true;
    }
    let ip = if trust_proxy {
        headers
            .get("x-forwarded-for")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(',').next())
            .and_then(|value| value.trim().parse().ok())
    } else {
        None
    }
    .or(remote);
    ip.is_some_and(|ip| allowed.contains(&ip))
}

fn google_auth_debug_enabled(provider: &dyn Provider) -> bool {
    provider.name() == "google_play_rtdn"
        && std::env::var("FANOUT_DEBUG_AUTH").is_ok_and(|value| value == "1")
}

fn headers_to_json(headers: &HeaderMap, provider: &dyn Provider) -> Value {
    let mut object = serde_json::Map::new();
    let mut names = vec![header::CONTENT_TYPE.as_str()];
    names.extend(provider.auth_header_names());
    for name in names {
        let values = headers
            .get_all(name)
            .iter()
            .filter_map(|value| value.to_str().ok().map(str::to_owned))
            .collect::<Vec<_>>();
        if values.len() == 1 {
            object.insert(name.to_owned(), Value::String(values[0].clone()));
        } else if !values.is_empty() {
            object.insert(
                name.to_owned(),
                Value::Array(values.into_iter().map(Value::String).collect()),
            );
        }
    }
    Value::Object(object)
}

fn request_url(headers: &HeaderMap, uri: &http::Uri) -> String {
    let host = headers
        .get("x-forwarded-host")
        .or_else(|| headers.get(header::HOST))
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty());
    let scheme = headers
        .get("x-forwarded-proto")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("http");
    match host {
        Some(host) => format!("{scheme}://{host}{uri}"),
        None => uri.to_string(),
    }
}

#[utoipa::path(
    get,
    path = "/healthz",
    responses((status = 200, description = "Process is alive")),
    tag = "Operations"
)]
pub(crate) async fn healthz() -> impl IntoResponse {
    StatusCode::OK
}

#[utoipa::path(
    get,
    path = "/readyz",
    responses(
        (status = 200, description = "Database is reachable"),
        (status = 503, description = "Database is unavailable")
    ),
    tag = "Operations"
)]
pub(crate) async fn readyz(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    if let Err(error) = sqlx::query_scalar::<_, i32>("SELECT 1")
        .fetch_one(&state.db.pool)
        .await
    {
        tracing::warn!(error = %error, "readiness check failed");
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"status": "not_ready", "reason": "database unavailable"})),
        );
    }
    let config = state.runtime_config.read().await;
    let secrets = state.runtime_secrets.read().await;
    let missing = config
        .source
        .iter()
        .filter(|(name, source)| {
            provider_for(&source.provider).is_none_or(Provider::secret_required)
                && !secrets.contains_key(*name)
                && (source.secret_env.is_empty() || std::env::var(&source.secret_env).is_err())
        })
        .map(|(name, _)| name.clone())
        .collect::<Vec<_>>();
    if missing.is_empty() {
        (StatusCode::OK, Json(json!({"status": "ready"})))
    } else {
        (
            StatusCode::OK,
            Json(json!({"status": "ready_with_missing_settings", "missing": missing})),
        )
    }
}

#[utoipa::path(
    get,
    path = "/metrics",
    responses((status = 200, description = "Prometheus metrics", content_type = "text/plain")),
    tag = "Operations"
)]
pub(crate) async fn metrics(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/plain; version=0.0.4".to_owned())],
        state.metrics.render(),
    )
}

#[derive(Debug, Deserialize)]
pub(crate) struct EventQuery {
    status: Option<String>,
    route: Option<String>,
    r#type: Option<String>,
    since: Option<String>,
    limit: Option<i64>,
    offset: Option<i64>,
}

#[utoipa::path(
    get,
    path = "/admin/events",
    params(
        ("status" = Option<String>, Query, description = "Event status filter"),
        ("route" = Option<String>, Query, description = "Matched route filter"),
        ("type" = Option<String>, Query, description = "Paystack event type filter"),
        ("since" = Option<String>, Query, description = "RFC3339 lower bound"),
        ("limit" = Option<i64>, Query, description = "Page size from 1 to 100"),
        ("offset" = Option<i64>, Query, description = "Number of rows to skip")
    ),
    responses((status = 200, description = "Matching events", body = Value)),
    security(("admin_bearer" = [])),
    tag = "Admin API"
)]
pub(crate) async fn list_events(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<EventQuery>,
) -> Response {
    if !api_authorized(&state, &headers, false).await {
        return StatusCode::NOT_FOUND.into_response();
    }
    let since = match query
        .since
        .as_deref()
        .map(|value| DateTime::parse_from_rfc3339(value).map(|value| value.with_timezone(&Utc)))
    {
        Some(Ok(value)) => Some(value),
        Some(Err(_)) => return StatusCode::BAD_REQUEST.into_response(),
        None => None,
    };
    match state
        .db
        .list_events(
            query.status.as_deref(),
            query.route.as_deref(),
            query.r#type.as_deref(),
            since,
            query.limit.unwrap_or(50).clamp(1, 100),
            query.offset.unwrap_or(0).max(0),
        )
        .await
    {
        Ok(events) => Json(json!({"events": events})).into_response(),
        Err(error) => {
            tracing::error!(error = %error, "listing events failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[utoipa::path(
    get,
    path = "/admin/events/{id}",
    params(("id" = Uuid, Path, description = "Event identifier")),
    responses(
        (status = 200, description = "Event detail", body = crate::db::EventDetail),
        (status = 404, description = "Event was not found")
    ),
    security(("admin_bearer" = [])),
    tag = "Admin API"
)]
pub(crate) async fn get_event(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Response {
    if !api_authorized(&state, &headers, false).await {
        return StatusCode::NOT_FOUND.into_response();
    }
    match state.db.get_event(id).await {
        Ok(Some(event)) => Json(event).into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => {
            tracing::error!(error = %error, "getting event failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub(crate) struct ReplayBody {
    route: Option<String>,
}

#[utoipa::path(
    post,
    path = "/admin/events/{id}/replay",
    params(("id" = Uuid, Path, description = "Event identifier")),
    request_body = ReplayBody,
    responses(
        (status = 202, description = "Event requeued"),
        (status = 404, description = "Event was not found")
    ),
    security(("admin_bearer" = [])),
    tag = "Admin API"
)]
pub(crate) async fn replay_event(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(body): Json<ReplayBody>,
) -> Response {
    if !api_authorized(&state, &headers, true).await {
        return StatusCode::NOT_FOUND.into_response();
    }
    let active_config = state.runtime_config.read().await.clone();
    match state
        .db
        .replay(id, body.route.as_deref(), &active_config)
        .await
    {
        Ok(true) => StatusCode::ACCEPTED.into_response(),
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => {
            tracing::error!(error = %error, "replaying event failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct BulkReplayQuery {
    status: Option<String>,
    route: Option<String>,
}

#[utoipa::path(
    post,
    path = "/admin/replay",
    params(
        ("status" = String, Query, description = "Status to replay"),
        ("route" = String, Query, description = "Destination route name")
    ),
    responses((status = 200, description = "Number of events requeued", body = Value)),
    security(("admin_bearer" = [])),
    tag = "Admin API"
)]
pub(crate) async fn bulk_replay(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<BulkReplayQuery>,
) -> Response {
    if !api_authorized(&state, &headers, true).await {
        return StatusCode::NOT_FOUND.into_response();
    }
    let (Some(status), Some(route)) = (query.status.as_deref(), query.route.as_deref()) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let active_config = state.runtime_config.read().await.clone();
    match state.db.bulk_replay(status, route, &active_config).await {
        Ok(count) => Json(json!({"requeued": count})).into_response(),
        Err(error) => {
            tracing::error!(error = %error, "bulk replay failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[derive(Debug, Deserialize, ToSchema)]
pub(crate) struct SourceWriteBody {
    pub name: Option<String>,
    pub path_slug: Option<String>,
    pub provider: Option<String>,
    pub secret: Option<String>,
    pub allowed_ips: Option<Vec<String>>,
    pub audience: Option<String>,
    pub service_account: Option<String>,
    pub provider_config: Option<HashMap<String, String>>,
    pub credentials: Option<HashMap<String, String>>,
    pub enabled: Option<bool>,
}

pub(crate) fn valid_source_slug(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 80
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn normalized_source_value(value: Option<String>) -> Option<String> {
    value
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn source_allowed_ips(values: Option<Vec<String>>) -> Result<Vec<String>, String> {
    values
        .unwrap_or_default()
        .into_iter()
        .map(|value| {
            let value = value.trim().to_owned();
            value
                .parse::<IpAddr>()
                .map(|_| value.clone())
                .map_err(|_| format!("invalid source IP: {value}"))
        })
        .collect()
}

fn valid_source_provider_settings(
    provider: &str,
    audience: Option<&str>,
    service_account: Option<&str>,
) -> bool {
    provider != "google_play_rtdn"
        || (audience.is_some_and(|value| !value.is_empty())
            && service_account.is_some_and(|value| !value.is_empty()))
}

#[utoipa::path(
    get,
    path = "/admin/sources",
    responses((status = 200, description = "Configured sources", body = [crate::db::DatabaseSourceResponse])),
    security(("admin_bearer" = [])),
    tag = "Admin API"
)]
pub(crate) async fn list_admin_sources(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    if !api_authorized(&state, &headers, false).await {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    match state.db.list_sources().await {
        Ok(sources) => Json(
            sources
                .into_iter()
                .map(DatabaseSourceResponse::from)
                .collect::<Vec<_>>(),
        )
        .into_response(),
        Err(error) => {
            tracing::error!(error = %error, "listing sources failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn save_api_source(
    state: &AppState,
    current_path_slug: Option<&str>,
    name: &str,
    path_slug: &str,
    provider: &str,
    secret: Option<&str>,
    allowed_ips: &[String],
    audience: Option<&str>,
    service_account: Option<&str>,
    provider_config: Option<&HashMap<String, String>>,
    credentials: Option<&HashMap<String, String>>,
    enabled: bool,
) -> Result<(), (StatusCode, String)> {
    if name.is_empty() || !valid_source_slug(path_slug) {
        return Err((
            StatusCode::BAD_REQUEST,
            "name and a path_slug containing only letters, numbers, - or _ are required".to_owned(),
        ));
    }
    if !crate::provider::supported_providers().contains(&provider) {
        return Err((
            StatusCode::BAD_REQUEST,
            "provider is not supported".to_owned(),
        ));
    }
    if !valid_source_provider_settings(provider, audience, service_account) {
        return Err((
            StatusCode::BAD_REQUEST,
            "Google Play sources require audience and service_account".to_owned(),
        ));
    }
    state
        .db
        .save_source(
            current_path_slug,
            name,
            path_slug,
            provider,
            secret,
            allowed_ips,
            audience,
            service_account,
            provider_config,
            credentials,
            enabled,
        )
        .await
        .map_err(|error| (StatusCode::BAD_REQUEST, error.to_string()))
}

#[utoipa::path(
    post,
    path = "/admin/sources",
    request_body = SourceWriteBody,
    responses((status = 201, description = "Source created", body = crate::db::DatabaseSourceResponse)),
    security(("admin_bearer" = [])),
    tag = "Admin API"
)]
pub(crate) async fn create_admin_source(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<SourceWriteBody>,
) -> Response {
    if !api_authorized(&state, &headers, true).await {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let Some(name) = body
        .name
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return (StatusCode::BAD_REQUEST, "name is required").into_response();
    };
    let path_slug = body
        .path_slug
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(name);
    let Some(provider) = body
        .provider
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return (StatusCode::BAD_REQUEST, "provider is required").into_response();
    };
    let allowed_ips = match source_allowed_ips(body.allowed_ips) {
        Ok(values) => values,
        Err(error) => return (StatusCode::BAD_REQUEST, error).into_response(),
    };
    let audience = normalized_source_value(body.audience);
    let service_account = normalized_source_value(body.service_account);
    let secret = normalized_source_value(body.secret);
    let error = save_api_source(
        &state,
        None,
        name,
        path_slug,
        provider,
        secret.as_deref(),
        &allowed_ips,
        audience.as_deref(),
        service_account.as_deref(),
        body.provider_config.as_ref(),
        body.credentials.as_ref(),
        body.enabled.unwrap_or(true),
    )
    .await
    .err();
    if let Some((status, message)) = error {
        return (status, message).into_response();
    }
    if let Err(error) = state.reload_runtime_config().await {
        tracing::error!(error = %error, "reloading source configuration failed");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    match state.db.list_sources().await.ok().and_then(|sources| {
        sources
            .into_iter()
            .find(|source| source.path_slug == path_slug)
    }) {
        Some(source) => (
            StatusCode::CREATED,
            Json(DatabaseSourceResponse::from(source)),
        )
            .into_response(),
        None => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

#[utoipa::path(
    patch,
    path = "/admin/sources/{path_slug}",
    params(("path_slug" = String, Path, description = "Source path slug")),
    request_body = SourceWriteBody,
    responses((status = 200, description = "Source updated", body = crate::db::DatabaseSourceResponse)),
    security(("admin_bearer" = [])),
    tag = "Admin API"
)]
pub(crate) async fn update_admin_source(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(path_slug): Path<String>,
    Json(body): Json<SourceWriteBody>,
) -> Response {
    if !api_authorized(&state, &headers, true).await {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let source = match state.db.list_sources().await {
        Ok(sources) => sources
            .into_iter()
            .find(|source| source.path_slug == path_slug),
        Err(error) => {
            return {
                tracing::error!(error = %error, "loading source failed");
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            };
        }
    };
    let Some(source) = source else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let name = body
        .name
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(&source.name);
    let new_path_slug = body
        .path_slug
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(&source.path_slug);
    let provider = body
        .provider
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(&source.provider);
    let allowed_ips =
        match source_allowed_ips(body.allowed_ips.or(Some(source.allowed_ips.clone()))) {
            Ok(values) => values,
            Err(error) => return (StatusCode::BAD_REQUEST, error).into_response(),
        };
    let audience = normalized_source_value(body.audience).or(source.audience.clone());
    let service_account =
        normalized_source_value(body.service_account).or(source.service_account.clone());
    let secret = normalized_source_value(body.secret);
    let error = save_api_source(
        &state,
        Some(&source.path_slug),
        name,
        new_path_slug,
        provider,
        secret.as_deref(),
        &allowed_ips,
        audience.as_deref(),
        service_account.as_deref(),
        body.provider_config.as_ref(),
        body.credentials.as_ref(),
        body.enabled.unwrap_or(source.enabled),
    )
    .await;
    if let Err((status, message)) = error {
        return (status, message).into_response();
    }
    if let Err(error) = state.reload_runtime_config().await {
        tracing::error!(error = %error, "reloading source configuration failed");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    match state.db.list_sources().await.ok().and_then(|sources| {
        sources
            .into_iter()
            .find(|source| source.path_slug == new_path_slug)
    }) {
        Some(source) => Json(DatabaseSourceResponse::from(source)).into_response(),
        None => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

#[utoipa::path(
    delete,
    path = "/admin/sources/{path_slug}",
    params(("path_slug" = String, Path, description = "Source path slug")),
    responses((status = 204, description = "Source deleted")),
    security(("admin_bearer" = [])),
    tag = "Admin API"
)]
pub(crate) async fn delete_admin_source(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(path_slug): Path<String>,
) -> Response {
    if !api_authorized(&state, &headers, true).await {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    match state.db.delete_source(&path_slug).await {
        Ok(true) => {
            let _ = state.reload_runtime_config().await;
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => {
            tracing::error!(error = %error, "deleting source failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub(crate) struct RouteWriteBody {
    pub name: Option<String>,
    pub target_url: Option<String>,
    pub ref_prefix: Option<String>,
    pub metadata_app: Option<String>,
    pub plan_code_prefix: Option<String>,
    pub app_identifier: Option<String>,
    pub environment: Option<String>,
    pub enabled: Option<bool>,
}

fn valid_environment(environment: Option<&str>) -> bool {
    environment.is_none_or(|value| matches!(value, "production" | "sandbox"))
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub(crate) struct SettingWriteBody {
    pub value: String,
    #[serde(default)]
    pub is_secret: bool,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub(crate) struct BootstrapBody {
    pub email: String,
    pub password: String,
}

fn valid_https_target(value: &str) -> bool {
    value.starts_with("https://") && value.len() > "https://".len()
}

async fn api_authorized(state: &AppState, headers: &HeaderMap, write: bool) -> bool {
    if state.admin_token.as_deref().is_some_and(|token| {
        bearer_matches(
            token,
            headers
                .get(header::AUTHORIZATION)
                .and_then(|value| value.to_str().ok()),
        )
    }) {
        return true;
    }
    if state.bootstrap_token.as_deref().is_some_and(|token| {
        bearer_matches(
            token,
            headers
                .get(header::AUTHORIZATION)
                .and_then(|value| value.to_str().ok()),
        )
    }) && state.db.user_count().await.ok() == Some(0)
    {
        return true;
    }
    let Some(token) = crate::auth::session_token(headers) else {
        return false;
    };
    state
        .db
        .session_user(&token)
        .await
        .ok()
        .flatten()
        .is_some_and(|user| !write || user.can_write)
}

#[utoipa::path(
    get,
    path = "/admin/routes",
    responses((status = 200, description = "Enabled routes", body = [crate::db::DatabaseRouteResponse])),
    security(("admin_bearer" = [])),
    tag = "Admin API"
)]
pub(crate) async fn list_admin_routes(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    if !api_authorized(&state, &headers, false).await {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    match state.db.list_database_route_records().await {
        Ok(routes) => Json(
            routes
                .into_iter()
                .map(DatabaseRouteResponse::from)
                .collect::<Vec<_>>(),
        )
        .into_response(),
        Err(error) => {
            tracing::error!(error = %error, "listing routes failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[utoipa::path(
    post,
    path = "/admin/routes",
    request_body = RouteWriteBody,
    responses((status = 201, description = "Route created", body = crate::db::DatabaseRouteResponse)),
    security(("admin_bearer" = [])),
    tag = "Admin API"
)]
pub(crate) async fn create_admin_route(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<RouteWriteBody>,
) -> Response {
    if !api_authorized(&state, &headers, true).await {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let (Some(name), Some(target_url)) = (body.name.as_deref(), body.target_url.as_deref()) else {
        return (StatusCode::BAD_REQUEST, "name and target_url are required").into_response();
    };
    if name.trim().is_empty()
        || !valid_https_target(target_url)
        || !valid_environment(body.environment.as_deref())
        || (body.ref_prefix.is_none()
            && body.metadata_app.is_none()
            && body.plan_code_prefix.is_none()
            && body.app_identifier.is_none()
            && body.environment.is_none())
    {
        return (
            StatusCode::BAD_REQUEST,
            "target_url must be https and at least one match rule is required",
        )
            .into_response();
    }
    match state
        .db
        .create_database_route_with_matcher(
            name,
            target_url,
            &ExtendedRouteMatcher {
                metadata_app: body.metadata_app.clone(),
                plan_code_prefix: body.plan_code_prefix.clone(),
                reference_prefix: body.ref_prefix.clone(),
                app_identifier: body.app_identifier.clone(),
                environment: body.environment.clone(),
                provider: None,
            },
            body.enabled.unwrap_or(true),
        )
        .await
    {
        Ok(route) => {
            state.clear_route_cache().await;
            match state.db.find_database_route_record(&route.name).await {
                Ok(Some(record)) => (
                    StatusCode::CREATED,
                    Json(DatabaseRouteResponse::from(record)),
                )
                    .into_response(),
                Ok(None) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
                Err(error) => {
                    tracing::error!(error = %error, "loading created route failed");
                    StatusCode::INTERNAL_SERVER_ERROR.into_response()
                }
            }
        }
        Err(error) => {
            tracing::error!(error = %error, "creating route failed");
            StatusCode::BAD_REQUEST.into_response()
        }
    }
}

#[utoipa::path(
    patch,
    path = "/admin/routes/{name}",
    params(("name" = String, Path, description = "Route name")),
    request_body = RouteWriteBody,
    responses((status = 200, description = "Route updated", body = crate::db::DatabaseRouteResponse)),
    security(("admin_bearer" = [])),
    tag = "Admin API"
)]
pub(crate) async fn update_admin_route(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(name): Path<String>,
    Json(body): Json<RouteWriteBody>,
) -> Response {
    if !api_authorized(&state, &headers, true).await {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    if body
        .target_url
        .as_deref()
        .is_some_and(|value| !valid_https_target(value))
    {
        return (StatusCode::BAD_REQUEST, "target_url must be https").into_response();
    }
    if !valid_environment(body.environment.as_deref()) {
        return (
            StatusCode::BAD_REQUEST,
            "environment must be production or sandbox",
        )
            .into_response();
    }
    match state
        .db
        .update_database_route_with_matcher(
            &name,
            body.target_url.as_deref(),
            body.ref_prefix.as_deref().map(Some),
            body.metadata_app.as_deref().map(Some),
            body.plan_code_prefix.as_deref().map(Some),
            body.app_identifier.as_deref().map(Some),
            body.environment.as_deref().map(Some),
            body.enabled,
        )
        .await
    {
        Ok(Some(route)) => {
            state.clear_route_cache().await;
            match state.db.find_database_route_record(&route.name).await {
                Ok(Some(record)) => Json(DatabaseRouteResponse::from(record)).into_response(),
                Ok(None) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
                Err(error) => {
                    tracing::error!(error = %error, "loading updated route failed");
                    StatusCode::INTERNAL_SERVER_ERROR.into_response()
                }
            }
        }
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => (StatusCode::BAD_REQUEST, error.to_string()).into_response(),
    }
}

#[utoipa::path(
    delete,
    path = "/admin/routes/{name}",
    params(("name" = String, Path, description = "Route name")),
    responses((status = 204, description = "Route deleted")),
    security(("admin_bearer" = [])),
    tag = "Admin API"
)]
pub(crate) async fn delete_admin_route(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> Response {
    if !api_authorized(&state, &headers, true).await {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    match state.db.delete_database_route(&name).await {
        Ok(true) => {
            state.clear_route_cache().await;
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => {
            tracing::error!(error = %error, "deleting route failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[derive(Debug, Deserialize, utoipa::IntoParams)]
pub(crate) struct DeliveryQuery {
    reference: Option<String>,
}

#[utoipa::path(
    get,
    path = "/admin/deliveries",
    params(DeliveryQuery),
    responses((status = 200, description = "Delivery records", body = [crate::db::DeliveryView])),
    security(("admin_bearer" = [])),
    tag = "Admin API"
)]
pub(crate) async fn list_admin_deliveries(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<DeliveryQuery>,
) -> Response {
    if !api_authorized(&state, &headers, false).await {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    match state.db.list_deliveries(query.reference.as_deref()).await {
        Ok(deliveries) => Json(deliveries).into_response(),
        Err(error) => {
            tracing::error!(error = %error, "listing deliveries failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[utoipa::path(
    get,
    path = "/admin/settings",
    responses((status = 200, description = "Settings with masked secret values", body = [crate::db::SettingView])),
    security(("admin_bearer" = [])),
    tag = "Admin API"
)]
pub(crate) async fn list_admin_settings(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    if !api_authorized(&state, &headers, false).await {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    match state.db.list_settings().await {
        Ok(settings) => Json(settings).into_response(),
        Err(error) => {
            tracing::error!(error = %error, "listing settings failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[utoipa::path(
    put,
    path = "/admin/settings/{key}",
    params(("key" = String, Path, description = "Setting key")),
    request_body = SettingWriteBody,
    responses((status = 204, description = "Setting stored")),
    security(("admin_bearer" = [])),
    tag = "Admin API"
)]
pub(crate) async fn set_admin_setting(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(key): Path<String>,
    Json(body): Json<SettingWriteBody>,
) -> Response {
    if !api_authorized(&state, &headers, true).await {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    if key.trim().is_empty() || body.value.is_empty() {
        return (StatusCode::BAD_REQUEST, "key and value are required").into_response();
    }
    let is_secret =
        body.is_secret || key.ends_with("KEY") || key.ends_with("TOKEN") || key.contains("WEBHOOK");
    match state
        .db
        .set_setting(&key, &body.value, is_secret, None)
        .await
    {
        Ok(()) => {
            if let Err(error) = state.reload_runtime_config().await {
                tracing::error!(error = %error, "reloading settings failed");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
            StatusCode::NO_CONTENT.into_response()
        }
        Err(error) => {
            tracing::error!(error = %error, "saving setting failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[utoipa::path(
    delete,
    path = "/admin/settings/{key}",
    params(("key" = String, Path, description = "Setting key")),
    responses((status = 204, description = "Setting deleted")),
    security(("admin_bearer" = [])),
    tag = "Admin API"
)]
pub(crate) async fn delete_admin_setting(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(key): Path<String>,
) -> Response {
    if !api_authorized(&state, &headers, true).await {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    match state.db.delete_setting(&key).await {
        Ok(_) => {
            if let Err(error) = state.reload_runtime_config().await {
                tracing::error!(error = %error, "reloading settings failed");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
            StatusCode::NO_CONTENT.into_response()
        }
        Err(error) => {
            tracing::error!(error = %error, "deleting setting failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[utoipa::path(
    post,
    path = "/admin/bootstrap",
    request_body = BootstrapBody,
    responses((status = 201, description = "First admin created")),
    security(("admin_bearer" = [])),
    tag = "Admin API"
)]
pub(crate) async fn bootstrap_admin(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<BootstrapBody>,
) -> Response {
    if !state.bootstrap_token.as_deref().is_some_and(|token| {
        bearer_matches(
            token,
            headers
                .get(header::AUTHORIZATION)
                .and_then(|value| value.to_str().ok()),
        )
    }) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    match state.db.user_count().await {
        Ok(0) => {
            let Ok(hash) = crate::auth::hash_password(&body.password) else {
                return StatusCode::BAD_REQUEST.into_response();
            };
            match state
                .db
                .create_user(&body.email, &hash, crate::auth::Role::Admin)
                .await
            {
                Ok(_) => StatusCode::CREATED.into_response(),
                Err(error) => {
                    tracing::error!(error = %error, "creating first admin failed");
                    StatusCode::BAD_REQUEST.into_response()
                }
            }
        }
        Ok(_) => StatusCode::CONFLICT.into_response(),
        Err(error) => {
            tracing::error!(error = %error, "checking admin bootstrap state failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

pub async fn retention_loop(state: Arc<AppState>) {
    loop {
        let retention_days = state.runtime_config.read().await.retention_days;
        if let Err(error) = state.db.prune_delivered(retention_days).await {
            tracing::error!(error = %error, "retention cleanup failed");
        }
        sleep(Duration::from_secs(86_400)).await;
    }
}
