use std::{sync::Arc, time::Instant};

use chrono::Utc;
use futures_util::StreamExt;
use serde_json::Value;
use tokio::time::{Duration, sleep};

use crate::{app::AppState, db::ClaimedDelivery};

pub const MAX_ATTEMPTS: i32 = 10;

pub fn retry_delay(attempt: i32) -> Option<Duration> {
    match attempt {
        1 => Some(Duration::from_secs(30)),
        2 => Some(Duration::from_mins(2)),
        3 => Some(Duration::from_mins(10)),
        4 => Some(Duration::from_mins(30)),
        5 => Some(Duration::from_hours(1)),
        6 => Some(Duration::from_hours(3)),
        7 => Some(Duration::from_hours(6)),
        8 => Some(Duration::from_hours(12)),
        9 => Some(Duration::from_hours(24)),
        _ => None,
    }
}

pub async fn run_worker(state: Arc<AppState>) {
    loop {
        match state.db.claim_delivery().await {
            Ok(Some(delivery)) => process_one(&state, delivery).await,
            Ok(None) => sleep(Duration::from_millis(500)).await,
            Err(error) => {
                tracing::error!(error = %error, "claiming delivery failed");
                sleep(Duration::from_secs(2)).await;
            }
        }
    }
}

pub async fn process_one(state: &AppState, delivery: ClaimedDelivery) {
    let started = Utc::now();
    let timer = Instant::now();
    let mut request = state.http.post(&delivery.destination_url);
    let mut has_content_type = false;
    let configured_header = delivery.outbound_auth_header.as_deref();
    if let Some(headers) = delivery.headers.as_object() {
        for (name, value) in headers {
            if configured_header.is_some_and(|configured| name.eq_ignore_ascii_case(configured))
                || name.eq_ignore_ascii_case("x-fanout-signature")
            {
                continue;
            }
            if !forwardable_header(name) {
                continue;
            }
            has_content_type |= name.eq_ignore_ascii_case("content-type");
            match value {
                Value::String(value) => {
                    request = request.header(name, value);
                }
                Value::Array(values) => {
                    for value in values.iter().filter_map(Value::as_str) {
                        request = request.header(name, value);
                    }
                }
                _ => {}
            }
        }
    }
    if !has_content_type {
        request = request.header("content-type", &delivery.content_type);
    }
    let fanout_event_id = if delivery.provider_event_id.is_empty() {
        delivery.event_id.to_string()
    } else {
        delivery.provider_event_id.clone()
    };
    let request = request
        .header("x-fanout-event-id", fanout_event_id)
        .header("x-fanout-attempt", delivery.attempt.to_string())
        .body(delivery.forward_body.clone());
    let request = match outbound_auth_value(
        delivery.outbound_auth_mode.as_deref(),
        delivery.outbound_auth_header.as_deref(),
        delivery.outbound_auth_secret.as_deref(),
        &delivery.forward_body,
    ) {
        Ok(Some((header, value))) => request.header(header, value),
        Ok(None) => request,
        Err(error) => {
            finish_failure(
                state,
                &delivery,
                started,
                Utc::now(),
                None,
                None,
                Some(error),
                0,
            )
            .await;
            return;
        }
    }
    .send()
    .await;
    let latency_ms = i32::try_from(timer.elapsed().as_millis()).unwrap_or(i32::MAX);
    let finished = Utc::now();
    state
        .metrics
        .observe_delivery_ms(u64::try_from(latency_ms).unwrap_or_default());
    match request {
        Ok(response) if response.status().is_success() => {
            let status = response.status().as_u16();
            let body = read_response_body(response).await;
            if let Err(error) = state
                .db
                .record_success(
                    &delivery,
                    started,
                    finished,
                    status,
                    body.as_deref(),
                    latency_ms,
                )
                .await
            {
                tracing::error!(error = %error, event_id = %delivery.event_id, "recording delivery success failed");
            }
            state
                .metrics
                .delivered
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        Ok(response) => {
            let status = response.status().as_u16();
            let body = read_response_body(response).await;
            finish_failure(
                state,
                &delivery,
                started,
                finished,
                Some(status),
                body.as_deref(),
                None,
                latency_ms,
            )
            .await;
        }
        Err(error) => {
            finish_failure(
                state,
                &delivery,
                started,
                finished,
                None,
                None,
                Some(&error.to_string()),
                latency_ms,
            )
            .await;
        }
    }
}

fn forwardable_header(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "content-type"
            | "authorization"
            | "x-paystack-signature"
            | "x-apple-signature"
            | "x-apple-notification-signature"
            | "x-apple-connect-signature"
            | "x-google-signature"
            | "x-goog-signature"
    )
}

#[allow(clippy::too_many_arguments)]
async fn finish_failure(
    state: &AppState,
    delivery: &ClaimedDelivery,
    started: chrono::DateTime<Utc>,
    finished: chrono::DateTime<Utc>,
    status: Option<u16>,
    body: Option<&str>,
    error: Option<&str>,
    latency_ms: i32,
) {
    let next = (delivery.attempt < delivery.max_attempts)
        .then(|| retry_delay(delivery.attempt))
        .flatten()
        .map(|delay| {
            Utc::now()
                + chrono::Duration::from_std(jitter(delay)).expect("jitter duration is valid")
        });
    let is_dead = next.is_none();
    if let Err(db_error) = state
        .db
        .record_failure(
            delivery, started, finished, status, body, error, latency_ms, next,
        )
        .await
    {
        tracing::error!(error = %db_error, event_id = %delivery.event_id, "recording delivery failure failed");
        return;
    }
    if is_dead {
        state
            .metrics
            .dead
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        state
            .alert(format!(
                "Paystack event {} delivery is dead after {} attempts",
                delivery.event_id, delivery.attempt
            ))
            .await;
    } else {
        state
            .metrics
            .retries
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}

fn jitter(delay: Duration) -> Duration {
    let ratio = 0.8 + (f64::from(rand::random::<u16>()) / f64::from(u16::MAX)) * 0.4;
    Duration::from_secs_f64(delay.as_secs_f64() * ratio)
}

fn outbound_auth_value(
    mode: Option<&str>,
    header: Option<&str>,
    secret: Option<&str>,
    body: &[u8],
) -> Result<Option<(String, String)>, &'static str> {
    let Some(mode) = mode else { return Ok(None) };
    let (Some(header), Some(secret)) = (header, secret) else {
        return Err("outbound authentication is incomplete");
    };
    let value = match mode {
        "static_header" => secret.to_owned(),
        "hmac_sha512" => crate::security::sign_forward(secret.as_bytes(), body),
        _ => return Err("outbound authentication mode is unsupported"),
    };
    Ok(Some((header.to_owned(), value)))
}

async fn read_response_body(response: reqwest::Response) -> Option<String> {
    let mut bytes = Vec::with_capacity(2_048);
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let Ok(chunk) = chunk else { break };
        let remaining = 2_048usize.saturating_sub(bytes.len());
        bytes.extend_from_slice(&chunk[..chunk.len().min(remaining)]);
        if bytes.len() >= 2_048 {
            break;
        }
    }
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_schedule_and_max_attempts() {
        assert_eq!(retry_delay(1).unwrap().as_secs(), 30);
        assert_eq!(retry_delay(2).unwrap().as_secs(), 120);
        assert_eq!(retry_delay(3).unwrap().as_secs(), 600);
        assert_eq!(retry_delay(9).unwrap().as_secs(), 86_400);
        assert!(retry_delay(MAX_ATTEMPTS).is_none());
    }

    #[test]
    fn hmac_auth_is_over_exact_forward_body() {
        let body = b"{\"amount\":1}\n";
        let (_, signature) = outbound_auth_value(
            Some("hmac_sha512"),
            Some("x-fanout-signature"),
            Some("relay-secret"),
            body,
        )
        .unwrap()
        .unwrap();
        assert!(crate::security::verify_signature(
            b"relay-secret",
            body,
            Some(&signature)
        ));
        assert!(!crate::security::verify_signature(
            b"relay-secret",
            br#"{"amount":1}"#,
            Some(&signature)
        ));
    }

    #[test]
    fn static_auth_preserves_literal_value() {
        assert_eq!(
            outbound_auth_value(
                Some("static_header"),
                Some("authorization"),
                Some("Bearer literal"),
                b"body"
            )
            .unwrap(),
            Some(("authorization".into(), "Bearer literal".into()))
        );
    }
}
