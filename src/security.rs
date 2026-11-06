use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha512};
use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};
use subtle::ConstantTimeEq;
use url::Url;

type HmacSha256 = Hmac<Sha256>;
type HmacSha512 = Hmac<Sha512>;

pub fn verify_signature(secret: &[u8], body: &[u8], provided: Option<&str>) -> bool {
    let Some(provided) = provided else {
        return false;
    };
    let Ok(expected_bytes) = hex::decode(provided) else {
        return false;
    };
    let Ok(mut mac) = HmacSha512::new_from_slice(secret) else {
        return false;
    };
    mac.update(body);
    let expected = mac.finalize().into_bytes();
    expected.as_slice().ct_eq(&expected_bytes).into()
}

pub fn sign_forward(secret: &[u8], body: &[u8]) -> String {
    let mut mac = HmacSha512::new_from_slice(secret).expect("HMAC accepts any key");
    mac.update(body);
    hex::encode(mac.finalize().into_bytes())
}

pub fn verify_hmac_sha256_signature(secret: &[u8], body: &[u8], provided: Option<&str>) -> bool {
    let Some(provided) = provided.and_then(|value| value.strip_prefix("hmacsha256=")) else {
        return false;
    };
    let Ok(provided_bytes) = hex::decode(provided) else {
        return false;
    };
    let Ok(mut mac) = HmacSha256::new_from_slice(secret) else {
        return false;
    };
    mac.update(body);
    let expected = mac.finalize().into_bytes();
    expected.as_slice().ct_eq(&provided_bytes).into()
}

pub fn dedupe_key(body: &[u8]) -> String {
    hex::encode(Sha256::digest(body))
}

pub fn bearer_matches(token: &str, provided: Option<&str>) -> bool {
    let Some(value) = provided.and_then(|v| v.strip_prefix("Bearer ")) else {
        return false;
    };
    Sha256::digest(token.as_bytes())
        .as_slice()
        .ct_eq(Sha256::digest(value.as_bytes()).as_slice())
        .into()
}

pub fn is_private_or_local_ip(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            address.is_loopback()
                || address.is_private()
                || address.is_link_local()
                || address.is_unspecified()
                || address.is_broadcast()
        }
        IpAddr::V6(address) => {
            address.to_ipv4_mapped().is_some_and(|mapped| {
                mapped.is_loopback()
                    || mapped.is_private()
                    || mapped.is_link_local()
                    || mapped.is_unspecified()
                    || mapped.is_broadcast()
            }) || address.is_loopback()
                || address.is_unique_local()
                || address.is_unicast_link_local()
                || address.is_unspecified()
        }
    }
}

pub fn valid_public_url_syntax(value: &str, allow_http: bool) -> bool {
    let Ok(url) = Url::parse(value.trim()) else {
        return false;
    };
    if (url.scheme() != "https" && (!allow_http || url.scheme() != "http"))
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return false;
    }
    let host = url.host_str().unwrap_or_default().to_ascii_lowercase();
    if matches!(host.as_str(), "localhost" | "metadata.google.internal")
        || host.ends_with(".localhost")
        || host.ends_with(".local")
    {
        return false;
    }
    if let Ok(address) = host.parse::<IpAddr>() {
        return !is_private_or_local_ip(address);
    }
    true
}

pub async fn public_http_client(value: &str, allow_http: bool) -> anyhow::Result<reqwest::Client> {
    anyhow::ensure!(
        valid_public_url_syntax(value, allow_http),
        "outbound URL is not a public HTTP(S) URL"
    );
    let url = Url::parse(value.trim())?;
    let host = url
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("outbound URL has no host"))?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| anyhow::anyhow!("outbound URL has no port"))?;
    let addresses = if let Ok(address) = host.parse::<IpAddr>() {
        vec![SocketAddr::new(address, port)]
    } else {
        tokio::net::lookup_host((host, port))
            .await?
            .collect::<Vec<_>>()
    };
    anyhow::ensure!(
        !addresses.is_empty(),
        "outbound URL did not resolve to an address"
    );
    anyhow::ensure!(
        addresses
            .iter()
            .all(|address| !is_private_or_local_ip(address.ip())),
        "outbound URL resolved to a private or local address"
    );
    reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .resolve(host, addresses[0])
        .build()
        .map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_cases() {
        let secret = b"sk_test_secret";
        let body = br#"{"event":"charge.success"}"#;
        let mut mac = HmacSha512::new_from_slice(secret).unwrap();
        mac.update(body);
        let signature = hex::encode(mac.finalize().into_bytes());
        assert!(verify_signature(secret, body, Some(&signature)));
        assert_eq!(sign_forward(secret, body), signature);
        assert!(!verify_signature(
            secret,
            br#"{"event":"tampered"}"#,
            Some(&signature)
        ));
        assert!(!verify_signature(b"wrong", body, Some(&signature)));
        assert!(!verify_signature(secret, body, None));
    }

    #[test]
    fn app_store_connect_signature_cases() {
        let secret = b"app-store-connect-secret";
        let body = br#"{"data":{"type":"BUILD_UPLOAD_STATE_UPDATED"}}"#;
        let mut mac = HmacSha256::new_from_slice(secret).unwrap();
        mac.update(body);
        let signature = format!("hmacsha256={}", hex::encode(mac.finalize().into_bytes()));
        assert!(verify_hmac_sha256_signature(secret, body, Some(&signature)));
        assert!(!verify_hmac_sha256_signature(
            secret,
            br#"{"data":{"type":"tampered"}}"#,
            Some(&signature)
        ));
        assert!(!verify_hmac_sha256_signature(
            b"wrong",
            body,
            Some(&signature)
        ));
        assert!(!verify_hmac_sha256_signature(secret, body, None));
        assert!(!verify_hmac_sha256_signature(
            secret,
            body,
            Some("deadbeef")
        ));
    }

    #[test]
    fn private_and_local_addresses_are_rejected_for_outbound_requests() {
        assert!(is_private_or_local_ip("127.0.0.1".parse().unwrap()));
        assert!(is_private_or_local_ip("169.254.169.254".parse().unwrap()));
        assert!(is_private_or_local_ip("10.0.0.1".parse().unwrap()));
        assert!(is_private_or_local_ip("fd00::1".parse().unwrap()));
        assert!(!is_private_or_local_ip("8.8.8.8".parse().unwrap()));
        assert!(!is_private_or_local_ip(
            "2001:4860:4860::8888".parse().unwrap()
        ));
    }

    #[tokio::test]
    async fn public_http_client_rejects_private_and_local_targets() {
        assert!(
            public_http_client("http://127.0.0.1:8080", true)
                .await
                .is_err()
        );
        assert!(
            public_http_client("https://localhost/webhook", false)
                .await
                .is_err()
        );
    }
}
