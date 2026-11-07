//! Bounded public JWKS fetching, cache and single-flight refresh.

use crate::ports::StoreError;
use std::collections::HashMap;

/// 平台 JWKS HTTP 取用(spec 012 workload_oidc_jwt),带 **TTL 缓存 + 负缓存 + 限速**(评审 M3:
/// 防 unknown-kid 触发的重取放大成 DoS)。rustls;只 GET 管理面登记的 `jwks_uri`(调用方保证,绝不取
/// JWT header 的 jku/x5u)。缓存键 = jwks_uri。
/// 正/负缓存共用:空 vec 即成功获取的空集。每个 URI 自带异步锁,并发冷取/强刷等待同一结果。
struct JwksCacheEntry {
    keys: Vec<crate::ports::PlatformJwk>,
    fetched_at: Option<i64>,
    last_forced_at: Option<i64>,
    last_failure: Option<(StoreError, i64)>,
    last_used_at: i64,
    refresh_lock: std::sync::Arc<tokio::sync::Mutex<()>>,
}

type JwksCache = std::sync::Arc<tokio::sync::Mutex<HashMap<String, JwksCacheEntry>>>;

#[derive(Clone)]
pub struct HttpJwksFetcher {
    cache: JwksCache,
    #[cfg(test)]
    network_requests: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

impl Default for HttpJwksFetcher {
    fn default() -> Self {
        Self::new()
    }
}

impl HttpJwksFetcher {
    pub fn new() -> Self {
        HttpJwksFetcher {
            cache: std::sync::Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            #[cfg(test)]
            network_requests: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        }
    }
}

/// JWKS 缓存 TTL(秒):正缓存 5min(平台 key 轮换慢);负缓存/限速窗同用,防重取风暴。
const JWKS_CACHE_TTL: i64 = 300;
const JWKS_FORCE_REFRESH_MIN_INTERVAL: i64 = 5;
const JWKS_MAX_CACHE_ENTRIES: usize = 256;
const JWKS_MAX_RESPONSE_BYTES: usize = 64 * 1024;
const JWKS_MAX_KEYS: usize = 10;

impl HttpJwksFetcher {
    fn evict_oldest_if_full(
        cache: &mut HashMap<String, JwksCacheEntry>,
        incoming_uri: &str,
    ) -> Result<(), StoreError> {
        if cache.contains_key(incoming_uri) || cache.len() < JWKS_MAX_CACHE_ENTRIES {
            return Ok(());
        }
        if let Some(oldest) = cache
            .iter()
            .filter(|(_, entry)| std::sync::Arc::strong_count(&entry.refresh_lock) == 1)
            .min_by_key(|(_, entry)| entry.last_used_at)
            .map(|(uri, _)| uri.clone())
        {
            cache.remove(&oldest);
            return Ok(());
        }
        Err(StoreError::Transient(
            "JWKS cache capacity is busy".to_string(),
        ))
    }

    async fn cached_result(
        &self,
        jwks_uri: &str,
        honor_cache_ttl: bool,
    ) -> Option<Result<Vec<crate::ports::PlatformJwk>, StoreError>> {
        let now = crate::token::current_unix_secs_pub();
        let mut cache = self.cache.lock().await;
        if let Some(entry) = cache.get_mut(jwks_uri) {
            entry.last_used_at = now;
            let recently_fetched = if honor_cache_ttl {
                entry
                    .fetched_at
                    .is_some_and(|at| now.saturating_sub(at) < JWKS_CACHE_TTL)
            } else {
                entry
                    .last_forced_at
                    .is_some_and(|at| now.saturating_sub(at) < JWKS_FORCE_REFRESH_MIN_INTERVAL)
            };
            if recently_fetched {
                if !honor_cache_ttl {
                    if let Some((error, failed_at)) = &entry.last_failure {
                        if entry
                            .last_forced_at
                            .is_some_and(|forced_at| *failed_at >= forced_at)
                        {
                            return Some(Err(error.clone()));
                        }
                    }
                }
                return Some(Ok(entry.keys.clone()));
            }
            if let Some((error, failed_at)) = &entry.last_failure {
                if now.saturating_sub(*failed_at) < JWKS_FORCE_REFRESH_MIN_INTERVAL {
                    return Some(Err(error.clone()));
                }
            }
        }
        None
    }

    async fn refresh_lock_for_uri(
        &self,
        jwks_uri: &str,
    ) -> Result<std::sync::Arc<tokio::sync::Mutex<()>>, StoreError> {
        let now = crate::token::current_unix_secs_pub();
        let mut cache = self.cache.lock().await;
        if let Some(entry) = cache.get_mut(jwks_uri) {
            entry.last_used_at = now;
            return Ok(entry.refresh_lock.clone());
        }
        Self::evict_oldest_if_full(&mut cache, jwks_uri)?;
        let refresh_lock = std::sync::Arc::new(tokio::sync::Mutex::new(()));
        cache.insert(
            jwks_uri.to_string(),
            JwksCacheEntry {
                keys: Vec::new(),
                fetched_at: None,
                last_forced_at: None,
                last_failure: None,
                last_used_at: now,
                refresh_lock: refresh_lock.clone(),
            },
        );
        Ok(refresh_lock)
    }

    async fn store_network_result(
        &self,
        jwks_uri: &str,
        forced: bool,
        result: &Result<Vec<crate::ports::PlatformJwk>, StoreError>,
    ) {
        let now = crate::token::current_unix_secs_pub();
        let mut cache = self.cache.lock().await;
        let Some(entry) = cache.get_mut(jwks_uri) else {
            return;
        };
        entry.last_used_at = now;
        if forced {
            entry.last_forced_at = Some(now);
        }
        match result {
            Ok(keys) => {
                entry.keys = keys.clone();
                entry.fetched_at = Some(now);
                entry.last_failure = None;
            }
            Err(error) => {
                entry.last_failure = Some((error.clone(), now));
            }
        }
    }

    async fn fetch_cached(
        &self,
        jwks_uri: &str,
        honor_cache_ttl: bool,
    ) -> Result<Vec<crate::ports::PlatformJwk>, StoreError> {
        if let Some(result) = self.cached_result(jwks_uri, honor_cache_ttl).await {
            return result;
        }
        let refresh_lock = self.refresh_lock_for_uri(jwks_uri).await?;
        let _refresh_guard = refresh_lock.lock().await;
        // 跟随者拿锁后复查 owner 已写入的成功/失败结果,不重复外呼。
        if let Some(result) = self.cached_result(jwks_uri, honor_cache_ttl).await {
            return result;
        }
        let result = self.fetch_network(jwks_uri).await;
        self.store_network_result(jwks_uri, !honor_cache_ttl, &result)
            .await;
        result
    }

    /// 外呼取一次；调用方持有该 URI 的 refresh lock 并负责写缓存结果。
    async fn fetch_network(
        &self,
        jwks_uri: &str,
    ) -> Result<Vec<crate::ports::PlatformJwk>, StoreError> {
        #[cfg(test)]
        self.network_requests
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let body = super::oidc_metadata::fetch_public_document(jwks_uri).await?;
        parse_jwks_document(&body)
    }
}

impl crate::ports::JwksFetcher for HttpJwksFetcher {
    async fn fetch(&self, jwks_uri: &str) -> Result<Vec<crate::ports::PlatformJwk>, StoreError> {
        self.fetch_cached(jwks_uri, true).await
    }

    async fn fetch_fresh(
        &self,
        jwks_uri: &str,
    ) -> Result<Vec<crate::ports::PlatformJwk>, StoreError> {
        self.fetch_cached(jwks_uri, false).await
    }
}

fn parse_jwks_document(body: &[u8]) -> Result<Vec<crate::ports::PlatformJwk>, StoreError> {
    if body.len() > JWKS_MAX_RESPONSE_BYTES {
        return Err(StoreError::Permanent(
            "JWKS response exceeds size limit".to_string(),
        ));
    }
    let doc: serde_json::Value = serde_json::from_slice(body)
        .map_err(|e| StoreError::Permanent(format!("JWKS json: {e}")))?;
    let source = doc
        .get("keys")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| StoreError::Permanent("JWKS keys must be an array".to_string()))?;
    if source.len() > JWKS_MAX_KEYS {
        return Err(StoreError::Permanent(
            "JWKS key count exceeds limit".to_string(),
        ));
    }
    Ok(source
        .iter()
        .filter_map(|key| {
            let allows_verification = key
                .get("use")
                .is_none_or(|value| value.as_str() == Some("sig"))
                && match key.get("key_ops") {
                    None => true,
                    Some(serde_json::Value::Array(operations)) => operations
                        .iter()
                        .any(|operation| operation.as_str() == Some("verify")),
                    Some(_) => false,
                };
            if !allows_verification {
                return None;
            }
            let kty = key.get("kty").and_then(serde_json::Value::as_str);
            let kid = key
                .get("kid")
                .and_then(serde_json::Value::as_str)
                .map(String::from);
            let alg = key
                .get("alg")
                .and_then(serde_json::Value::as_str)
                .map(String::from);
            match kty {
                Some("RSA") => Some(crate::ports::PlatformJwk {
                    kid,
                    kty: Some("RSA".into()),
                    n: key
                        .get("n")
                        .and_then(serde_json::Value::as_str)?
                        .to_string(),
                    e: key
                        .get("e")
                        .and_then(serde_json::Value::as_str)?
                        .to_string(),
                    crv: None,
                    x: None,
                    y: None,
                    alg,
                }),
                Some("EC")
                    if key.get("crv").and_then(serde_json::Value::as_str) == Some("P-256") =>
                {
                    Some(crate::ports::PlatformJwk {
                        kid,
                        kty: Some("EC".into()),
                        n: String::new(),
                        e: String::new(),
                        crv: Some("P-256".into()),
                        x: Some(
                            key.get("x")
                                .and_then(serde_json::Value::as_str)?
                                .to_string(),
                        ),
                        y: Some(
                            key.get("y")
                                .and_then(serde_json::Value::as_str)?
                                .to_string(),
                        ),
                        alg,
                    })
                }
                _ => None,
            }
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::{
        parse_jwks_document, HttpJwksFetcher, JwksCacheEntry, JWKS_MAX_CACHE_ENTRIES,
        JWKS_MAX_KEYS, JWKS_MAX_RESPONSE_BYTES,
    };
    use crate::ports::{JwksFetcher, PlatformJwk, StoreError};

    #[test]
    fn parser_enforces_response_and_key_count_limits() {
        assert!(matches!(
            parse_jwks_document(&vec![b' '; JWKS_MAX_RESPONSE_BYTES + 1]),
            Err(StoreError::Permanent(_))
        ));
        let keys: Vec<serde_json::Value> = (0..=JWKS_MAX_KEYS)
            .map(|index| {
                serde_json::json!({
                    "kid": format!("key-{index}"),
                    "kty": "RSA",
                    "alg": "RS256",
                    "n": "modulus",
                    "e": "AQAB"
                })
            })
            .collect();
        assert!(matches!(
            parse_jwks_document(&serde_json::to_vec(&serde_json::json!({ "keys": keys })).unwrap()),
            Err(StoreError::Permanent(_))
        ));
    }

    #[test]
    fn parser_excludes_keys_not_allowed_for_signature_verification() {
        let rsa_key = |kid: &str| {
            serde_json::json!({
                "kid": kid,
                "kty": "RSA",
                "alg": "RS256",
                "n": "modulus",
                "e": "AQAB"
            })
        };
        let mut encryption_use = rsa_key("encryption-use");
        encryption_use["use"] = serde_json::json!("enc");
        let mut encryption_ops = rsa_key("encryption-ops");
        encryption_ops["key_ops"] = serde_json::json!(["encrypt"]);
        let mut malformed_ops = rsa_key("malformed-ops");
        malformed_ops["key_ops"] = serde_json::json!("verify");
        let mut verification_ops = rsa_key("verification-ops");
        verification_ops["key_ops"] = serde_json::json!(["verify"]);
        let parsed = parse_jwks_document(
            &serde_json::to_vec(&serde_json::json!({
                "keys": [
                    rsa_key("unspecified"),
                    encryption_use,
                    encryption_ops,
                    malformed_ops,
                    verification_ops
                ]
            }))
            .unwrap(),
        )
        .unwrap();

        assert_eq!(
            parsed
                .iter()
                .filter_map(|key| key.kid.as_deref())
                .collect::<Vec<_>>(),
            vec!["unspecified", "verification-ops"]
        );
    }

    #[tokio::test]
    async fn fetcher_blocks_literal_private_targets_before_network_io() {
        let fetcher = HttpJwksFetcher::new();
        assert!(matches!(
            fetcher.fetch("https://127.0.0.1/jwks").await,
            Err(StoreError::Permanent(_))
        ));
        assert!(matches!(
            fetcher.fetch("https://169.254.169.254/latest").await,
            Err(StoreError::Permanent(_))
        ));
    }

    #[tokio::test]
    async fn concurrent_force_refreshes_share_one_network_failure() {
        let fetcher = HttpJwksFetcher::new();
        let uri = "https://127.0.0.1/jwks";
        let mut attempts = Vec::new();
        for _ in 0..16 {
            let fetcher = fetcher.clone();
            attempts.push(tokio::spawn(async move { fetcher.fetch_fresh(uri).await }));
        }
        for attempt in attempts {
            assert!(attempt.await.unwrap().is_err());
        }
        assert_eq!(
            fetcher
                .network_requests
                .load(std::sync::atomic::Ordering::Relaxed),
            1,
            "并发 unknown-kid 强刷应等待并共享一次外呼结果"
        );
    }

    #[tokio::test]
    async fn failed_force_refresh_preserves_cached_key_ttl_and_starts_cooldown_on_completion() {
        let fetcher = HttpJwksFetcher::new();
        let uri = "https://127.0.0.1/jwks";
        let fetched_at = crate::token::current_unix_secs_pub() - 60;
        fetcher.cache.lock().await.insert(
            uri.to_string(),
            JwksCacheEntry {
                keys: vec![PlatformJwk {
                    kid: Some("known-key".to_string()),
                    ..Default::default()
                }],
                fetched_at: Some(fetched_at),
                last_forced_at: None,
                last_failure: None,
                last_used_at: fetched_at,
                refresh_lock: std::sync::Arc::new(tokio::sync::Mutex::new(())),
            },
        );

        let before = crate::token::current_unix_secs_pub();
        assert!(fetcher.fetch_fresh(uri).await.is_err());
        {
            let cache = fetcher.cache.lock().await;
            let entry = cache.get(uri).unwrap();
            assert_eq!(entry.fetched_at, Some(fetched_at));
            assert!(
                entry
                    .last_failure
                    .as_ref()
                    .is_some_and(|(_, failed_at)| *failed_at >= before),
                "失败冷却应从外呼完成时开始且不得延长旧 key TTL"
            );
        }
        assert_eq!(
            fetcher.fetch(uri).await.unwrap()[0].kid.as_deref(),
            Some("known-key"),
            "failed unknown-kid refresh must not hide a still-valid cached key"
        );
        assert!(fetcher.fetch_fresh(uri).await.is_err());
        assert_eq!(
            fetcher
                .network_requests
                .load(std::sync::atomic::Ordering::Relaxed),
            1,
            "forced refresh failures must be rate-limited during the cooldown"
        );
    }

    #[tokio::test]
    async fn ordinary_fetch_timestamp_does_not_suppress_forced_refresh() {
        let fetcher = HttpJwksFetcher::new();
        let uri = "https://127.0.0.1/jwks";
        let fetched_at = crate::token::current_unix_secs_pub();
        fetcher.cache.lock().await.insert(
            uri.to_string(),
            JwksCacheEntry {
                keys: Vec::new(),
                fetched_at: Some(fetched_at),
                last_forced_at: None,
                last_failure: None,
                last_used_at: fetched_at,
                refresh_lock: std::sync::Arc::new(tokio::sync::Mutex::new(())),
            },
        );

        assert!(fetcher.fetch_fresh(uri).await.is_err());
        assert_eq!(
            fetcher
                .network_requests
                .load(std::sync::atomic::Ordering::Relaxed),
            1,
            "a recent ordinary fetch must not count as the unknown-kid forced attempt"
        );
    }

    #[tokio::test]
    async fn concurrent_cold_fetches_make_one_network_attempt_and_cache_the_failure() {
        let fetcher = HttpJwksFetcher::new();
        let uri = "https://127.0.0.1/jwks";
        let mut attempts = Vec::new();
        for _ in 0..16 {
            let fetcher = fetcher.clone();
            attempts.push(tokio::spawn(async move { fetcher.fetch(uri).await }));
        }
        for attempt in attempts {
            assert!(attempt.await.unwrap().is_err());
        }
        assert_eq!(
            fetcher
                .network_requests
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
        assert!(fetcher.fetch(uri).await.is_err());
        assert_eq!(
            fetcher
                .network_requests
                .load(std::sync::atomic::Ordering::Relaxed),
            1,
            "失败结果应在限速窗内负缓存"
        );
    }

    #[tokio::test]
    async fn cache_entry_count_is_bounded() {
        let fetcher = HttpJwksFetcher::new();
        for index in 0..=JWKS_MAX_CACHE_ENTRIES {
            assert!(fetcher
                .refresh_lock_for_uri(&format!("https://keys-{index}.example.com/jwks"))
                .await
                .is_ok());
        }
        assert_eq!(fetcher.cache.lock().await.len(), JWKS_MAX_CACHE_ENTRIES);
    }

    #[tokio::test]
    async fn cache_does_not_evict_entries_with_active_refresh_callers() {
        let fetcher = HttpJwksFetcher::new();
        let mut active_locks = Vec::new();
        for index in 0..JWKS_MAX_CACHE_ENTRIES {
            active_locks.push(
                fetcher
                    .refresh_lock_for_uri(&format!("https://keys-{index}.example.com/jwks"))
                    .await
                    .unwrap(),
            );
        }
        assert!(matches!(
            fetcher
                .refresh_lock_for_uri("https://overflow.example.com/jwks")
                .await,
            Err(StoreError::Transient(_))
        ));
        assert_eq!(fetcher.cache.lock().await.len(), JWKS_MAX_CACHE_ENTRIES);
        drop(active_locks);
    }
}
