//! mTLS 客户端证书接入 seam(spec 012 §1.4 X.509-SVID / C5.7,P3)。
//!
//! **可测缝**:handler 只依赖 plain `ClientCertPem` 请求扩展(零 lambda 依赖),便于进程内 e2e 直接注入。
//! 真机(`feature=lambda`)由 [`client_cert_layer`] 中间件把 lambda_http 的 `RequestContext`
//! (API Gateway mTLS 已验链的客户端证书,`authentication.client_cert.client_cert_pem`)翻译成该扩展。
//!
//! **安全不变量(评审 H1/H3)**:X.509 身份**仅当**该扩展存在(= 连接层真有已验证证书)时才成立;
//! execute-api / CloudFront 回源路径无 mTLS 握手 → 扩展恒缺 → X.509 路径自然 fail-closed 不激活。
//! 任何 header/query 都不得注入该扩展(只有 lambda 层从 requestContext 真实证书翻译)。

/// 已验链的客户端证书叶子 PEM(来自 API Gateway mTLS `requestContext.authentication.clientCert`)。
/// 存在即代表**连接层真有一张 API Gateway 已验链到 truststore 的客户端证书**。
#[derive(Debug, Clone)]
pub struct ClientCertPem(pub String);

/// Trusted client IP copied only from API Gateway request context. Password
/// rate limiting never derives this value from forwarding headers.
#[derive(Debug, Clone)]
pub struct TrustedSourceIp(pub String);

/// `feature=lambda` 中间件:从 lambda_http `RequestContext` 提取 mTLS 客户端证书 PEM 与可信 sourceIp
/// 注入请求扩展。仅 API Gateway v2 context 被接受;header/query 不能构造这些扩展。
#[cfg(feature = "lambda")]
pub async fn client_cert_layer(
    mut req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use lambda_http::request::RequestContext;
    let context = req.extensions().get::<RequestContext>();
    let pem = context
        .and_then(|ctx| match ctx {
            // ApiGatewayV2 变体直接包 ApiGatewayV2httpRequestContext(authentication 是其直接字段)。
            RequestContext::ApiGatewayV2(v2ctx) => v2ctx
                .authentication
                .as_ref()
                .and_then(|a| a.client_cert.as_ref())
                .and_then(|c| c.client_cert_pem.clone()),
            _ => None,
        })
        .filter(|p| !p.trim().is_empty());
    let source_ip = context
        .and_then(|ctx| match ctx {
            RequestContext::ApiGatewayV2(v2ctx) => v2ctx.http.source_ip.clone(),
            _ => None,
        })
        .filter(|ip| !ip.trim().is_empty());
    if let Some(pem) = pem {
        req.extensions_mut().insert(ClientCertPem(pem));
    }
    if let Some(source_ip) = source_ip {
        req.extensions_mut().insert(TrustedSourceIp(source_ip));
    }
    next.run(req).await
}

#[cfg(all(test, feature = "lambda"))]
mod tests {
    use crate::ports::RateLimitStore;
    use crate::{build_router, AppState};
    use axum::body::Body;
    use axum::extract::Extension;
    use axum::http::{Request, StatusCode};
    use axum::middleware;
    use axum::routing::get;
    use axum::Router;
    use lambda_http::aws_lambda_events::event::apigw::{
        ApiGatewayV2httpRequestContext, ApiGatewayV2httpRequestContextAuthentication,
        ApiGatewayV2httpRequestContextAuthenticationClientCert,
    };
    use lambda_http::request::RequestContext;
    use tower::ServiceExt;

    async fn observed_client_certificate(
        certificate: Option<Extension<super::ClientCertPem>>,
    ) -> String {
        certificate
            .map(|Extension(value)| value.0)
            .unwrap_or_else(|| "none".to_string())
    }

    #[tokio::test]
    async fn lambda_request_context_is_the_only_client_certificate_input() {
        let router = Router::new()
            .route("/certificate", get(observed_client_certificate))
            .layer(middleware::from_fn(super::client_cert_layer));

        let forged = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/certificate")
                    .header("x-client-cert", "forged-header-certificate")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let forged_body = axum::body::to_bytes(forged.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(forged_body.as_ref(), b"none");

        let mut certificate = ApiGatewayV2httpRequestContextAuthenticationClientCert::default();
        certificate.client_cert_pem = Some("trusted-request-context-certificate".to_string());
        let mut authentication = ApiGatewayV2httpRequestContextAuthentication::default();
        authentication.client_cert = Some(certificate);
        let mut context = ApiGatewayV2httpRequestContext::default();
        context.authentication = Some(authentication);
        let mut trusted = Request::builder()
            .uri("/certificate")
            .header("x-client-cert", "forged-header-certificate")
            .body(Body::empty())
            .unwrap();
        trusted
            .extensions_mut()
            .insert(RequestContext::ApiGatewayV2(context));

        let trusted = router.oneshot(trusted).await.unwrap();
        let trusted_body = axum::body::to_bytes(trusted.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(
            trusted_body.as_ref(),
            b"trusted-request-context-certificate"
        );
    }

    fn password_request() -> axum::http::request::Builder {
        Request::builder()
            .method("POST")
            .uri("/login/password")
            .header("host", "localhost")
            .header("content-type", "application/json")
            .header("x-forwarded-for", "198.51.100.99")
    }

    #[tokio::test]
    async fn lambda_request_context_is_the_only_trusted_source_ip_input() {
        let state = AppState::dev("localhost");
        let rate_limit = state.rate_limit.clone().expect("rate-limit store");
        let future_now = crate::token::current_unix_secs_pub() + 3600;
        for _ in 0..30 {
            assert!(
                rate_limit
                    .try_consume("pwd:ip::203.0.113.17", future_now, 30.0, 0.5, 1.0)
                    .await
                    .unwrap()
                    .allowed
            );
        }
        let router = build_router(state).0;
        let mut context = ApiGatewayV2httpRequestContext::default();
        context.http.source_ip = Some("203.0.113.17".to_string());
        let mut trusted_request = password_request()
            .body(Body::from(
                serde_json::json!({
                    "email": "lambda-source-ip@example.com",
                    "password": "Any wrong password!",
                })
                .to_string(),
            ))
            .expect("request");
        trusted_request
            .extensions_mut()
            .insert(RequestContext::ApiGatewayV2(context));

        let trusted = router
            .clone()
            .oneshot(trusted_request)
            .await
            .expect("trusted request");
        assert_eq!(trusted.status(), StatusCode::TOO_MANY_REQUESTS);

        for _ in 0..30 {
            assert!(
                rate_limit
                    .try_consume("pwd:ip::198.51.100.99", future_now, 30.0, 0.5, 1.0)
                    .await
                    .unwrap()
                    .allowed
            );
        }
        let forged = router
            .oneshot(
                password_request()
                    .body(Body::from(
                        serde_json::json!({
                            "email": "lambda-xff-only@example.com",
                            "password": "Any wrong password!",
                        })
                        .to_string(),
                    ))
                    .expect("request"),
            )
            .await
            .expect("forged request");
        assert_eq!(forged.status(), StatusCode::UNAUTHORIZED);
    }
}
