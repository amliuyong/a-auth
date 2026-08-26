//! 本地 axum server(开发 / e2e 联调)。真机走 Lambda(`lambda` feature + API Gateway)。
//!
//! 用法:`cargo run -p agent-auth-http --bin agent-auth-server`;监听 127.0.0.1:8080。
//! issuer 形态默认自部署 + P0;`AGENT_AUTH_HOST` 环境变量可覆盖配置 host(默认 localhost)。

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let host = std::env::var("AGENT_AUTH_HOST").unwrap_or_else(|_| "localhost".to_string());
    let state = agent_auth_http::AppState::dev(&host);
    let (router, _api) = agent_auth_http::build_router(state);

    let addr = "127.0.0.1:8080";
    let listener = tokio::net::TcpListener::bind(addr).await?;
    eprintln!("agent-auth-server 监听 http://{addr}(配置 host={host})");
    axum::serve(listener, router).await?;
    Ok(())
}
