//! 从代码派生 OpenAPI JSON,导出到 `openapi/openapi.json`(repo 根)。
//!
//! 代码即契约:schema 由 handler 类型 + `#[utoipa::path]` 派生,不手写。
//! CI 应跑本 bin 后校验 `git diff --exit-code openapi/openapi.json`(生成物与提交一致)。
//!
//! 用法:`cargo run -p agent-auth-http --bin export-openapi -- <输出路径>`(默认 openapi/openapi.json)。

use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let out = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("openapi/openapi.json"));

    let doc = agent_auth_http::openapi_doc();
    let json = doc.to_pretty_json()?;

    if let Some(parent) = out.parent() {
        std::fs::create_dir_all(parent)?;
    }
    // 结尾补换行,便于 diff / POSIX 文本约定。
    std::fs::write(&out, format!("{json}\n"))?;
    eprintln!("OpenAPI 已导出到 {}", out.display());
    Ok(())
}
