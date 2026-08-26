#!/usr/bin/env bash
# spec 003 §4(C9.5)上游 IdP 联邦真机 e2e:本 AS 作 downstream RP,把用户登录联邦到**真 Cognito**(OIDC)。
#
# 全链(真往返,不走浏览器——用 requests 模拟 Cognito Hosted UI 表单):
#   GET  {AS}/authorize?...&idp_hint={IDP}   → 303 到上游 Cognito authorize(带本 AS 回调 + state + PKCE)
#   GET  {COGNITO}/oauth2/authorize          → Hosted UI 登录页(取 _csrf + cookie)
#   POST {COGNITO}/login                      → 测试用户凭证登录 → 302 回 {AS}/federation/callback?code=&state=
#   GET  {AS}/federation/callback            → 换上游 token + 验 id_token(iss/aud/nonce/exp)+ 建本地会话
#                                              (Set-Cookie __Host-agent_auth_session)→ 303 续跑回 /authorize
#   GET  {AS}/authorize(带会话)             → 联邦用户被识别为已认证 → 进 consent(征下游同意)不回落登录
#
# 前置(真机):
#   - 部署带 AGENT_AUTH_FEDERATION_ENABLED=1 + 自定义域名(见 infra;AS_URL 用该域)。
#   - Cognito User Pool + domain + confidential app client(callback = {AS_URL}/federation/callback)+ 测试用户。
#   - client secret 存 Secrets Manager 前缀 agent-auth/federation/*(IAM 已授权)。
#   - PUT /admin/federation 登记该上游(tenant=default,idp={IDP},issuer/端点/client_id/secret_ref/scopes)。
#   - 下游 OAuth client 已注册(DOWN_CLIENT_ID;redirect_uri=DOWN_REDIRECT)。
#
# 用法(全部 env 占位符,无账号/secret 硬编码):
#   AS_URL=https://auth.<zone>                 本 AS 自定义域
#   IDP=cognito                                登记的 upstream_idp_id
#   COGNITO_DOMAIN=https://<prefix>.auth.<region>.amazoncognito.com
#   UPSTREAM_CLIENT_ID=<cognito app client id>
#   DOWN_CLIENT_ID=<本 AS 下游 client id>       DOWN_REDIRECT=https://<downstream>/cb
#   TEST_USER=<email>                          TEST_PASSWORD=<pw>(仅测试用户;勿用真凭证)
#   ./e2e/federation.sh
set -euo pipefail

: "${AS_URL:?需 AS_URL(本 AS 自定义域,如 https://auth.aws.<zone>)}"
: "${IDP:=cognito}"
: "${COGNITO_DOMAIN:?需 COGNITO_DOMAIN(https://<prefix>.auth.<region>.amazoncognito.com)}"
: "${UPSTREAM_CLIENT_ID:?需 UPSTREAM_CLIENT_ID(Cognito app client id)}"
: "${DOWN_CLIENT_ID:?需 DOWN_CLIENT_ID(本 AS 下游 client)}"
: "${DOWN_REDIRECT:=https://probe.example.com/cb}"
: "${TEST_USER:?需 TEST_USER(测试用户邮箱)}"
: "${TEST_PASSWORD:?需 TEST_PASSWORD(测试用户密码;勿用真凭证)}"

exec python3 "$(dirname "$0")/federation_roundtrip.py"
