#!/usr/bin/env python3
"""spec 003 §4 上游 IdP 联邦真机往返驱动(由 e2e/federation.sh 调,env 提供配置)。

本 AS 作 downstream RP,把登录联邦到真 Cognito(OIDC):
  发起(/authorize?idp_hint) → Cognito Hosted UI 登录 → 回调(/federation/callback:换 token+验 id_token+
  建本地会话)→ 续跑 /authorize 识别为已认证。不走浏览器,用 requests 模拟 Hosted UI 表单 POST。

**凭证不打印**;TEST_PASSWORD 仅测试用户,勿传真凭证。所有配置走 env(见 federation.sh 头)。
"""
import os
import re
import sys
import urllib.parse as u

import requests

AS = os.environ["AS_URL"].rstrip("/")
IDP = os.environ.get("IDP", "cognito")
COGNITO = os.environ["COGNITO_DOMAIN"].rstrip("/")
UP_CID = os.environ["UPSTREAM_CLIENT_ID"]
DOWN_CID = os.environ["DOWN_CLIENT_ID"]
DOWN_CB = os.environ.get("DOWN_REDIRECT", "https://probe.example.com/cb")
USER = os.environ["TEST_USER"]
PW = os.environ["TEST_PASSWORD"]
CB = f"{AS}/federation/callback"
# 任意合法 S256 challenge(下游 code 不在此兑换;只验联邦建会话 + 续跑识别已认证)。
CH = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

s = requests.Session()


def fail(msg):
    print(f"FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


# 1. 本 AS 发起联邦:/authorize?idp_hint=<idp> → 303 到 Cognito authorize。
authz = (f"{AS}/authorize?response_type=code&client_id={DOWN_CID}"
         f"&redirect_uri={u.quote(DOWN_CB, safe='')}&code_challenge={CH}"
         f"&code_challenge_method=S256&scope=openid&state=downstate&idp_hint={IDP}")
r = s.get(authz, allow_redirects=False, timeout=20)
if r.status_code != 303 or COGNITO not in r.headers.get("location", ""):
    fail(f"发起腿应 303→Cognito,实得 {r.status_code} loc={r.headers.get('location','')[:80]}")
up_authz = r.headers["location"]
print("[1] 发起腿 303 → 上游 Cognito authorize ✓")

# 2. GET Cognito 登录页(取 _csrf + cookie)。
r = s.get(up_authz, timeout=20)
m_csrf = re.search(r'name="_csrf" value="([^"]*)"', r.text)
m_act = re.search(r'action="(/login[^"]*)"', r.text)
if not (m_csrf and m_act):
    fail("Cognito 登录页缺 _csrf/action")
csrf, action = m_csrf.group(1), m_act.group(1).replace("&amp;", "&")
print("[2] Cognito 登录页拿到 _csrf + form ✓")

# 3. POST 登录表单 → 302 回本 AS /federation/callback?code=&state=。
r = s.post(COGNITO + action,
           data={"_csrf": csrf, "username": USER, "password": PW},
           allow_redirects=False, timeout=20)
cb_loc = r.headers.get("location", "")
if r.status_code not in (302, 303) or CB not in cb_loc or "code=" not in cb_loc:
    fail(f"Cognito 登录应 30x→本 AS callback 带 code,实得 {r.status_code} loc={cb_loc[:80]}")
print("[3] Cognito 登录成功 → 302 回本 AS /federation/callback(带 code)✓")

# 4. 本 AS 回调:换 token + 验 id_token + 建本地会话(Set-Cookie)+ 303 续跑回 /authorize。
r = s.get(cb_loc, allow_redirects=False, timeout=20)
if r.status_code != 303:
    fail(f"回调腿应 303 续跑,实得 {r.status_code}: {r.text[:200]}")
if "__Host-agent_auth_session=" not in r.headers.get("set-cookie", ""):
    fail(f"回调应建本地会话 cookie,headers={dict(r.headers)}")
cont = r.headers["location"]
if "/authorize" not in cont:
    fail(f"应续跑回 /authorize,实得 {cont[:80]}")
print("[4] 回调腿 303 + Set-Cookie 本地会话 ✓(换 token + 验 id_token 通过);续跑回 /authorize")

# 5. 带会话续跑 /authorize → 联邦用户被识别为已认证(进 consent 或直签 code),不回落登录。
r = s.get(cont, allow_redirects=False, timeout=20)
final = r.headers.get("location", "")
if r.status_code != 303 or not (("/consent" in final) or (DOWN_CB in final and "code=" in final)):
    fail(f"续跑应 303→consent 或下游 code,实得 {r.status_code} loc={final[:80]}")
where = "consent(征下游同意)" if "/consent" in final else "下游 code(直签)"
print(f"[5] 续跑 /authorize → 303 → {where} ✓(联邦会话被识别为已认证,未回落登录)")

print("\n=== 联邦真机往返全绿:AS →(idp_hint)→ Cognito Hosted UI 登录 → 回调换token/验id_token/建会话 → 续跑识别已认证 ===")
