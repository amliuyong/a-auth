# Agent Auth — 前端交互页(web/)

React + TS SPA(Vite + antd + react-router + i18next),承载 consent 同意页、magic-link 登录页、
账户恢复页、错误页。**当前是 UI 骨架**:后端 magic-link/consent/recover 的 JSON API 属 **P0.5**
(引真实身份前置账户恢复 gate,见 `docs/DESIGN.md`),尚未接入;页面先落 UI + 交互 + i18n,调预期端点、
失败降级提示。

## 开发

```bash
npm install
npm run gen:api    # 从 ../openapi/openapi.json 生成 src/api/schema.d.ts(契约先行)
npm run dev        # 本地 :5173(VITE_API_BASE 可指向后端)
npm run build      # tsc + vite build → dist/
```

## 约束(用户要求,已满足)

- **i18n 中英**:`src/i18n`,antd locale 随 i18n 同步;语言优先级 `?ui_locales` → localStorage → navigator。
- **企业级观感**:antd + 统一 Layout(深色导航 + 居中卡片)。
- **path 可 bookmark**:`createBrowserRouter` 真实路由,每页独立 URL;重定向保留 query(authorize 上下文不丢)。
- **消费生成的 OpenAPI 类型**:`openapi-typescript` 从 `openapi/openapi.json` 生成类型,`openapi-fetch` 类型化客户端。

## 🔴 部署 gate / P0.5 待办

1. **CloudFront history fallback**:SPA 部署到 S3+CloudFront 时,MUST 配 `errorResponses` 把
   403/404 回退到 `/index.html`(200),否则直达 `/consent`、`/recover` 或书签会 404
   (path 可 bookmark 在客户端路由达标,但部署层需兑现)。CDK 前端栈随 P0.5。
2. **clickjacking 头**(C10.9b,DESIGN §8):consent/登录页响应 MUST 含 `Content-Security-Policy:
   frame-ancestors 'none'` + `X-Frame-Options: DENY`——在 CDN/托管层下发(见 `infra-core::websec`)。
3. **anti-CSRF token**(C10.9):consent SPA 通过同源、会话鉴权的 `GET /consent/context`
   读取 CSRF token 并只保存在内存中(**不走 URL query**,防 Referer/日志泄露),再随
   `POST /consent/decision` 回带。
4. **P0.5 JSON 端点接入**:`/login/magic-link`、`/consent`、`/recover` 落地后 MUST 加入
   `openapi.json`,并把页面里的裸 `fetch` 改为类型化 `api.POST(...)`(见 `src/api/client.ts`)。
5. **SERVER_SECRET** 走 Secrets Manager;magic-link 接 authn crate(cooldown/session nonce 绑定 C9.2)。
6. **RAR 结构化渲染**(DESIGN §11#8):consent 页当前只显示裸 scope,细粒度授权(RAR)渲染待补。
