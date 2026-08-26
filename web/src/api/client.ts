import createClient from 'openapi-fetch';
import type { paths } from './schema';

// 类型化 API 客户端——路径/请求/响应类型由 openapi-typescript 从 repo 的 openapi/openapi.json
// 生成(npm run gen:api)。契约先行:后端改了 OpenAPI,前端类型自动跟随、编译期发现漂移。
//
// baseUrl:同源部署时为空(相对路径,与 /authorize 同域,cookie/CSRF 正确);
// 本地开发可用 VITE_API_BASE 指向后端(如真机 API Gateway)。
const baseUrl = import.meta.env.VITE_API_BASE ?? '';

export const api = createClient<paths>({ baseUrl });
