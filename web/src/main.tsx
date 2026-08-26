import React from 'react';
import ReactDOM from 'react-dom/client';
import { ConfigProvider } from 'antd';
import enUS from 'antd/locale/en_US';
import zhCN from 'antd/locale/zh_CN';
import { createBrowserRouter, Navigate, RouterProvider, useLocation } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import './i18n';
import { Login } from './pages/Login';
import { Consent } from './pages/Consent';
import { Recover } from './pages/Recover';
import { Account } from './pages/Account';
import { Approve } from './pages/Approve';
import { Admin } from './pages/Admin';
import { ErrorPage } from './pages/ErrorPage';
import { Invite } from './pages/Invite';

/**
 * 保留当前 query 的重定向(修评审 bug):IdP 可能落到 `/?client_id=..&state=..`(authorize
 * 上下文挂根路径),静态 Navigate 会丢 search、后续 magic-link 拿不到 authorize 上下文。
 */
function RedirectKeepingQuery({ to }: { to: string }) {
  const { search } = useLocation();
  return <Navigate to={{ pathname: to, search }} replace />;
}

/** catch-all:保留原 query 再附 error=not_found(不覆盖已有上下文)。 */
function NotFoundRedirect() {
  const { search } = useLocation();
  const params = new URLSearchParams(search);
  if (!params.has('error')) params.set('error', 'not_found');
  return <Navigate to={{ pathname: '/error', search: params.toString() }} replace />;
}

// 真实路由(path 可 bookmark,用户硬要求):每个交互页独立 URL,可直接访问/收藏/分享。
const router = createBrowserRouter([
  { path: '/login', element: <Login /> },
  { path: '/invite', element: <Invite /> },
  { path: '/consent', element: <Consent /> },
  { path: '/recover', element: <Recover /> },
  // 用户自助授权管理(spec 011 §5.1)+ 异步授权批准页(spec 013 §2b)。page path 与 API 动作 path
  // (/grants、/device、/bc-approve)分离——CloudFront 按 path 选 origin,SPA 页显式挂 S3、API 落
  // default→API(同 /consent↔/consent/decision 收敛)。二者都靠会话 cookie 鉴权,未登录引导 /login。
  { path: '/account', element: <Account /> },
  { path: '/approve', element: <Approve /> },
  // admin 控制台(spec 025):**只用 /admin 一个真实 path**;tab/search 用 query state,
  // 避免 SPA 子路径与 /admin/clients、/admin/overview API 前缀在 CloudFront 上冲突。
  { path: '/admin', element: <Admin /> },
  { path: '/error', element: <ErrorPage /> },
  { path: '/', element: <RedirectKeepingQuery to="/login" /> },
  { path: '*', element: <NotFoundRedirect /> },
]);

function App() {
  const { i18n } = useTranslation();
  // antd 组件文案随 i18n 语言切换(中/英)。
  const locale = i18n.language.startsWith('zh') ? zhCN : enUS;
  return (
    <ConfigProvider locale={locale} theme={{ token: { colorPrimary: '#1677ff' } }}>
      <RouterProvider router={router} />
    </ConfigProvider>
  );
}

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
