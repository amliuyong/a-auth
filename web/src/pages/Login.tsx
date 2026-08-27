import { useEffect, useRef, useState } from 'react';
import { Alert, Button, Divider, Form, Input, Space, Typography, message } from 'antd';
import type { InputRef } from 'antd';
import { useTranslation } from 'react-i18next';
import { useSearchParams } from 'react-router-dom';
import { Layout } from '../Layout';
import { api } from '../api/client';
import { bufToB64url, b64urlToBuf, webauthnSupported } from '../api/webauthn';
import { passwordRule } from '../passwordPolicy';

/**
 * 登录成功后续跑目标(passkey 认证建会话后前端自行跳转,后端不返回 next)。
 * open-redirect 防线(评审 codex:passkey finish 无后端 sanitize,MUST 前端做):
 * **用 `new URL(raw, origin)` 解析后校 origin 严格同源**,只返回 `pathname+search+hash`——比字符串规则稳,
 * 天然挡 `//`/`\`/绝对 URL/**C0 控制字符(tab/LF/CR)绕过**(评审 codex High:`/%09//evil` 解码后浏览器剥 tab
 * 变 `//evil`,纯字符串规则漏)。解析失败 / 跨源 → 回落 /account。
 * authorize_query 非空 → 优先续跑 /authorize(继续 OAuth 流)。
 */
function safeNext(raw: string | null): string {
  if (!raw) return '/account';
  // C0 控制字符(码点 < 0x20,含 tab/LF/CR)一律拒——浏览器 URL 解析会剥它们,留着会绕过 origin 判定。
  // 逐码点判(避免源码内嵌控制字符)。
  for (let i = 0; i < raw.length; i++) {
    if (raw.charCodeAt(i) < 0x20) return '/account';
  }
  try {
    const u = new URL(raw, window.location.origin);
    if (u.origin !== window.location.origin) return '/account'; // 跨源(绝对 URL / 协议相对)拒
    // 只回相对路径(丢弃 origin 部分,防意外带上跨源;此处已同源,pathname+search+hash 即安全相对路径)。
    const rel = u.pathname + u.search + u.hash;
    return rel.startsWith('/') ? rel : '/account';
  } catch {
    return '/account'; // 非法 URL
  }
}

/**
 * magic-link 登录页(C9.1/C9.2)。path = /login,可 bookmark。
 * 保留 authorize 的 query(client_id/redirect_uri/state/code_challenge…)以便登录后续流。
 *
 * ⚠️ 后端 magic-link 请求 API(POST /login/magic-link)属 P0.5(引真实身份前),尚未接;
 * 本页先落 UI + 交互 + i18n,提交时调预期端点,失败降级为提示。
 */
type LoginForm = {
  email: string;
  password: string;
  newPassword: string;
  confirmPassword: string;
};

type LoginCredentials = Pick<LoginForm, 'email' | 'password'>;

export function Login() {
  const { t } = useTranslation();
  const [params] = useSearchParams();
  const [form] = Form.useForm<LoginForm>();
  // OIDF BrowserControl uses HtmlUnit clear()+sendKeys(); AntD Form field
  // subscriptions can block that event loop, so read login values at submit.
  const emailInput = useRef<InputRef>(null);
  const passwordInput = useRef<InputRef>(null);
  const [ready, setReady] = useState(false);
  const [loginFieldErrors, setLoginFieldErrors] = useState<
    Partial<Record<keyof LoginCredentials, string>>
  >({});
  const [sent, setSent] = useState(false);
  const [passwordBusy, setPasswordBusy] = useState(false);
  const [magicBusy, setMagicBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [pkBusy, setPkBusy] = useState(false);
  const [passkeyOff, setPasskeyOff] = useState(false); // begin 404(feature 关)→ 记住隐藏入口(评审 codex Low3)
  const [changeRequired, setChangeRequired] = useState(false);
  const [temporaryCredentials, setTemporaryCredentials] = useState<{
    email: string;
    password: string;
  } | null>(null);
  const passkeyAvailable = webauthnSupported() && !passkeyOff;

  useEffect(() => {
    setReady(true);
  }, []);

  // authorize 上下文 = 除 next 外的全部 query(next 单列发送,不混入 authorize_query)。
  const authorizeParams = new URLSearchParams(params);
  authorizeParams.delete('next');
  const authorizeQuery = authorizeParams.toString();

  // 登录成功后续跑:authorize_query 非空 → /authorize 续 OAuth 流;否则 next(前端 sanitize);否则 /account。
  const continueAfterLogin = () => {
    if (authorizeQuery) {
      window.location.href = `/authorize?${authorizeQuery}`;
    } else {
      window.location.href = safeNext(params.get('next'));
    }
  };

  // passkey 认证仪式(pre-login):begin(login_hint)→ navigator.credentials.get() → finish → 建会话 → 续跑。
  const onPasskey = async (values: { email: string }) => {
    setPkBusy(true);
    setError(null);
    try {
      const beginResp = await api.GET('/passkey/authenticate/begin', {
        params: { query: { login_hint: values.email } },
      });
      if (beginResp.response.status === 404) {
        setPasskeyOff(true); // 记住隐藏 passkey 入口(不再让用户反复点已关的功能)
        setError(t('passkey.unsupported'));
        return;
      }
      if (!beginResp.response.ok || !beginResp.data) {
        setError(t('error.generic'));
        return;
      }
      // 直接用 openapi-fetch 生成类型(评审 Kiro Blocker:勿 `as` 断言绕过契约)。data=AuthBeginResponse。
      const opts = beginResp.data;
      // 该 email 无 passkey(allow_credentials 空)→ 不调 get(免浏览器弹空列表);自动回落 magic-link
      // 表单 + info 提示(评审 Kiro Med:减少用户手动切换)。
      if (opts.allow_credentials.length === 0) {
        void message.info(t('passkey.noCredentials'));
        return;
      }
      // 组 PublicKeyCredentialRequestOptions;rpId=后端返回值(不用 window.location)。
      const assertion = (await navigator.credentials.get({
        publicKey: {
          rpId: opts.rp_id,
          challenge: b64urlToBuf(opts.challenge),
          allowCredentials: opts.allow_credentials.map((id) => ({
            id: b64urlToBuf(id),
            type: 'public-key' as const,
          })),
          userVerification: (opts.user_verification as UserVerificationRequirement) || 'required',
          timeout: 120000,
        },
      })) as PublicKeyCredential | null;
      if (!assertion) {
        setError(t('error.generic'));
        return;
      }
      const ar = assertion.response as AuthenticatorAssertionResponse;
      const fin = await api.POST('/passkey/authenticate/finish', {
        body: {
          challenge: opts.challenge,
          credential_id: bufToB64url(assertion.rawId), // rawId → credential_id(评审 codex Med1)
          client_data_json: bufToB64url(ar.clientDataJSON),
          authenticator_data: bufToB64url(ar.authenticatorData),
          signature: bufToB64url(ar.signature),
        },
      });
      if (fin.response.ok && fin.data?.authenticated) {
        void message.success(t('passkey.authenticate.success'));
        continueAfterLogin();
      } else {
        setError(t('passkey.failed'));
      }
    } catch (e) {
      if (e instanceof DOMException && e.name === 'NotAllowedError') {
        void message.info(t('passkey.cancelled'));
      } else if (e instanceof TypeError) {
        setError(t('error.network'));
      } else {
        setError(t('passkey.failed'));
      }
    } finally {
      setPkBusy(false);
    }
  };

  const passwordError = (status: number) => {
    if (status === 401) return t('login.invalidCredentials');
    if (status === 429) return t('login.tooManyAttempts');
    if (status === 503) return t('login.unavailable');
    return t('error.generic');
  };

  const readLoginCredentials = (passwordRequired: boolean): LoginCredentials | null => {
    const emailElement = emailInput.current?.input;
    const passwordElement = passwordInput.current?.input;
    const values = {
      email: emailElement?.value ?? '',
      password: passwordElement?.value ?? '',
    };
    const fieldErrors: Partial<Record<keyof LoginCredentials, string>> = {};

    if (!values.email) {
      fieldErrors.email = t('login.emailRequired');
    } else if (emailElement && !emailElement.validity.valid) {
      fieldErrors.email = t('login.emailInvalid');
    }
    if (passwordRequired && !values.password) {
      fieldErrors.password = t('login.passwordRequired');
    }

    setError(null);
    setLoginFieldErrors(fieldErrors);
    return Object.keys(fieldErrors).length === 0 ? values : null;
  };

  const signInWithPassword = async (values: LoginCredentials) => {
    setPasswordBusy(true);
    setError(null);
    try {
      const { data, response } = await api.POST('/login/password', {
        body: {
          email: values.email,
          password: values.password,
          authorize_query: authorizeQuery,
        },
      });
      if (response.ok && data?.authenticated) {
        form.resetFields();
        continueAfterLogin();
      } else if (response.ok && data?.password_change_required) {
        setTemporaryCredentials({ email: values.email, password: values.password });
        setChangeRequired(true);
      } else {
        setError(passwordError(response.status));
      }
    } catch {
      setError(t('error.network'));
    } finally {
      setPasswordBusy(false);
    }
  };

  const submitPassword = async () => {
    const values = readLoginCredentials(true);
    if (values) {
      await signInWithPassword(values);
    }
  };

  const changePassword = async (values: LoginForm) => {
    if (!temporaryCredentials) {
      setChangeRequired(false);
      setError(t('error.generic'));
      return;
    }
    setPasswordBusy(true);
    setError(null);
    try {
      const { data, response } = await api.POST('/login/password/change', {
        body: {
          email: temporaryCredentials.email,
          current_password: temporaryCredentials.password,
          new_password: values.newPassword,
          authorize_query: authorizeQuery,
        },
      });
      if (response.ok && data?.authenticated) {
        setTemporaryCredentials(null);
        form.resetFields();
        continueAfterLogin();
      } else if (response.status === 400) {
        setError(t('login.passwordPolicy'));
      } else if (response.status === 409) {
        setTemporaryCredentials(null);
        setChangeRequired(false);
        form.setFieldsValue({ password: '', newPassword: '', confirmPassword: '' });
        setError(t('login.passwordChangedElsewhere'));
      } else {
        setError(passwordError(response.status));
      }
    } catch {
      setError(t('error.network'));
    } finally {
      setPasswordBusy(false);
    }
  };

  const requestMagicLink = async (values: { email: string }) => {
    setMagicBusy(true);
    setError(null);
    try {
      const { response } = await api.POST('/login/magic-link', {
        body: {
          email: values.email,
          authorize_query: authorizeQuery,
          next: params.get('next') ?? '',
        },
      });
      if (response.status === 429) {
        setError(t('login.cooldown'));
      } else if (!response.ok) {
        setError(t('error.generic'));
      } else {
        setSent(true);
      }
    } catch (e) {
      // 区分网络错(fetch reject = TypeError)与其它,给更贴切提示。
      setError(e instanceof TypeError ? t('error.network') : t('error.generic'));
    } finally {
      setMagicBusy(false);
    }
  };

  const submitPasskey = async () => {
    const values = readLoginCredentials(false);
    if (values) {
      await onPasskey({ email: values.email });
    }
  };

  const submitMagicLink = async () => {
    const values = readLoginCredentials(false);
    if (values) {
      await requestMagicLink({ email: values.email });
    }
  };

  return (
    <Layout>
      {ready && <span id="agent-auth-login-ready" hidden aria-hidden="true" />}
      <Typography.Title level={3}>{t('login.title')}</Typography.Title>
      <Typography.Paragraph type="secondary">{t('login.subtitle')}</Typography.Paragraph>
      {sent && !changeRequired ? (
        <>
          <Alert type="success" showIcon message={t('login.sent')} />
          <Button type="link" onClick={() => setSent(false)} style={{ paddingLeft: 0, marginTop: 12 }}>
            {t('login.resend')}
          </Button>
        </>
      ) : (
        <Form
          form={form}
          layout="vertical"
          noValidate
          onFinish={(values) => {
            if (changeRequired) {
              return changePassword(values);
            }
            return submitPassword();
          }}
          requiredMark={false}
        >
          {error && (
            <Form.Item>
              <Alert type="error" showIcon message={error} />
            </Form.Item>
          )}
          {changeRequired ? (
            <>
              <Alert
                type="info"
                showIcon
                message={t('login.changeRequired')}
                style={{ marginBottom: 20 }}
              />
              <Form.Item name="newPassword" label={t('login.newPassword')}
                rules={[passwordRule(t('login.passwordPolicy'))]}>
                <Input.Password size="large" autoComplete="new-password" />
              </Form.Item>
              <Form.Item
                name="confirmPassword"
                label={t('login.confirmPassword')}
                dependencies={['newPassword']}
                rules={[
                  { required: true, message: t('login.confirmRequired') },
                  ({ getFieldValue }) => ({
                    validator(_, value) {
                      return value === getFieldValue('newPassword')
                        ? Promise.resolve()
                        : Promise.reject(new Error(t('login.passwordMismatch')));
                    },
                  }),
                ]}
              >
                <Input.Password size="large" autoComplete="new-password" />
              </Form.Item>
              <Button
                type="primary"
                htmlType="submit"
                size="large"
                block
                loading={passwordBusy}
              >
                {t('login.changePassword')}
              </Button>
              <Button
                type="link"
                block
                onClick={() => {
                  setTemporaryCredentials(null);
                  setChangeRequired(false);
                  setError(null);
                  form.setFieldsValue({ password: '', newPassword: '', confirmPassword: '' });
                }}
              >
                {t('login.backToSignIn')}
              </Button>
            </>
          ) : (
            <>
              <Form.Item
                label={t('login.email')}
                htmlFor="agent-auth-login-email"
                validateStatus={loginFieldErrors.email ? 'error' : undefined}
                help={
                  loginFieldErrors.email
                    ? <span id="agent-auth-login-email-error">{loginFieldErrors.email}</span>
                    : undefined
                }
              >
                <Input
                  ref={emailInput}
                  id="agent-auth-login-email"
                  type="email"
                  size="large"
                  autoComplete="username webauthn"
                  placeholder="you@example.com"
                  required
                  status={loginFieldErrors.email ? 'error' : undefined}
                  aria-invalid={Boolean(loginFieldErrors.email)}
                  aria-describedby={
                    loginFieldErrors.email ? 'agent-auth-login-email-error' : undefined
                  }
                />
              </Form.Item>
              <Form.Item
                label={t('login.password')}
                htmlFor="agent-auth-login-password"
                validateStatus={loginFieldErrors.password ? 'error' : undefined}
                help={
                  loginFieldErrors.password
                    ? <span id="agent-auth-login-password-error">{loginFieldErrors.password}</span>
                    : undefined
                }
              >
                <Input.Password
                  ref={passwordInput}
                  id="agent-auth-login-password"
                  size="large"
                  autoComplete="current-password"
                  required
                  status={loginFieldErrors.password ? 'error' : undefined}
                  aria-invalid={Boolean(loginFieldErrors.password)}
                  aria-describedby={
                    loginFieldErrors.password ? 'agent-auth-login-password-error' : undefined
                  }
                />
              </Form.Item>
              <Button
                id="agent-auth-login-submit"
                type="primary"
                htmlType="submit"
                size="large"
                block
                loading={passwordBusy}
              >
                {t('login.signIn')}
              </Button>
              <Divider plain>{t('login.or')}</Divider>
              <Space direction="vertical" style={{ width: '100%' }}>
                {passkeyAvailable && (
                  <Button
                    htmlType="button"
                    size="large"
                    block
                    loading={pkBusy}
                    onClick={() => void submitPasskey()}
                  >
                    {pkBusy ? t('passkey.authenticate.authenticating') : t('passkey.authenticate.button')}
                  </Button>
                )}
                <Button
                  htmlType="button"
                  size="large"
                  block
                  loading={magicBusy}
                  onClick={() => void submitMagicLink()}
                >
                  {magicBusy ? t('login.sending') : t('login.send')}
                </Button>
              </Space>
            </>
          )}
        </Form>
      )}
      <Typography.Paragraph style={{ marginTop: 16, marginBottom: 0 }}>
        <Typography.Link href="/recover">{t('login.useRecoveryCode')}</Typography.Link>
      </Typography.Paragraph>
    </Layout>
  );
}
