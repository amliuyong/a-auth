import { useEffect, useState } from 'react';
import { Alert, Button, Space, Typography, message } from 'antd';
import { useTranslation } from 'react-i18next';
import { api } from '../api/client';
import { bufToB64url, b64urlToBuf, webauthnSupported } from '../api/webauthn';

/**
 * passkey 注册仪式(spec 003 §3.9,C9.4)。嵌入 /account(会话鉴权),类比 RecoverySetup。
 *
 * 流程:register/begin(下发 challenge+选项,绑当前会话 user_id)→ navigator.credentials.create()
 *      → register/finish(consume challenge + 验 attestation + 存凭证)。
 *
 * 铁律(评审收敛):
 * - **user.id 走 TextEncoder**(后端 user_id 是明文串,非 base64url;codex Blocker1);rp.id=后端返回值
 *   (逐租户权威源,不用 window.location;codex High1)。
 * - base64url↔ArrayBuffer 只用于 challenge/rawId/clientDataJSON/attestationObject(webauthn.ts)。
 * - 能力检测:不支持(非安全上下文/无 PublicKeyCredential)→ 不渲染;feature 关(begin 404)→ 记住隐藏。
 * - 取消(NotAllowedError)→ info 非 error;其它失败 → friendly。
 *
 * visible=false 时不渲染(父页未登录/加载中);无 show-once 明文,故无 RecoverySetup 的强制渲染守卫。
 */
type Props = {
  visible: boolean;
  knownStatus?: { configured: boolean; count: number };
  onRegistered?: () => void;
  onReauthenticationRequired?: () => void;
};

export function PasskeySetup({
  visible,
  knownStatus,
  onRegistered,
  onReauthenticationRequired,
}: Props) {
  const { t } = useTranslation();
  const [busy, setBusy] = useState(false);
  const [hidden, setHidden] = useState(false); // feature 关(begin 404)→ 记住隐藏
  const [error, setError] = useState<string | null>(null);
  const [status, setStatus] = useState<{ configured: boolean; count: number } | null>(null);
  const [promptDismissed, setPromptDismissed] = useState(false);
  const supported = webauthnSupported();

  useEffect(() => {
    if (!visible || !supported || hidden) return;
    if (knownStatus) {
      setStatus(knownStatus);
      return;
    }
    let cancelled = false;
    const loadStatus = async () => {
      try {
        const { data, response } = await api.GET('/passkey/status');
        if (cancelled) return;
        if (response.status === 404) {
          setHidden(true);
        } else if (response.status === 401) {
          setError(t('account.signin'));
        } else if (response.ok && data) {
          setStatus(data);
        } else {
          setError(t('error.generic'));
        }
      } catch (e) {
        if (!cancelled) {
          setError(e instanceof TypeError ? t('error.network') : t('error.generic'));
        }
      }
    };
    void loadStatus();
    return () => {
      cancelled = true;
    };
  }, [hidden, knownStatus, supported, t, visible]);

  // 浏览器不支持 WebAuthn / 非安全上下文 → 不渲染(挂载即知)。
  if (!visible || hidden || !supported) {
    return null;
  }

  const register = async () => {
    setBusy(true);
    setError(null);
    try {
      // 1. begin(会话鉴权)。
      const { data, response } = await api.POST('/passkey/register/begin');
      if (response.status === 404) {
        setHidden(true); // feature 关 → 隐藏入口
        return;
      }
      if (response.status === 401) {
        setError(t('account.signin'));
        return;
      }
      if (response.status === 403) {
        onReauthenticationRequired?.();
        return;
      }
      if (!response.ok || !data) {
        setError(t('error.generic'));
        return;
      }
      // 直接用 openapi-fetch 生成类型(评审 Kiro Blocker:勿 `as` 断言绕过契约,否则后端 schema 漂移
      // 编译期查不出)。`data` 已是 RegisterBeginResponse 类型。
      const opts = data;
      // 2. 组 PublicKeyCredentialCreationOptions。user.id=TextEncoder(明文 user_id,非 base64url);
      //    rp.id=后端返回值;challenge/excludeCredentials.id 走 base64url→ArrayBuffer。
      const cred = (await navigator.credentials.create({
        publicKey: {
          rp: { id: opts.rp_id, name: 'Agent Auth' },
          user: {
            id: new TextEncoder().encode(opts.user_id),
            name: opts.user_id,
            displayName: opts.user_id,
          },
          challenge: b64urlToBuf(opts.challenge),
          pubKeyCredParams: [{ alg: opts.alg, type: 'public-key' }],
          authenticatorSelection: {
            userVerification: (opts.user_verification as UserVerificationRequirement) || 'required',
          },
          excludeCredentials: opts.exclude_credentials.map((id) => ({
            id: b64urlToBuf(id),
            type: 'public-key' as const,
          })),
          timeout: 120000,
        },
      })) as PublicKeyCredential | null;
      if (!cred) {
        setError(t('error.generic'));
        return;
      }
      const att = cred.response as AuthenticatorAttestationResponse;
      // 3. finish(consume challenge + 验 attestation + 存凭证)。
      const fin = await api.POST('/passkey/register/finish', {
        body: {
          challenge: opts.challenge,
          client_data_json: bufToB64url(att.clientDataJSON),
          attestation_object: bufToB64url(att.attestationObject),
        },
      });
      if (fin.response.ok) {
        setStatus((current) => ({
          configured: true,
          count: (current?.count ?? 0) + 1,
        }));
        void message.success(t('passkey.register.success'));
        onRegistered?.();
      } else if (fin.response.status === 401) {
        setError(t('account.signin'));
      } else if (fin.response.status === 403) {
        onReauthenticationRequired?.();
      } else {
        setError(t('passkey.failed'));
      }
    } catch (e) {
      // 用户取消 / 超时 = NotAllowedError → info 非 error(非失败);其它 → friendly。
      if (e instanceof DOMException && e.name === 'NotAllowedError') {
        void message.info(t('passkey.cancelled'));
      } else if (e instanceof TypeError) {
        setError(t('error.network'));
      } else {
        setError(t('passkey.failed'));
      }
    } finally {
      setBusy(false);
    }
  };

  const enrollmentWarning = status && !status.configured && !promptDismissed;

  return (
    <div style={{ marginTop: 32 }}>
      <Typography.Title level={4}>{t('passkey.register.title')}</Typography.Title>
      <Typography.Paragraph type="secondary">{t('passkey.register.subtitle')}</Typography.Paragraph>
      {enrollmentWarning && (
        <Alert
          type="warning"
          showIcon
          message={t('passkey.register.promptTitle')}
          description={t('passkey.register.promptDescription')}
          action={
            <Space direction="vertical">
              <Button type="primary" loading={busy} onClick={() => void register()}>
                {t('passkey.register.add')}
              </Button>
              <Button type="text" onClick={() => setPromptDismissed(true)}>
                {t('passkey.register.notNow')}
              </Button>
            </Space>
          }
          style={{ marginBottom: 16 }}
        />
      )}
      {error && <Alert type="error" showIcon message={error} style={{ marginBottom: 12 }} />}
      {status?.configured && (
        <Typography.Paragraph type="secondary">
          {t('passkey.register.configured', { count: status.count })}
        </Typography.Paragraph>
      )}
      {!enrollmentWarning && (
        <Space>
          <Button type="primary" loading={busy} onClick={() => void register()}>
            {t('passkey.register.add')}
          </Button>
        </Space>
      )}
    </div>
  );
}
