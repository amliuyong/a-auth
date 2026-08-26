import { useCallback, useEffect, useState } from 'react';
import { Alert, Button, Form, Input, Popconfirm, Result, Space, Spin, Tag, Typography } from 'antd';
import { useTranslation } from 'react-i18next';
import { useSearchParams } from 'react-router-dom';
import { Layout } from '../Layout';
import { api } from '../api/client';

/**
 * form-urlencoded body 序列化器(评审 codex/Kiro HIGH):后端 device_approve / bc_approve_decide 用
 * Axum `Form(...)`,须 `application/x-www-form-urlencoded`;openapi-fetch 默认 `JSON.stringify` →
 * axum Form 遇非 urlencoded 返 415。传 URLSearchParams,fetch 自动置正确 Content-Type。
 * 各值 String 化(bool → "true"/"false",serde_urlencoded 可解;与 device_e2e.rs 断言一致)。
 */
const formBody = (b: unknown): URLSearchParams => {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(b as Record<string, unknown>)) p.set(k, String(v));
  return p;
};

/** 去"一键同意"惯性倒计时(spec 013 C7b.6 / Task 3.3):批准按钮出现后 N 秒禁用。返回剩余秒(0=可点)。 */
const APPROVE_DELAY_SECS = 3;
function useApproveCountdown(active: boolean): number {
  const [left, setLeft] = useState(APPROVE_DELAY_SECS);
  useEffect(() => {
    if (!active) return;
    setLeft(APPROVE_DELAY_SECS);
    const timer = setInterval(() => {
      setLeft((n) => {
        if (n <= 1) {
          clearInterval(timer);
          return 0;
        }
        return n - 1;
      });
    }, 1000);
    return () => clearInterval(timer);
  }, [active]);
  return left;
}

/**
 * 批准按钮:去"一键同意"惯性(spec 013 C7b.6,评审 L3)——**3s 倒计时禁用 + 点击二次确认**叠加
 * (纯延迟可盲点、纯二次确认可惯性,两者叠加)。倒计时内按钮禁用并显示剩余秒;倒计时结束后点击
 * 弹二次确认才真正提交。CIBA 与 device 批准共用。
 */
function ApproveButton({
  onApprove,
  loading,
  ready,
}: {
  onApprove: () => void;
  loading: boolean;
  ready: boolean; // 上下文就绪(CIBA 拉到 info / device 页已可交互)才起倒计时
}) {
  const { t } = useTranslation();
  const left = useApproveCountdown(ready);
  const disabled = !ready || left > 0;
  const btn = (
    <Button type="primary" loading={loading} disabled={disabled}>
      {left > 0 ? t('approve.wait', { secs: left }) : t('consent.approve')}
    </Button>
  );
  // 倒计时未结束禁用态下不挂 Popconfirm(禁用按钮不触发);就绪后点击弹二次确认。
  return disabled ? (
    btn
  ) : (
    <Popconfirm
      title={t('approve.confirm')}
      okText={t('consent.approve')}
      cancelText={t('consent.deny')}
      onConfirm={onApprove}
    >
      {btn}
    </Popconfirm>
  );
}

/**
 * 异步授权批准页(spec 013 §2b,P2)。path = /approve,可 bookmark。**须已登录**(会话 cookie)。
 *
 * 两模式(按 query 区分,与 device/CIBA 协议一致):
 * - **device**(默认;`?user_code=` 可预填,来自 verification_uri_complete):用户在本设备输入另一设备
 *   显示的 user_code → `POST /device`(approve/deny)。批准后 grant 认领当前登录 user(token 的 sub 源)。
 * - **CIBA**(`?auth_req_id=<id>`):先 `GET /bc-approve/{id}` 拉待批准上下文(发起 client + binding_message
 *   + scope/resources,IDOR-safe:非本人 404)→ approve/deny `POST /bc-approve/{id}`。
 *
 * 未登录:后端 401 → 引导 /login。CSRF 靠 session cookie SameSite=Lax(与 /consent 同套防线)。
 */

type ApproveInfo = {
  client_id: string;
  scope: string[];
  resources: string[];
  binding_message?: string | null;
  status: string;
};

export function Approve() {
  const { t } = useTranslation();
  const [params] = useSearchParams();
  const authReqId = params.get('auth_req_id');
  const mode: 'ciba' | 'device' = authReqId ? 'ciba' : 'device';

  return (
    <Layout>
      <Typography.Title level={3}>{t('approve.title')}</Typography.Title>
      <Typography.Paragraph type="secondary">{t('approve.subtitle')}</Typography.Paragraph>
      {mode === 'ciba' ? <CibaApprove authReqId={authReqId!} /> : <DeviceApprove />}
    </Layout>
  );
}

/** CIBA 批准:先拉上下文再决策。 */
function CibaApprove({ authReqId }: { authReqId: string }) {
  const { t } = useTranslation();
  const [info, setInfo] = useState<ApproveInfo | null>(null);
  const [needLogin, setNeedLogin] = useState(false);
  const [notFound, setNotFound] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [deciding, setDeciding] = useState<'approve' | 'deny' | null>(null);
  const [done, setDone] = useState<'approve' | 'deny' | null>(null);

  const load = useCallback(async () => {
    setError(null);
    setNeedLogin(false);
    setNotFound(false);
    try {
      const { data, response } = await api.GET('/bc-approve/{auth_req_id}', {
        params: { path: { auth_req_id: authReqId } },
      });
      if (response.status === 401) setNeedLogin(true);
      else if (response.status === 404) setNotFound(true);
      else if (response.ok) setInfo(data as ApproveInfo);
      else setError(t('error.generic'));
    } catch (e) {
      setError(e instanceof TypeError ? t('error.network') : t('error.generic'));
    }
  }, [authReqId, t]);

  useEffect(() => {
    void load();
  }, [load]);

  const decide = async (approve: boolean) => {
    setDeciding(approve ? 'approve' : 'deny');
    setError(null);
    try {
      const { response } = await api.POST('/bc-approve/{auth_req_id}', {
        params: { path: { auth_req_id: authReqId } },
        body: { approve },
        bodySerializer: formBody, // form-urlencoded(见 formBody 注释,评审 HIGH)
      });
      if (response.status === 401) setNeedLogin(true);
      else if (response.status === 404) setNotFound(true);
      else if (response.ok) setDone(approve ? 'approve' : 'deny');
      else setError(t('error.generic'));
    } catch (e) {
      setError(e instanceof TypeError ? t('error.network') : t('error.generic'));
    } finally {
      setDeciding(null);
    }
  };

  if (needLogin) return <LoginPrompt />;
  if (notFound) return <Alert type="warning" showIcon message={t('approve.notFound')} />;
  if (done)
    return (
      <Result
        status={done === 'approve' ? 'success' : 'info'}
        title={t(done === 'approve' ? 'approve.approved' : 'approve.denied')}
      />
    );
  if (!info)
    return (
      <div style={{ textAlign: 'center', padding: 32 }}>
        <Spin />
      </div>
    );

  return (
    <>
      {error && <Alert type="error" showIcon message={error} style={{ marginBottom: 16 }} />}
      <Alert type="warning" showIcon message={t('consent.unverified')} style={{ marginBottom: 16 }} />

      <Typography.Paragraph>
        {t('approve.requestedBy')}: <Typography.Text strong>{info.client_id}</Typography.Text>
      </Typography.Paragraph>

      {info.binding_message && (
        <Alert
          type="info"
          showIcon
          message={t('approve.bindingMessage')}
          description={<Typography.Text code>{info.binding_message}</Typography.Text>}
          style={{ marginBottom: 16 }}
        />
      )}

      <Typography.Text strong>{t('consent.scopes')}</Typography.Text>
      <div style={{ margin: '8px 0 12px' }}>
        {(info.scope.length ? info.scope : ['openid']).map((s) => (
          <Tag color="blue" key={s}>
            {s}
          </Tag>
        ))}
      </div>

      {info.resources.length > 0 && (
        <Typography.Paragraph>
          <Typography.Text strong>{t('consent.resource')}: </Typography.Text>
          {info.resources.map((r) => (
            <Typography.Text code key={r} style={{ marginRight: 6 }}>
              {r}
            </Typography.Text>
          ))}
        </Typography.Paragraph>
      )}

      <Space style={{ width: '100%', justifyContent: 'flex-end', marginTop: 8 }}>
        <Button onClick={() => decide(false)} loading={deciding === 'deny'}>
          {t('consent.deny')}
        </Button>
        {/* 去惯性:info 拉到才起 3s 倒计时 + 二次确认(C7b.6)。 */}
        <ApproveButton onApprove={() => decide(true)} loading={deciding === 'approve'} ready={!!info} />
      </Space>
    </>
  );
}

/** device 批准:输入 user_code(可从 ?user_code= 预填)+ approve/deny。 */
function DeviceApprove() {
  const { t } = useTranslation();
  const [params] = useSearchParams();
  const [needLogin, setNeedLogin] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState<'approve' | 'deny' | null>(null);
  const [done, setDone] = useState<'approve' | 'deny' | null>(null);
  const prefill = params.get('user_code') ?? '';

  const submit = async (userCode: string, approve: boolean) => {
    if (!userCode.trim()) {
      setError(t('approve.codeRequired'));
      return;
    }
    setLoading(approve ? 'approve' : 'deny');
    setError(null);
    try {
      const { response } = await api.POST('/device', {
        body: { user_code: userCode.trim(), approve },
        bodySerializer: formBody, // form-urlencoded(见 formBody 注释,评审 HIGH)
      });
      if (response.status === 401) setNeedLogin(true);
      else if (response.status === 404) setError(t('approve.notFound'));
      else if (response.ok) setDone(approve ? 'approve' : 'deny');
      else setError(t('error.generic'));
    } catch (e) {
      setError(e instanceof TypeError ? t('error.network') : t('error.generic'));
    } finally {
      setLoading(null);
    }
  };

  if (needLogin) return <LoginPrompt />;
  if (done)
    return (
      <Result
        status={done === 'approve' ? 'success' : 'info'}
        title={t(done === 'approve' ? 'approve.approved' : 'approve.denied')}
      />
    );

  return (
    <Form
      layout="vertical"
      requiredMark={false}
      initialValues={{ user_code: prefill }}
      // 回车不直接批准(去惯性 C7b.6:批准必经 3s 倒计时 + 二次确认,不走表单 submit 秒批)。
      onFinish={() => {}}
    >
      {error && (
        <Form.Item>
          <Alert type="error" showIcon message={error} />
        </Form.Item>
      )}
      <Alert type="warning" showIcon message={t('consent.unverified')} style={{ marginBottom: 16 }} />
      <Form.Item name="user_code" label={t('approve.userCode')} rules={[{ required: true }]}>
        <Input size="large" autoComplete="one-time-code" placeholder="ABCD-1234" autoFocus />
      </Form.Item>
      <Space style={{ width: '100%', justifyContent: 'flex-end' }}>
        <Form.Item shouldUpdate style={{ marginBottom: 0 }}>
          {({ getFieldValue }) => {
            const code = (getFieldValue('user_code') ?? '').trim();
            return (
              <Space>
                <Button onClick={() => submit(code, false)} loading={loading === 'deny'}>
                  {t('consent.deny')}
                </Button>
                {/* 去惯性:输入 user_code 后才起 3s 倒计时 + 二次确认(C7b.6),防秒批。 */}
                <ApproveButton
                  onApprove={() => submit(code, true)}
                  loading={loading === 'approve'}
                  ready={code.length > 0}
                />
              </Space>
            );
          }}
        </Form.Item>
      </Space>
    </Form>
  );
}

/** 未登录引导:批准动作须已认证会话。带 next=当前页(含 auth_req_id/user_code query),
 *  登录后回原批准页(后端 sanitize 同源相对路径,spec 003 P0.5)——CIBA 推送链接会话过期尤其需要。 */
function LoginPrompt() {
  const { t } = useTranslation();
  const next = encodeURIComponent(location.pathname + location.search);
  return (
    <Alert
      type="info"
      showIcon
      message={t('account.signin')}
      action={
        <Button type="link" href={`/login?next=${next}`}>
          {t('account.signinLink')}
        </Button>
      }
    />
  );
}
