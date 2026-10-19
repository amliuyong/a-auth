import { useCallback, useEffect, useRef, useState } from 'react';
import { Alert, Button, Card, Descriptions, List, Space, Spin, Tag, Typography } from 'antd';
import { useTranslation } from 'react-i18next';
import { useLocation } from 'react-router-dom';
import { Layout } from '../Layout';
import type { components } from '../api/schema';
import { api } from '../api/client';
import { consentContextQuery } from '../consentQuery';
import { formatMinorUnits } from '../paymentAmount';

type ConsentContext = components['schemas']['ConsentContext'];
type PaymentConsentView = components['schemas']['PaymentConsentView'];
type RarEntry = {
  type?: string;
  locations?: string[];
  valid_from?: string | number;
  valid_to?: string | number;
  resource_subset?: string[];
  max_records?: number;
};

/** RFC 9396 type of the single-transaction payment authorization (rendered by its own card). */
const PAYMENT_RAR_TYPE = 'agent_auth_payment_v1';
/** Largest Unix-seconds instant a JS Date can represent. */
const MAX_DATE_SECONDS = 8_640_000_000_000;

type PaymentDisplay = {
  amount: string;
  fundingSource: string;
  payee: string;
  orderId: string;
  actor: string;
  deadline: Date;
  intentId: string;
};

function isNonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0;
}

function isPaymentDetail(value: unknown): value is Record<string, unknown> {
  return (
    typeof value === 'object' &&
    value !== null &&
    !Array.isArray(value) &&
    (value as Record<string, unknown>).type === PAYMENT_RAR_TYPE
  );
}

/**
 * Display model of the server-validated payment terms, or `null` when the view is malformed
 * or inconsistent with the rest of the context. A `null` result keeps approval disabled
 * (fail closed): the page never shows a guessed amount, payee or funding source.
 */
function paymentDisplay(
  payment: PaymentConsentView,
  workloadActor: string | null | undefined,
  details: unknown[],
): PaymentDisplay | null {
  if (typeof payment !== 'object' || payment === null) return null;
  const amount = formatMinorUnits(payment.amount_minor, payment.currency_exponent);
  if (amount === null) return null;
  if (typeof payment.currency !== 'string' || !/^[A-Z]{3}$/.test(payment.currency)) return null;
  if (
    !Number.isSafeInteger(payment.execute_before) ||
    payment.execute_before <= 0 ||
    payment.execute_before > MAX_DATE_SECONDS
  ) {
    return null;
  }
  const fundingSource = payment.funding_source?.label;
  const payee = payment.payee?.name;
  if (
    ![
      payment.terms_digest,
      payment.intent_id,
      payment.order_id,
      payment.actor,
      fundingSource,
      payee,
    ].every(isNonEmptyString)
  ) {
    return null;
  }
  // The payment may only be executed by the delegated workload this consent names.
  if (payment.actor !== workloadActor) return null;
  // Every canonical payment detail must describe this exact intent and terms.
  const consistent = details
    .filter(isPaymentDetail)
    .every(
      (entry) =>
        entry.intent_id === payment.intent_id && entry.terms_digest === payment.terms_digest,
    );
  if (!consistent) return null;
  return {
    amount: `${amount} ${payment.currency}`,
    fundingSource,
    payee,
    orderId: payment.order_id,
    actor: payment.actor,
    deadline: new Date(payment.execute_before * 1000),
    intentId: payment.intent_id,
  };
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((item) => typeof item === 'string');
}

function isRarEntry(value: unknown): value is RarEntry {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const entry = value as Record<string, unknown>;
  return (
    (entry.type === undefined || typeof entry.type === 'string') &&
    (entry.locations === undefined || isStringArray(entry.locations)) &&
    (entry.valid_from === undefined ||
      typeof entry.valid_from === 'string' ||
      typeof entry.valid_from === 'number') &&
    (entry.valid_to === undefined ||
      typeof entry.valid_to === 'string' ||
      typeof entry.valid_to === 'number') &&
    (entry.resource_subset === undefined || isStringArray(entry.resource_subset)) &&
    (entry.max_records === undefined || typeof entry.max_records === 'number')
  );
}

/**
 * consent 同意页(C10.9 anti-CSRF)。path = /consent,可 bookmark(带 authorize query)。
 * 展示 client 请求的 scope/resource,用户批准 → 后端签发 code 回跳 redirect_uri。
 *
 * 后端 consent 批准 API = `POST /consent/decision`(校验 anti-CSRF token);page path `/consent` 与
 * 动作 path 分离,避免 CloudFront 统一入口按 path 选 origin 时冲突(spec 025)。
 * 展示上下文与 anti-CSRF token 由后端 `GET /consent/context` 下发(consent 走 cookie 会话)。
 */
export function Consent() {
  const { t, i18n } = useTranslation();
  const { search } = useLocation();
  const authorizeQuery = search.startsWith('?') ? search.slice(1) : search;
  const [loadedContext, setLoadedContext] = useState<{
    authorizeQuery: string;
    data: ConsentContext;
  } | null>(null);
  const [loading, setLoading] = useState<'approve' | 'deny' | null>(null);
  const [error, setError] = useState<string | null>(null);
  const loginRedirected = useRef(false);
  const context =
    loadedContext?.authorizeQuery === authorizeQuery ? loadedContext.data : null;
  const redirectToLogin = useCallback(() => {
    if (loginRedirected.current) return;
    loginRedirected.current = true;
    window.location.assign(authorizeQuery ? `/login?${authorizeQuery}` : '/login');
  }, [authorizeQuery]);

  useEffect(() => {
    let cancelled = false;
    setLoadedContext(null);
    setError(null);

    const load = async () => {
      const query = consentContextQuery(authorizeQuery);
      if (!query) {
        setError(t('error.generic'));
        return;
      }
      try {
        const { data, response } = await api.GET('/consent/context', {
          params: {
            query,
          },
          querySerializer: () => authorizeQuery,
        });
        if (response.status === 401) {
          if (!cancelled) redirectToLogin();
          return;
        }
        if (!response.ok) {
          if (!cancelled) setError(t('error.generic'));
          return;
        }
        if (!cancelled && data) setLoadedContext({ authorizeQuery, data });
      } catch (e) {
        if (!cancelled) {
          setError(e instanceof TypeError ? t('error.network') : t('error.generic'));
        }
      }
    };

    void load();
    return () => {
      cancelled = true;
    };
  }, [authorizeQuery, redirectToLogin, t]);

  const client = context
    ? context.client_source === 'cimd' && context.client_id_host
      ? `${context.client_name} (${context.client_id_host})`
      : context.client_name || context.client_id
    : t('consent.unknownClient');
  const redirectHost = context?.redirect_uri_host ?? null;
  const redirectIsLoopback =
    redirectHost === 'localhost' ||
    redirectHost === '::1' ||
    redirectHost === '[::1]' ||
    redirectHost?.startsWith('127.');
  const scopes = context?.scopes ?? [];
  const resources =
    context?.resources && context.resources.length > 0
      ? context.resources
      : context?.resource
        ? [context.resource]
        : [];
  // RFC 9396 authorization_details(RAR;spec 010 §4 / DESIGN §721):仅渲染后端已做准入
  // 校验的结构化约束，不再信任浏览器 query 中未经验证的 RAR。
  // Payment-typed entries are shown only by the dedicated payment card below.
  const details = context?.authorization_details ?? [];
  const rar = details.filter((entry) => !isPaymentDetail(entry)).filter(isRarEntry);
  // Single-transaction payment authorization (issue #77): every displayed value comes from the
  // server-validated `payment` view, never from the browser query.
  const payment = context?.payment ?? null;
  const paymentView =
    payment !== null ? paymentDisplay(payment, context?.workload_actor, details) : null;
  // A malformed payment view, or a payment-typed detail without one, cannot be approved.
  const paymentBlocked =
    context !== null &&
    (payment !== null ? paymentView === null : details.some(isPaymentDetail));
  // The server binds the CSRF token to the displayed terms digest, so both decisions of a payment
  // authorization echo it; any other authorization keeps the body without this key.
  const paymentTermsDigest =
    payment !== null && isNonEmptyString(payment.terms_digest) ? payment.terms_digest : undefined;
  const fmtDeadline = (deadline: Date): string =>
    new Intl.DateTimeFormat(i18n.resolvedLanguage ?? i18n.language, {
      dateStyle: 'full',
      timeStyle: 'long',
    }).format(deadline);
  const fmtInstant = (v: string | number | undefined): string | null => {
    if (v === undefined) return null;
    if (typeof v === 'number') return new Date(v * 1000).toISOString();
    return v;
  };
  const csrf = context?.csrf_token ?? '';

  const submit = async (decision: 'approve' | 'deny') => {
    if (!context) return;
    if (decision === 'approve' && paymentBlocked) return;
    setLoading(decision);
    setError(null);
    try {
      const { data, response } = await api.POST('/consent/decision', {
        body: {
          decision, csrf, authorize_query: authorizeQuery,
          workload_actor: context.workload_actor,
          ...(paymentTermsDigest === undefined
            ? {}
            : { payment_terms_digest: paymentTermsDigest }),
        },
      });
      if (response.status === 401) {
        redirectToLogin();
        return;
      }
      if (response.ok) {
        // 后端返回回跳 URL(带 code + iss + state)。
        if (data?.redirect) {
          window.location.assign(data.redirect);
          return;
        }
      }
      setError(t('error.generic'));
    } catch (e) {
      setError(e instanceof TypeError ? t('error.network') : t('error.generic'));
    } finally {
      setLoading(null);
    }
  };

  return (
    <Layout>
      <Typography.Title level={3}>{t('consent.title')}</Typography.Title>
      <Typography.Paragraph type="secondary">
        {t('consent.subtitle', { client })}
      </Typography.Paragraph>
      {/* C4/002 4.2:P0 无 client 认证/软件声明(software_statement)——所有 DCR 注册的 client 均为
          "未验证",consent 页 SHOULD 明示,提醒用户此应用身份未经背书(降低钓鱼授权风险)。 */}
      <Alert
        type="warning"
        showIcon
        message={t('consent.unverified')}
        style={{ marginBottom: 16 }}
      />
      {context?.client_source === 'cimd' && redirectHost && (
        <Alert
          type={redirectIsLoopback ? 'warning' : 'info'}
          showIcon
          message={t(
            redirectIsLoopback ? 'consent.redirectHostLoopback' : 'consent.redirectHost',
            { host: redirectHost },
          )}
          style={{ marginBottom: 16 }}
        />
      )}
      {error && <Alert type="error" showIcon message={error} style={{ marginBottom: 16 }} />}

      {!context ? (
        !error && (
          <div style={{ textAlign: 'center', padding: 32 }}>
            <Spin />
          </div>
        )
      ) : (
        <>
          <Typography.Text strong>{t('consent.scopes')}</Typography.Text>
          <List
            size="small"
            dataSource={scopes}
            renderItem={(s) => (
              <List.Item>
                <Tag color="blue">{s}</Tag>
              </List.Item>
            )}
            style={{ marginBottom: 12 }}
          />
          {resources.length > 0 && (
            <Typography.Paragraph>
              <Typography.Text strong>{t('consent.resources')}: </Typography.Text>
              <Space size={[4, 4]} wrap>
                {resources.map((resource) => (
                  <Typography.Text code key={resource}>
                    {resource}
                  </Typography.Text>
                ))}
              </Space>
            </Typography.Paragraph>
          )}
          {context.workload_actor && (
            <Alert
              type="info"
              showIcon
              message={t('consent.workloadActor')}
              description={
                <>
                  <Typography.Text code>{context.workload_actor}</Typography.Text>
                  <Typography.Paragraph>{t('consent.workloadActorLimit')}</Typography.Paragraph>
                </>
              }
              style={{ marginBottom: 12 }}
            />
          )}
          {paymentView && (
            <Card
              id="agent-auth-consent-payment"
              size="small"
              title={t('consent.payment.title')}
              style={{ marginBottom: 12, borderColor: '#faad14' }}
            >
              <Alert
                type="warning"
                showIcon
                message={t('consent.payment.onlyThisPayment')}
                style={{ marginBottom: 12 }}
              />
              <Descriptions size="small" column={1} bordered>
                <Descriptions.Item label={t('consent.payment.amount')}>
                  <Typography.Text strong style={{ fontSize: 18 }}>
                    {paymentView.amount}
                  </Typography.Text>
                </Descriptions.Item>
                <Descriptions.Item label={t('consent.payment.payee')}>
                  {paymentView.payee}
                </Descriptions.Item>
                <Descriptions.Item label={t('consent.payment.fundingSource')}>
                  {paymentView.fundingSource}
                </Descriptions.Item>
                <Descriptions.Item label={t('consent.payment.order')}>
                  <Typography.Text code>{paymentView.orderId}</Typography.Text>
                </Descriptions.Item>
                <Descriptions.Item label={t('consent.payment.actor')}>
                  <Typography.Text code>{paymentView.actor}</Typography.Text>
                </Descriptions.Item>
                <Descriptions.Item label={t('consent.payment.deadline')}>
                  <time dateTime={paymentView.deadline.toISOString()}>
                    {fmtDeadline(paymentView.deadline)}
                  </time>
                </Descriptions.Item>
              </Descriptions>
              <Typography.Paragraph
                type="secondary"
                style={{ marginTop: 8, marginBottom: 0, fontSize: 12 }}
              >
                {t('consent.payment.intent')}:{' '}
                <Typography.Text type="secondary" code style={{ fontSize: 12 }}>
                  {paymentView.intentId}
                </Typography.Text>
              </Typography.Paragraph>
            </Card>
          )}
          {paymentBlocked && (
            <Alert
              id="agent-auth-consent-payment-invalid"
              type="error"
              showIcon
              message={t('consent.payment.invalid')}
              style={{ marginBottom: 12 }}
            />
          )}
        </>
      )}

      {/* RAR 细粒度约束(DESIGN §721):用户同意前看清"只能读 2026 年文档/最多 N 条"等约束。 */}
      {rar.length > 0 && (
        <Card size="small" title={t('consent.rar')} style={{ marginBottom: 12 }}>
          {rar.map((entry, i) => {
            const from = fmtInstant(entry.valid_from);
            const to = fmtInstant(entry.valid_to);
            return (
              <Descriptions
                key={i}
                size="small"
                column={1}
                bordered
                style={{ marginBottom: i < rar.length - 1 ? 8 : 0 }}
              >
                {entry.locations && entry.locations.length > 0 && (
                  <Descriptions.Item label={t('consent.rar.locations')}>
                    {entry.locations.map((l) => (
                      <Tag key={l} color="geekblue">
                        {l}
                      </Tag>
                    ))}
                  </Descriptions.Item>
                )}
                {from && (
                  <Descriptions.Item label={t('consent.rar.validFrom')}>
                    <Typography.Text code>{from}</Typography.Text>
                  </Descriptions.Item>
                )}
                {to && (
                  <Descriptions.Item label={t('consent.rar.validTo')}>
                    <Typography.Text code>{to}</Typography.Text>
                  </Descriptions.Item>
                )}
                {entry.resource_subset && entry.resource_subset.length > 0 && (
                  <Descriptions.Item label={t('consent.rar.resourceSubset')}>
                    {entry.resource_subset.map((r) => (
                      <Tag key={r}>{r}</Tag>
                    ))}
                  </Descriptions.Item>
                )}
                {entry.max_records !== undefined && (
                  <Descriptions.Item label={t('consent.rar.maxRecords')}>
                    {entry.max_records}
                  </Descriptions.Item>
                )}
              </Descriptions>
            );
          })}
        </Card>
      )}

      {context && <span id="agent-auth-consent-ready" hidden aria-hidden="true" />}
      <Space style={{ width: '100%', justifyContent: 'flex-end', marginTop: 8 }}>
        <Button
          id="agent-auth-consent-deny"
          onClick={() => submit('deny')}
          loading={loading === 'deny'}
          disabled={!context}
        >
          {t('consent.deny')}
        </Button>
        <Button
          id="agent-auth-consent-approve"
          type="primary"
          onClick={() => submit('approve')}
          loading={loading === 'approve'}
          disabled={!context || paymentBlocked}
        >
          {loading === 'approve' ? t('consent.approving') : t('consent.approve')}
        </Button>
      </Space>
    </Layout>
  );
}
