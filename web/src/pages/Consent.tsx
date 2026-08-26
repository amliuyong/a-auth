import { useCallback, useEffect, useRef, useState } from 'react';
import { Alert, Button, Card, Descriptions, List, Space, Spin, Tag, Typography } from 'antd';
import { useTranslation } from 'react-i18next';
import { useLocation } from 'react-router-dom';
import { Layout } from '../Layout';
import type { components } from '../api/schema';
import { api } from '../api/client';
import { consentContextQuery } from '../consentQuery';

type ConsentContext = components['schemas']['ConsentContext'];
type RarEntry = {
  type?: string;
  locations?: string[];
  valid_from?: string | number;
  valid_to?: string | number;
  resource_subset?: string[];
  max_records?: number;
};

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
  const { t } = useTranslation();
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
  const rar = (context?.authorization_details ?? []).filter(isRarEntry);
  const fmtInstant = (v: string | number | undefined): string | null => {
    if (v === undefined) return null;
    if (typeof v === 'number') return new Date(v * 1000).toISOString();
    return v;
  };
  const csrf = context?.csrf_token ?? '';

  const submit = async (decision: 'approve' | 'deny') => {
    if (!context) return;
    setLoading(decision);
    setError(null);
    try {
      const { data, response } = await api.POST('/consent/decision', {
        body: { decision, csrf, authorize_query: authorizeQuery },
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
          disabled={!context}
        >
          {loading === 'approve' ? t('consent.approving') : t('consent.approve')}
        </Button>
      </Space>
    </Layout>
  );
}
