import { useEffect, useRef, useState } from 'react';
import { Alert, Button, Card, Form, Input, Select, Space, Spin, Typography } from 'antd';
import { useTranslation } from 'react-i18next';
import { adminApi } from '../api/admin';
import { api } from '../api/client';
import type { components } from '../api/schema';

type Client = components['schemas']['ClientView'];
type Overview = components['schemas']['Overview'];
type Trust = components['schemas']['WorkloadTrustView'];
type Scene = 'mcp' | 'cli' | 'workload';
type Metadata = {
  issuer: string;
  grant_types_supported: string[];
  code_challenge_methods_supported: string[];
  token_endpoint_auth_methods_supported: string[];
  introspection_endpoint?: string;
  device_authorization_endpoint?: string;
};

function metadata(value: unknown, issuer: string): Metadata | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const raw = value as Record<string, unknown>;
  if (raw.issuer !== issuer) return null;
  const strings = (key: string) => Array.isArray(raw[key]) &&
    (raw[key] as unknown[]).every((item) => typeof item === 'string')
    ? raw[key] as string[] : [];
  return {
    issuer, grant_types_supported: strings('grant_types_supported'),
    code_challenge_methods_supported: strings('code_challenge_methods_supported'),
    token_endpoint_auth_methods_supported: strings('token_endpoint_auth_methods_supported'),
    introspection_endpoint: typeof raw.introspection_endpoint === 'string' ? raw.introspection_endpoint : undefined,
    device_authorization_endpoint: typeof raw.device_authorization_endpoint === 'string' ? raw.device_authorization_endpoint : undefined,
  };
}

function loopback(value: string): boolean {
  try {
    const url = new URL(value);
    return url.protocol === 'http:' && ['127.0.0.1', '[::1]', 'localhost'].includes(url.hostname);
  } catch { return false; }
}

function validResource(value: string): boolean {
  if (!/^https:\/\/[\x21-\x7e]+$/.test(value) || /["\\]/.test(value) ||
    /\/(?:\.|%2e){1,2}(?:\/|$)/i.test(value)) return false;
  try {
    const url = new URL(value);
    return url.protocol === 'https:' && !url.username && !url.password && !url.hash && !url.search &&
      !/\.lambda-url\.[a-z0-9-]+\.on\.aws\.?$/i.test(url.hostname);
  } catch { return false; }
}

export function OnboardingTab({ onUnauthorized }: { onUnauthorized: () => void }) {
  const { t } = useTranslation();
  const unauthorized = useRef(onUnauthorized);
  const trustRevision = useRef(0);
  useEffect(() => { unauthorized.current = onUnauthorized; }, [onUnauthorized]);
  const [revision, setRevision] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [source, setSource] = useState<{ overview: Overview; clients: Client[]; discovery: Metadata } | null>(null);
  const [scene, setScene] = useState<Scene>('mcp');
  const [flow, setFlow] = useState<'pkce' | 'device'>('pkce');
  const [rsId, setRsId] = useState('');
  const [clientId, setClientId] = useState('');
  const [actorId, setActorId] = useState('');
  const [resource, setResource] = useState('');
  const [scope, setScope] = useState('read');
  const [tenant, setTenant] = useState('');
  const [trusts, setTrusts] = useState<Trust[] | null>(null);
  const [trustError, setTrustError] = useState(false);
  const [trustLoading, setTrustLoading] = useState(false);
  const [copied, setCopied] = useState(false);
  const [copyError, setCopyError] = useState(false);

  useEffect(() => {
    let active = true;
    setLoading(true); setSource(null); setError(null); setTrusts(null);
    trustRevision.current += 1;
    setTrustLoading(false); setTrustError(false);
    setRsId(''); setClientId(''); setActorId(''); setResource('');
    setCopied(false); setCopyError(false);
    void (async () => {
      try {
        const [overview, clients, discovery] = await Promise.all([
          adminApi.GET('/admin/overview'), adminApi.GET('/admin/clients'),
          api.GET('/.well-known/openid-configuration'),
        ]);
        if (!active) return;
        if ([overview, clients].some((result) => result.response.status === 401)) {
          unauthorized.current(); return;
        }
        if ([overview, clients].some((result) => result.response.status === 403)) {
          setError('admin.onboarding.forbidden'); return;
        }
        const parsed = overview.data && metadata(discovery.data, overview.data.issuer);
        if (!overview.response.ok || !clients.response.ok || !discovery.response.ok ||
          !overview.data || !Array.isArray(clients.data?.clients) || !parsed) {
          setError('admin.onboarding.failed'); return;
        }
        setSource({ overview: overview.data, clients: clients.data!.clients, discovery: parsed });
      } catch {
        if (active) setError('admin.onboarding.failed');
      } finally {
        if (active) setLoading(false);
      }
    })();
    return () => { active = false; trustRevision.current += 1; };
  }, [revision]);

  useEffect(() => {
    trustRevision.current += 1;
    setTrusts(null); setTrustError(false); setTrustLoading(false);
  }, [tenant, actorId]);
  useEffect(() => { setCopied(false); setCopyError(false); }, [resource, scope, clientId, rsId, actorId, scene, flow, tenant, trusts]);

  const rsClients = source?.clients.filter((client) => client.introspect_enabled &&
    client.token_endpoint_auth_method === 'client_secret_basic' && client.resource_ids.length) ?? [];
  const cliClients = source?.clients.filter((client) => client.client_type !== 'workload' &&
    client.token_endpoint_auth_method === 'none' && !client.require_dpop) ?? [];
  const actors = source?.clients.filter((client) => client.client_type === 'workload' && !client.require_dpop) ?? [];
  const client = cliClients.find((item) => item.client_id === clientId);
  const redirect = client?.redirect_uris.find(loopback);
  const rs = rsClients.find((item) => item.client_id === rsId);
  const discovery = source?.discovery;
  const pkce = discovery?.grant_types_supported.includes('authorization_code') &&
    discovery.code_challenge_methods_supported.includes('S256') &&
    discovery.token_endpoint_auth_methods_supported.includes('none');
  const device = discovery?.grant_types_supported.includes('urn:ietf:params:oauth:grant-type:device_code') &&
    !!discovery.device_authorization_endpoint && discovery.token_endpoint_auth_methods_supported.includes('none');
  const workload = source && ['P2', 'P3'].includes(source.overview.phase) &&
    discovery?.grant_types_supported.includes('urn:ietf:params:oauth:grant-type:token-exchange') &&
    discovery.token_endpoint_auth_methods_supported.includes('workload_oidc_jwt') &&
    !!discovery.introspection_endpoint;
  const boundTrust = trusts?.find((binding) => binding.mapped_client_id === actorId && binding.mechanism === 'oidc');
  const scopeValid = /^[\x21\x23-\x5b\x5d-\x7e]+(?: [\x21\x23-\x5b\x5d-\x7e]+)*$/.test(scope);
  const resourceValid = validResource(resource);
  const cliReady = client && (flow === 'device' ? device : pkce && redirect);
  const ready = source && resourceValid && scopeValid && (scene === 'mcp' ||
    scene === 'cli' && cliReady ||
    scene === 'workload' && pkce && client && redirect && workload &&
      actors.some((actor) => actor.client_id === actorId) && boundTrust && rs?.resource_ids.includes(resource));
  // Serialize only explicitly selected public facts. Never spread ClientView,
  // discovery or an Admin response into generated examples.
  const config = source ? JSON.stringify({
    issuer: source.overview.issuer, resource, scope,
    ...(client ? { client_id: client.client_id, redirect_uri: redirect } : {}),
    ...(scene === 'cli' ? { authorization_flow: flow } : {}),
    ...(rs ? { introspection_client_id: rs.client_id } : {}),
    ...(scene === 'workload' && actorId ? { workload_actor: actorId } : {}),
    online: scene === 'workload',
  }, null, 2) : '';

  const loadTrust = async () => {
    const selectedTenant = tenant.trim();
    const requestRevision = ++trustRevision.current;
    setTrusts(null); setTrustError(false); setTrustLoading(true);
    try {
      const result = await adminApi.GET('/admin/workload-trust/{tenant_id}', {
        params: { path: { tenant_id: selectedTenant } },
      });
      if (requestRevision !== trustRevision.current) return;
      if (result.response.status === 401) return unauthorized.current();
      if (!result.response.ok || !result.data ||
        result.data.bindings.some((binding) => binding.tenant_id !== selectedTenant)) {
        setTrustError(true);
      } else {
        setTrusts(result.data.bindings);
      }
    } catch {
      if (requestRevision === trustRevision.current) setTrustError(true);
    } finally {
      if (requestRevision === trustRevision.current) setTrustLoading(false);
    }
  };

  const options = (items: Client[]) => items.map((item) => ({ value: item.client_id, label: item.client_id }));
  return (
    <Space direction="vertical" size="middle" style={{ width: '100%' }}>
      <Typography.Paragraph>{t('admin.onboarding.boundary')}</Typography.Paragraph>
      <Button onClick={() => setRevision((value) => value + 1)} loading={loading}>{t('admin.onboarding.refresh')}</Button>
      {loading && <Spin />}
      {error && <Alert type="error" showIcon message={t(error)} />}
      {source && <>
        <Typography.Paragraph style={{ overflowWrap: 'anywhere' }}>
          {t('admin.onboarding.current', { issuer: source.overview.issuer, phase: source.overview.phase })}
        </Typography.Paragraph>
        <Form layout="vertical">
          <Form.Item label={t('admin.onboarding.scene')} htmlFor="onboarding-scene">
            <Select id="onboarding-scene" value={scene} onChange={setScene} options={[
              { value: 'mcp', label: t('admin.onboarding.mcp') },
              { value: 'cli', label: t('admin.onboarding.cli') },
              { value: 'workload', label: t('admin.onboarding.workload') },
            ]} />
          </Form.Item>
          <Form.Item label={t('admin.onboarding.rs')} htmlFor="onboarding-rs">
            <Select id="onboarding-rs" value={rsId || undefined} onChange={(id) => {
              setRsId(id || ''); setResource(rsClients.find((item) => item.client_id === id)?.resource_ids[0] ?? '');
            }} options={options(rsClients)} allowClear />
          </Form.Item>
          <Form.Item label={t('admin.onboarding.resource')} htmlFor="onboarding-resource">
            <Input id="onboarding-resource" value={resource} onChange={(event) => setResource(event.target.value)} />
          </Form.Item>
          <Form.Item label={t('admin.onboarding.scope')} htmlFor="onboarding-scope">
            <Input id="onboarding-scope" value={scope} onChange={(event) => setScope(event.target.value)} />
          </Form.Item>
          <Form.Item label={t('admin.onboarding.client')} htmlFor="onboarding-client">
            <Select id="onboarding-client" value={clientId || undefined} onChange={(id) => setClientId(id || '')}
              options={options(cliClients)} allowClear />
          </Form.Item>
          {scene === 'cli' && <Form.Item label={t('admin.onboarding.flow')} htmlFor="onboarding-flow">
            <Select id="onboarding-flow" value={flow} onChange={setFlow} options={[
              { value: 'pkce', label: 'Authorization Code + PKCE', disabled: !pkce },
              { value: 'device', label: 'Device flow', disabled: !device },
            ]} />
          </Form.Item>}
          {scene === 'workload' && <>
            <Form.Item label={t('admin.onboarding.actor')} htmlFor="onboarding-actor">
              <Select id="onboarding-actor" value={actorId || undefined} onChange={(id) => setActorId(id || '')}
                options={options(actors)} allowClear />
            </Form.Item>
            <Form.Item label={t('admin.onboarding.tenant')} htmlFor="onboarding-tenant">
              <Input id="onboarding-tenant" value={tenant} onChange={(event) => setTenant(event.target.value)} />
            </Form.Item>
            <Button disabled={!tenant.trim() || !actorId} loading={trustLoading}
              aria-label={t('admin.onboarding.trust')} aria-busy={trustLoading}
              onClick={() => void loadTrust()}>{t('admin.onboarding.trust')}</Button>
            {trustError && <Alert type="error" message={t('admin.onboarding.trustFailed')} />}
            {trusts && <Alert type={boundTrust ? 'success' : 'warning'}
              message={boundTrust ? t('admin.onboarding.trustBound', {
                issuer: boundTrust.trust_anchor, subject: boundTrust.subject_pattern,
              }) : t('admin.onboarding.trustMissing')} />}
          </>}
        </Form>
        {!ready && <Alert type="warning" showIcon message={t('admin.onboarding.incomplete')} />}
        {!pkce && (scene === 'workload' || scene === 'cli' && flow === 'pkce') &&
          <Alert type="warning" message={t('admin.onboarding.pkceUnavailable')} />}
        {scene === 'cli' && <Alert type={device ? 'info' : 'warning'}
          message={t(device ? 'admin.onboarding.deviceAvailable' : 'admin.onboarding.deviceUnavailable')} />}
        {scene === 'workload' && !workload && <Alert type="warning" message={t('admin.onboarding.workloadUnavailable')} />}
        {ready && <Card title={t('admin.onboarding.configuration')}>
          <pre data-testid="onboarding-config" style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{config}</pre>
          <Button onClick={async () => {
            setCopied(false); setCopyError(false);
            try { await navigator.clipboard.writeText(config); setCopied(true); }
            catch { setCopyError(true); }
          }}>{t('admin.onboarding.copy')}</Button>
          {copied && <Typography.Paragraph role="status">{t('admin.onboarding.copied')}</Typography.Paragraph>}
          {copyError && <Alert type="error" message={t('admin.onboarding.copyFailed')} />}
        </Card>}
        <Card title={t(`admin.onboarding.${scene}`)}>
          <Typography.Paragraph>{t(`admin.onboarding.steps.${scene}`)}</Typography.Paragraph>
          <Typography.Paragraph>{t('admin.onboarding.reject')}</Typography.Paragraph>
          <Typography.Paragraph>{t('admin.onboarding.revoke')}</Typography.Paragraph>
          <Typography.Link href="https://github.com/amliuyong/a-auth/tree/main/examples/onboarding">
            {t('admin.onboarding.examples')}
          </Typography.Link>
          <Typography.Paragraph>{t('admin.onboarding.packagePending')}</Typography.Paragraph>
          <Typography.Link href="?tab=clients">{t('admin.onboarding.manageClients')}</Typography.Link>
        </Card>
      </>}
    </Space>
  );
}
