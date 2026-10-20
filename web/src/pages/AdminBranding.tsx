import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Alert, Button, Form, Input, Radio, Select, Space, Spin, Typography, message } from 'antd';
import { I18nextProvider, useTranslation } from 'react-i18next';
import { adminApi } from '../api/admin';
import type { components } from '../api/schema';
import { defaultBranding, parseBrandingSettings, type BrandingSettings } from '../branding';
import { Login } from './Login';
import { Consent } from './Consent';

type AdminBrandingView = components['schemas']['AdminBrandingView'];

// These immutable display facts never come from a tenant, query or branding input.
const syntheticConsent: components['schemas']['ConsentContext'] = {
  client_id: 'synthetic-client', client_name: 'Synthetic application',
  client_source: 'dcr', csrf_token: 'not-an-authority-token',
  scopes: ['read', 'transfer'], resources: ['https://resource.example/mcp'],
  workload_actor: 'synthetic-workload',
  authorization_details: [
    { type: 'synthetic_restrictions', locations: ['https://resource.example/mcp'],
      resource_subset: ['synthetic-records'], max_records: 100,
      valid_from: '2030-01-01', valid_to: '2030-01-02' },
    { type: 'agent_auth_payment_v1', intent_id: 'synthetic-intent', terms_digest: 'synthetic-terms' },
  ],
  payment: {
    actor: 'synthetic-workload', amount_minor: '12345', currency: 'USD', currency_exponent: 2,
    execute_before: 1893456000, intent_id: 'synthetic-intent', order_id: 'synthetic-order',
    resource: 'https://resource.example/mcp', terms_digest: 'synthetic-terms',
    funding_source: { id: 'synthetic-funding', version: 1, label: 'Synthetic account ••1234' },
    payee: { id: 'synthetic-payee', version: 1, name: 'Synthetic Payee' },
  },
};

function validView(value: AdminBrandingView): boolean {
  return Number.isSafeInteger(value.version) && value.version >= 1 &&
    Number.isSafeInteger(value.revision) && value.revision >= 0 &&
    typeof value.can_manage === 'boolean' && parseBrandingSettings(value.settings) !== null &&
    (value.status === 'unsupported_deployment' || value.status === 'unsupported_version' ||
      (value.status === 'ready' && value.version === 1));
}

export function AdminBranding({ canManageAccess, onUnauthorized }: {
  canManageAccess: boolean; onUnauthorized: () => void;
}) {
  const { t, i18n } = useTranslation();
  const [view, setView] = useState<AdminBrandingView | null>(null);
  const [draft, setDraft] = useState<BrandingSettings>(defaultBranding);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const generation = useRef(0);
  const [previewPage, setPreviewPage] = useState<'login' | 'consent'>('login');
  const [previewWidth, setPreviewWidth] = useState<'desktop' | 'mobile'>('desktop');
  const [previewLanguage, setPreviewLanguage] = useState<'en' | 'zh'>(
    () => i18n.language.startsWith('zh') ? 'zh' : 'en',
  );
  const previewI18n = useMemo(
    () => i18n.cloneInstance({ lng: previewLanguage, initImmediate: false }),
    [i18n, previewLanguage],
  );

  const load = useCallback(async () => {
    const current = ++generation.current;
    setBusy(true);
    setView(null);
    setError(null);
    try {
      const { data, response } = await adminApi.GET('/admin/branding');
      if (current !== generation.current) return;
      if (response.status === 401) return onUnauthorized();
      if (!response.ok || !data || !validView(data)) {
        setError(t('branding.unavailable'));
        return;
      }
      setView(data);
      setDraft(data.settings);
    } catch {
      if (current === generation.current) setError(t('branding.unavailable'));
    } finally {
      if (current === generation.current) setBusy(false);
    }
  }, [onUnauthorized, t]);

  useEffect(() => {
    void load();
    return () => { generation.current += 1; };
  }, [load]);

  const settings = parseBrandingSettings(draft);
  const canManage = !!view && view.status === 'ready' && canManageAccess && view.can_manage;
  const canSave = canManage && !!settings;

  const mutate = async (reset: boolean) => {
    if (!canManage || busy || !view || (!reset && !settings)) return;
    const current = ++generation.current;
    setBusy(true);
    setError(null);
    try {
      const result = reset
        ? await adminApi.POST('/admin/branding/reset', { body: { expected_revision: view.revision } })
        : await adminApi.PUT('/admin/branding', { body: { expected_revision: view.revision, settings: settings! } });
      if (current !== generation.current) return;
      if (result.response.status === 401) {
        setView(null);
        return onUnauthorized();
      }
      const next = result.data ? { ...result.data, can_manage: view.can_manage } : null;
      if (!result.response.ok || !next || !validView(next) || next.status !== 'ready') {
        setView(null);
        setError(t(result.response.status === 409 ? 'branding.conflict' : 'branding.unavailable'));
        return;
      }
      setView(next);
      setDraft(next.settings);
      void message.success(t(reset ? 'branding.resetDone' : 'branding.saved'));
    } catch {
      // An uncertain write must be read back before another edit can be submitted.
      if (current === generation.current) {
        setView(null);
        setError(t('branding.unavailable'));
      }
    } finally {
      if (current === generation.current) setBusy(false);
    }
  };

  return (
    <Space direction="vertical" size="middle" style={{ width: '100%' }}>
      <Typography.Title level={3}>{t('branding.title')}</Typography.Title>
      <Typography.Paragraph>{t('branding.hint')}</Typography.Paragraph>
      {error && <Alert type="error" showIcon message={error} />}
      <Button onClick={() => void load()} disabled={busy}>{t('branding.reload')}</Button>
      {busy && !view && <Spin />}
      {view?.status === 'unsupported_deployment' &&
        <Alert type="info" showIcon message={t('branding.unsupportedDeployment')} />}
      {view?.status === 'unsupported_version' &&
        <Alert type="warning" showIcon message={t('branding.unsupportedVersion')} />}
      {view?.status === 'ready' && <>
        {(!canManageAccess || !view.can_manage) &&
          <Alert type="info" showIcon message={t('branding.readonly')} />}
        <Form layout="vertical">
          <Form.Item label={t('branding.name')}>
            <Input aria-label={t('branding.name')} value={draft.name ?? ''}
              placeholder={t('app.name')} disabled={busy}
              onChange={(event) => setDraft({ ...draft, name: event.target.value || null })} />
          </Form.Item>
          <Form.Item label={t('branding.logo')}>
            <Select aria-label={t('branding.logo')} value={draft.logo} disabled={busy}
              onChange={(logo: BrandingSettings['logo']) => setDraft({ ...draft, logo })}
              options={(['none', 'shield', 'key'] as const).map(
                (value) => ({ value, label: t(`branding.logo.${value}`) }),
              )} />
          </Form.Item>
          <Form.Item label={t('branding.primary')}>
            <Select aria-label={t('branding.primary')} value={draft.primary} disabled={busy}
              onChange={(primary: BrandingSettings['primary']) => setDraft({ ...draft, primary })}
              options={(['blue', 'teal', 'violet'] as const).map(
                (value) => ({ value, label: t(`branding.primary.${value}`) }),
              )} />
          </Form.Item>
          {!settings && <Alert type="error" showIcon message={t('branding.invalid')} />}
          <Space wrap>
            <Button type="primary" disabled={!canSave || busy} onClick={() => void mutate(false)}>
              {t('branding.save')}
            </Button>
            <Button disabled={!canManage || busy} onClick={() => void mutate(true)}>
              {t('branding.reset')}
            </Button>
          </Space>
        </Form>
        <Typography.Title level={4}>{t('branding.preview.title')}</Typography.Title>
        <Alert type="info" showIcon message={t('branding.preview.warning')} />
        <Space wrap>
          <Radio.Group aria-label={t('branding.preview.page')} value={previewPage}
            onChange={(event) => setPreviewPage(event.target.value)}>
            <Radio value="login">{t('branding.preview.login')}</Radio>
            <Radio value="consent">{t('branding.preview.consent')}</Radio>
          </Radio.Group>
          <Radio.Group aria-label={t('branding.preview.width')} value={previewWidth}
            onChange={(event) => setPreviewWidth(event.target.value)}>
            <Radio value="desktop">{t('branding.preview.desktop')}</Radio>
            <Radio value="mobile">{t('branding.preview.mobile')}</Radio>
          </Radio.Group>
          <Select aria-label={t('branding.preview.language')} value={previewLanguage}
            onChange={setPreviewLanguage} style={{ width: 120 }}
            options={[{ value: 'en', label: 'English' }, { value: 'zh', label: '中文' }]} />
        </Space>
        {settings && <div data-testid="branding-preview"
          style={{ width: previewWidth === 'mobile' ? 360 : 640, maxWidth: '100%' }}>
          <I18nextProvider i18n={previewI18n}>
            {previewPage === 'login' ? <Login preview={{ branding: settings }} />
              : <Consent preview={{ branding: settings, context: syntheticConsent }} />}
          </I18nextProvider>
        </div>}
      </>}
    </Space>
  );
}
