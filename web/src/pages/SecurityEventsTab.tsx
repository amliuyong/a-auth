import { useEffect, useState } from 'react';
import {
  Alert, Button, Descriptions, Empty, Form, Input, Modal, Space, Spin, Table, Tag, Typography,
} from 'antd';
import type { TableColumnsType } from 'antd';
import { useTranslation } from 'react-i18next';
import { useSearchParams } from 'react-router-dom';
import { adminApi } from '../api/admin';
import type { components } from '../api/schema';

type StoredEvent = components['schemas']['StoredSecurityEvent'];
type EventList = components['schemas']['SecurityEventList'];
type Correlation = components['schemas']['SecurityEventCorrelation'];

// Deliberately enumerate the public, redacted correlation contract. Extra
// response fields must never become an accidental raw-request/token viewer.
const correlationFields: (keyof Correlation)[] = [
  'request_id', 'operation_id', 'authz_session_id', 'client_id', 'grant_id',
  'credential_id', 'mapping_id', 'mapping_revision', 'session_fingerprint',
  'target_namespace', 'target_key', 'upstream_idp_id', 'old_value_summary', 'new_value_summary',
];

function queryInteger(value: string | null, fallback: number): number {
  return value === null ? fallback : /^\d+$/.test(value) ? Number(value) : NaN;
}

function localDateInput(seconds: number): string {
  const date = new Date(seconds * 1000);
  if (!Number.isFinite(date.getTime())) return '';
  const pad = (value: number) => String(value).padStart(2, '0');
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

function validWindow(from: number, through: number, limit: number): boolean {
  return Number.isSafeInteger(from) && from >= 0 && Number.isSafeInteger(through) &&
    through >= from && Number.isFinite(new Date(through * 1000).getTime()) &&
    Number.isInteger(limit) && limit >= 1 && limit <= 500;
}

export function SecurityEventsTab({ onUnauthorized }: { onUnauthorized: () => void }) {
  const { t, i18n } = useTranslation();
  const [params, setParams] = useSearchParams();
  // Anchor the default window: all cursor pages must use identical bounds.
  const [defaultThrough, setDefaultThrough] = useState(() => Math.floor(Date.now() / 1000));
  const from = queryInteger(params.get('event_from'), defaultThrough - 30 * 86400);
  const through = queryInteger(params.get('event_through'), defaultThrough);
  const limit = queryInteger(params.get('event_limit'), 100);
  const valid = validWindow(from, through, limit);
  const queryKey = `${from}:${through}:${limit}`;
  const [draft, setDraft] = useState({
    from: localDateInput(from), through: localDateInput(through), limit: String(limit),
  });
  const [paging, setPaging] = useState<{
    queryKey: string; cursors: (string | undefined)[]; index: number;
  }>({ queryKey, cursors: [undefined], index: 0 });
  const page = paging.queryKey === queryKey
    ? paging : { queryKey, cursors: [undefined], index: 0 };
  const cursor = page.cursors[page.index];
  const [refreshRevision, setRefreshRevision] = useState(0);
  const [data, setData] = useState<EventList | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [formError, setFormError] = useState(false);
  const [selected, setSelected] = useState<StoredEvent | null>(null);

  useEffect(() => {
    setDraft({ from: localDateInput(from), through: localDateInput(through), limit: String(limit) });
    setFormError(false);
  }, [from, through, limit]);

  useEffect(() => {
    let cancelled = false;
    setData(null);
    setSelected(null);
    setError(null);
    setLoading(valid);
    if (!valid) return () => { cancelled = true; };

    const load = async () => {
      try {
        const result = await adminApi.GET('/admin/security-events', {
          params: { query: { from, through, limit, ...(cursor ? { cursor } : {}) } },
        });
        if (cancelled) return;
        if (result.response.status === 401) {
          onUnauthorized();
        } else if (result.response.status === 403) {
          setError(t('admin.events.forbidden'));
        } else if (result.response.status === 404) {
          setError(t('admin.events.unavailable'));
        } else if (!result.response.ok || !result.data ||
          !Array.isArray(result.data.events) ||
          result.data.events.some((row) => row.event?.tenant_id !== result.data!.tenant_id)) {
          setError(t('admin.events.failed'));
        } else {
          setData(result.data);
        }
      } catch {
        if (!cancelled) setError(t('admin.events.failed'));
      } finally {
        if (!cancelled) setLoading(false);
      }
    };
    void load();
    return () => { cancelled = true; };
  }, [from, through, limit, cursor, refreshRevision, valid, onUnauthorized, t]);

  const apply = () => {
    const nextFrom = Date.parse(draft.from) / 1000;
    const nextThrough = Date.parse(draft.through) / 1000;
    const nextLimit = queryInteger(draft.limit, 100);
    if (!validWindow(nextFrom, nextThrough, nextLimit)) {
      setFormError(true);
      return;
    }
    const next = new URLSearchParams(params);
    next.set('event_from', String(nextFrom));
    next.set('event_through', String(nextThrough));
    next.set('event_limit', String(nextLimit));
    setParams(next);
    setPaging({ queryKey: `${nextFrom}:${nextThrough}:${nextLimit}`, cursors: [undefined], index: 0 });
    setFormError(false);
    setRefreshRevision((revision) => revision + 1);
  };

  const timestamp = (seconds: number | null | undefined) => {
    if (seconds == null || !Number.isFinite(new Date(seconds * 1000).getTime())) return '—';
    return new Intl.DateTimeFormat(i18n.language.startsWith('zh') ? 'zh-CN' : 'en-US', {
      dateStyle: 'medium', timeStyle: 'medium',
    }).format(new Date(seconds * 1000));
  };
  const text = (value: string | number | null | undefined) => (
    <Typography.Text code style={{ overflowWrap: 'anywhere' }}>{value ?? '—'}</Typography.Text>
  );
  const outcome = (value: StoredEvent['event']['outcome']) => (
    <Tag color={value === 'success' ? 'green' : value === 'denied' ? 'orange' : 'red'}>
      {t(`admin.events.outcome.${value}`, value)}
    </Tag>
  );
  const delivery = (value: StoredEvent['delivery']['status']) => (
    <Tag color={['failed', 'dead_lettered'].includes(value) ? 'red' : value === 'archived' ? 'green' : 'default'}>
      {t(`admin.events.delivery.${value}`, value)}
    </Tag>
  );
  const columns: TableColumnsType<StoredEvent> = [
    { title: t('admin.events.time'), width: 185, render: (_, row) => timestamp(row.event.occurred_at) },
    { title: t('admin.events.actor'), width: 180, render: (_, row) => (
      <div>{text(row.event.actor.id)}<br />{row.event.actor.kind}</div>
    ) },
    { title: t('admin.events.subject'), width: 180, render: (_, row) => (
      <div>{text(row.event.subject.id)}<br />{row.event.subject.kind}</div>
    ) },
    { title: t('admin.events.action'), width: 155, render: (_, row) => text(row.event.action) },
    { title: t('admin.events.outcome'), width: 125, render: (_, row) => outcome(row.event.outcome) },
    { title: t('admin.events.delivery'), width: 180, render: (_, row) => delivery(row.delivery.status) },
    { title: t('admin.events.details'), width: 95, render: (_, row) => (
      <Button size="small" onClick={() => setSelected(row)}>{t('admin.events.details')}</Button>
    ) },
  ];

  return (
    <div>
      <Typography.Paragraph type="secondary">{t('admin.events.boundary')}</Typography.Paragraph>
      <Form layout="vertical" onFinish={apply}>
        <Space align="start" wrap>
          <Form.Item label={t('admin.events.from')} htmlFor="security-event-from">
            <Input id="security-event-from" type="datetime-local" value={draft.from}
              onChange={(e) => setDraft({ ...draft, from: e.target.value })} />
          </Form.Item>
          <Form.Item label={t('admin.events.through')} htmlFor="security-event-through">
            <Input id="security-event-through" type="datetime-local" value={draft.through}
              onChange={(e) => setDraft({ ...draft, through: e.target.value })} />
          </Form.Item>
          <Form.Item label={t('admin.events.limit')} htmlFor="security-event-limit">
            <Input id="security-event-limit" inputMode="numeric" style={{ width: 100 }} value={draft.limit}
              onChange={(e) => setDraft({ ...draft, limit: e.target.value })} />
          </Form.Item>
          <Form.Item label=" ">
            <Button type="primary" htmlType="submit">{t('admin.events.apply')}</Button>
          </Form.Item>
        </Space>
      </Form>
      <Typography.Paragraph type="secondary">{t('admin.events.localTime')}</Typography.Paragraph>
      {(!valid || formError) && <Alert type="error" showIcon message={t('admin.events.invalid')} />}
      {error && <Alert type="error" showIcon message={error} />}
      <Space wrap style={{ margin: '16px 0' }}>
        <Button onClick={() => {
          if (!params.has('event_from') && !params.has('event_through')) {
            setDefaultThrough(Math.floor(Date.now() / 1000));
          }
          setPaging({ queryKey, cursors: [undefined], index: 0 });
          setRefreshRevision((revision) => revision + 1);
        }}>{t('admin.events.refresh')}</Button>
        <Button disabled={loading || page.index === 0} onClick={() => {
          setPaging({ ...page, index: page.index - 1 });
        }}>{t('admin.events.previous')}</Button>
        <Button disabled={loading || !data?.next_cursor} onClick={() => {
          setPaging({
            queryKey, cursors: [...page.cursors.slice(0, page.index + 1), data!.next_cursor!],
            index: page.index + 1,
          });
        }}>{t('admin.events.next')}</Button>
        {data && <Typography.Text>{t('admin.events.page', {
          page: page.index + 1, count: data.events.length, tenant: data.tenant_id,
        })}</Typography.Text>}
      </Space>
      {data && <Typography.Paragraph type="secondary">{t('admin.events.window', {
        from: timestamp(data.from), through: timestamp(data.through), days: data.hot_retention_days,
      })}</Typography.Paragraph>}
      {loading ? (
        <Space><Spin size="small" /><Typography.Text>{t('admin.events.loading')}</Typography.Text></Space>
      ) : data?.events.length === 0 ? (
        <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={t('admin.events.empty')} />
      ) : data ? (
        <Table rowKey={(row) => row.event.event_id} dataSource={data.events}
          columns={columns} pagination={false} scroll={{ x: 1200 }} />
      ) : null}
      <Modal title={t('admin.events.details')} open={selected !== null}
        onCancel={() => setSelected(null)} footer={null} width={720}>
        {selected && <>
          <Typography.Title level={5}>{t('admin.events.fact')}</Typography.Title>
          <Descriptions column={1} size="small" bordered items={[
            { key: 'id', label: t('admin.events.id'), children: text(selected.event.event_id) },
            { key: 'tenant', label: t('admin.events.tenant'), children: text(selected.event.tenant_id) },
            { key: 'time', label: t('admin.events.time'), children: timestamp(selected.event.occurred_at) },
            { key: 'actor', label: t('admin.events.actor'), children: <>{text(selected.event.actor.id)} ({selected.event.actor.kind})</> },
            { key: 'subject', label: t('admin.events.subject'), children: <>{text(selected.event.subject.id)} ({selected.event.subject.kind})</> },
            { key: 'action', label: t('admin.events.action'), children: text(selected.event.action) },
            { key: 'category', label: t('admin.events.category'), children: text(selected.event.category) },
            { key: 'outcome', label: t('admin.events.outcome'), children: outcome(selected.event.outcome) },
            ...correlationFields.filter((field) => selected.event.correlation[field] != null).map((field) => ({
              key: field, label: t(`admin.events.correlation.${field}`),
              children: text(selected.event.correlation[field]),
            })),
          ]} />
          <Typography.Title level={5}>{t('admin.events.delivery')}</Typography.Title>
          <Descriptions column={1} size="small" bordered items={[
            { key: 'status', label: t('admin.events.delivery'), children: delivery(selected.delivery.status) },
            { key: 'attempts', label: t('admin.events.attempts'), children: selected.delivery.attempts },
            { key: 'last', label: t('admin.events.lastAttempt'), children: timestamp(selected.delivery.last_attempt_at) },
            { key: 'archived', label: t('admin.events.archivedAt'), children: timestamp(selected.delivery.archived_at) },
            { key: 'dead', label: t('admin.events.deadLetteredAt'), children: timestamp(selected.delivery.dead_lettered_at) },
          ]} />
          {selected.delivery.history.map((attempt, index) => (
            <div key={index} style={{ marginTop: 8 }}>
              {timestamp(attempt.occurred_at)} {delivery(attempt.status)}
            </div>
          ))}
        </>}
      </Modal>
    </div>
  );
}
