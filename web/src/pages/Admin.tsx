import {
  useCallback,
  useEffect,
  useRef,
  useState,
  type HTMLAttributes,
  type PointerEvent as ReactPointerEvent,
} from 'react';
import {
  Alert,
  AutoComplete,
  Button,
  Descriptions,
  Divider,
  Form,
  Grid,
  Input,
  InputNumber,
  Layout as AntLayout,
  Modal,
  Popconfirm,
  Segmented,
  Select,
  Space,
  Spin,
  Statistic,
  Switch,
  Table,
  Tabs,
  Tag,
  Typography,
  message,
} from 'antd';
import type { TableColumnsType } from 'antd';
import type { TFunction } from 'i18next';
import { useTranslation } from 'react-i18next';
import { useBlocker, useSearchParams } from 'react-router-dom';
import { setLang } from '../i18n';
import {
  adminApi,
  adminSessionApi,
  clearAdminToken,
  getAdminToken,
  setAdminToken,
} from '../api/admin';
import {
  AdminProbeError,
  classifyControlProbe,
  classifyTenantProbe,
  type AdminMode,
} from '../adminProbe';
import type { components } from '../api/schema';
import { passwordRule } from '../passwordPolicy';

const { Header, Content, Footer } = AntLayout;

type ClientView = components['schemas']['ClientView'];
type RegisteredClientJwks = components['schemas']['RegisteredClientJwks'];
type Overview = components['schemas']['Overview'];
type MessageView = components['schemas']['MessageView'];
type FederationIdpView = components['schemas']['FederationIdpView'];
type UserView = components['schemas']['UserView'];
type UserDetail = components['schemas']['UserDetail'];
type InvitationSecretResponse = components['schemas']['InvitationSecretResponse'];
type ControlTenants = components['schemas']['ControlTenants'];
type ControlTenantView = components['schemas']['ControlTenantView'];
type CredentialSetView = components['schemas']['CredentialSetView'];
type CredentialView = components['schemas']['CredentialView'];
type InitialAccessTokenView = components['schemas']['InitialAccessTokenView'];
type AdminSessionView = components['schemas']['AdminSessionView'];
type AdminOidcConfigView = components['schemas']['AdminOidcConfigView'];
type NamespaceRegistrationView = components['schemas']['NamespaceRegistrationView'];
type UserStatusFilter = components['schemas']['ListUsersStatus'];
type FederationAttributeMappingList =
  components['schemas']['FederationAttributeMappingList'];
type FederationAttributeMappingView =
  components['schemas']['FederationAttributeMappingView'];
type ClientCredentialKind = 'client-secret' | 'registration-token';
type CredentialSlotRow = { role: 'current' | 'next'; credential: CredentialView };
type AdminAccessType = 'token' | 'session';
type ClientColumnKey =
  | 'client_id'
  | 'auth'
  | 'redirects'
  | 'resource'
  | 'introspect'
  | 'last_used_at'
  | 'actions';

const CLIENT_COLUMN_DEFAULT_WIDTHS: Record<ClientColumnKey, number> = {
  client_id: 240,
  auth: 150,
  redirects: 340,
  resource: 210,
  introspect: 100,
  last_used_at: 180,
  actions: 250,
};

const CLIENT_COLUMN_MIN_WIDTHS: Record<ClientColumnKey, number> = {
  client_id: 140,
  auth: 110,
  redirects: 180,
  resource: 140,
  introspect: 90,
  last_used_at: 140,
  actions: 210,
};

type ResizableHeaderCellProps = Omit<HTMLAttributes<HTMLTableCellElement>, 'onResize'> & {
  width?: number;
  minWidth?: number;
  resizeLabel?: string;
  onColumnResize?: (width: number) => void;
};

function ResizableHeaderCell({
  width,
  minWidth = 80,
  resizeLabel,
  onColumnResize,
  style,
  children,
  ...rest
}: ResizableHeaderCellProps) {
  const onPointerDown = (event: ReactPointerEvent<HTMLSpanElement>) => {
    if (width == null || !onColumnResize) return;
    event.preventDefault();
    event.stopPropagation();

    const startX = event.clientX;
    const startWidth = width;
    const previousCursor = document.body.style.cursor;
    const previousUserSelect = document.body.style.userSelect;
    document.body.style.cursor = 'col-resize';
    document.body.style.userSelect = 'none';

    const onPointerMove = (moveEvent: PointerEvent) => {
      onColumnResize(Math.max(minWidth, Math.round(startWidth + moveEvent.clientX - startX)));
    };
    const finishResize = () => {
      window.removeEventListener('pointermove', onPointerMove);
      window.removeEventListener('pointerup', finishResize);
      window.removeEventListener('pointercancel', finishResize);
      document.body.style.cursor = previousCursor;
      document.body.style.userSelect = previousUserSelect;
    };

    window.addEventListener('pointermove', onPointerMove);
    window.addEventListener('pointerup', finishResize);
    window.addEventListener('pointercancel', finishResize);
  };

  return (
    <th {...rest} style={{ ...style, width, position: 'relative' }}>
      {children}
      {onColumnResize && width != null && (
        <span
          role="separator"
          aria-label={resizeLabel}
          aria-orientation="vertical"
          aria-valuenow={Math.round(width)}
          data-client-column-resizer
          onPointerDown={onPointerDown}
          style={{
            position: 'absolute',
            top: 0,
            right: -4,
            zIndex: 1,
            width: 8,
            height: '100%',
            cursor: 'col-resize',
            touchAction: 'none',
            borderRight: '2px solid #d9d9d9',
          }}
        />
      )}
    </th>
  );
}

function userStatusFilterFromParam(value: string | null): UserStatusFilter {
  switch (value) {
    case 'active':
    case 'disabled':
    case 'tombstoned':
    case 'all':
      return value;
    default:
      return 'non_deleted';
  }
}

function formatUtcDay(seconds: number): string {
  const date = new Date(seconds * 1000).toLocaleDateString(undefined, { timeZone: 'UTC' });
  return `${date} UTC`;
}

function formatUtcTimestamp(seconds: number): string {
  const timestamp = new Date(seconds * 1000).toLocaleString(undefined, { timeZone: 'UTC' });
  return `${timestamp} UTC`;
}

function isLocalEmailUser(user: UserView): boolean {
  return !!user.email
    && user.user_id.startsWith('user:')
    && !user.user_id.startsWith('user:fed:');
}

function adminProbeErrorMessage(t: TFunction, error: unknown): string {
  return error instanceof AdminProbeError
    ? t('admin.token.unavailable', { status: error.status })
    : t('admin.token.networkError');
}

async function detectAdminMode(): Promise<AdminMode | null> {
  const tenant = await adminApi.GET('/admin/overview');
  const tenantResult = classifyTenantProbe(tenant.response.status);
  if (tenantResult === 'tenant') return tenantResult;

  const control = await adminApi.GET('/admin/control/tenants');
  return classifyControlProbe(control.response.status);
}

/**
 * Admin 控制台(spec 025):仪表盘(overview)+ client 管理(CRUD)。path = /admin,可 bookmark。
 *
 * Daily access uses an HttpOnly, tenant-bound OIDC Admin session. A bearer in
 * sessionStorage remains available only for bootstrap and break-glass access.
 * 端点/请求/响应类型由生成的 OpenAPI 契约约束(npm run gen:api)。
 */
export function Admin() {
  const { t } = useTranslation();
  const [accessType, setAccessType] = useState<AdminAccessType | null>(null);
  const [sessionInfo, setSessionInfo] = useState<AdminSessionView | null>(null);
  const [mode, setMode] = useState<AdminMode | null>(null);
  const [checking, setChecking] = useState(true);
  const [probeError, setProbeError] = useState<string | null>(null);

  useEffect(() => {
    if (mode) return;
    let active = true;
    setChecking(true);
    const token = getAdminToken();
    const probe = async () => {
      try {
        const { data, response } = await adminSessionApi.GET('/admin/session');
        if (response.ok && data?.auth_type === 'oidc_session') {
          return { detected: 'tenant' as const, session: data, tokenInvalid: false };
        }
        if (response.status !== 401) throw new AdminProbeError(response.status);
      } catch (error) {
        // A valid break-glass credential must remain usable while the OIDC
        // session store is unavailable.
        if (!token) throw error;
      }
      if (!token) return { detected: null, session: null, tokenInvalid: false };
      const detected = await detectAdminMode();
      return { detected, session: null, tokenInvalid: !detected };
    };
    void probe()
      .then((result) => {
        if (!active) return;
        if (result.detected) {
          setProbeError(null);
          setSessionInfo(result.session);
          if (result.session) {
            clearAdminToken();
            setAccessType('session');
          } else {
            setAccessType('token');
          }
          setMode(result.detected);
        } else if (result.tokenInvalid) {
          clearAdminToken();
          setProbeError(t('admin.token.invalid'));
          setAccessType(null);
        }
      })
      .catch((e) => {
        if (!active) return;
        if (token) {
          clearAdminToken();
          setProbeError(adminProbeErrorMessage(t, e));
          setAccessType(null);
        } else {
          setProbeError(adminProbeErrorMessage(t, e));
        }
      })
      .finally(() => {
        if (active) setChecking(false);
      });
    return () => { active = false; };
  }, [mode, t]);

  if (checking || (accessType && !mode)) {
    return <AdminShell><div style={{ display: 'grid', placeItems: 'center', minHeight: 320 }}><Spin /></div></AdminShell>;
  }
  if (!accessType) {
    return (
      <AdminShell>
        <TokenGate initialError={probeError} onConnected={(connectedMode) => {
          setProbeError(null);
          setMode(connectedMode);
          setAccessType('token');
        }} />
      </AdminShell>
    );
  }

  const disconnect = async () => {
    if (accessType === 'session') {
      try {
        const { response } = await adminApi.POST('/admin/logout');
        if (!response.ok) {
          message.error(t('admin.sso.logoutFailed'));
          return;
        }
      } catch {
        message.error(t('admin.sso.logoutFailed'));
        return;
      }
    }
    clearAdminToken();
    setSessionInfo(null);
    setMode(null);
    setAccessType(null);
  };
  const canManageAccess = accessType === 'token' || sessionInfo?.role === 'owner';
  return (
    <AdminShell onSignout={disconnect}>
      {mode === 'control'
        ? <ControlConsole onUnauthorized={disconnect} />
        : sessionInfo?.role === 'member'
          ? <Alert type="warning" showIcon message={t('admin.sso.memberDenied')} />
          : (
            <AdminConsole
              onUnauthorized={disconnect}
              canManageAccess={canManageAccess}
              oidcSession={accessType === 'session'}
            />
          )}
    </AdminShell>
  );
}

/** 宽版外壳(区别于窄卡片的用户交互页):顶栏 + 语言/断开按钮。 */
function AdminShell({
  children,
  onSignout,
}: {
  children: React.ReactNode;
  onSignout?: () => void | Promise<void>;
}) {
  const { t, i18n } = useTranslation();
  const toggle = () => setLang(i18n.language.startsWith('zh') ? 'en' : 'zh');
  return (
    <AntLayout style={{ minHeight: '100vh', background: '#f0f2f5' }}>
      <Header
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          background: '#001529',
          padding: '0 24px',
        }}
      >
        <Typography.Text strong style={{ color: '#fff', fontSize: 18 }}>
          {t('app.name')} · {t('admin.title')}
        </Typography.Text>
        <Space>
          <Button size="small" onClick={toggle} ghost>{t('lang.switch')}</Button>
          {onSignout && <Button size="small" onClick={onSignout} ghost danger>{t('admin.token.signout')}</Button>}
        </Space>
      </Header>
      <Content style={{ padding: '32px 24px', maxWidth: 1440, margin: '0 auto', width: '100%' }}>
        {children}
      </Content>
      <Footer style={{ textAlign: 'center', color: '#8c8c8c' }}>{t('footer.secured')}</Footer>
    </AntLayout>
  );
}

/** Enterprise SSO is the daily path; a bearer remains available for break-glass recovery. */
function TokenGate({
  initialError,
  onConnected,
}: {
  initialError: string | null;
  onConnected: (mode: AdminMode) => void;
}) {
  const { t } = useTranslation();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(initialError);

  const connect = async (values: { token: string }) => {
    setLoading(true);
    setError(null);
    setAdminToken(values.token.trim());
    try {
      const mode = await detectAdminMode();
      if (mode) {
        onConnected(mode);
      } else {
        clearAdminToken();
        setError(t('admin.token.invalid'));
      }
    } catch (e) {
      clearAdminToken();
      setError(adminProbeErrorMessage(t, e));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ maxWidth: 460, margin: '48px auto' }}>
      <Typography.Title level={3}>{t('admin.title')}</Typography.Title>
      <Typography.Paragraph type="secondary">{t('admin.subtitle')}</Typography.Paragraph>
      <Button type="primary" size="large" block href="/admin/sso/start">
        {t('admin.sso.signin')}
      </Button>
      <Divider plain>{t('admin.sso.breakGlass')}</Divider>
      <Form layout="vertical" onFinish={connect} requiredMark={false}>
        {error && (
          <Form.Item>
            <Alert type="error" showIcon message={error} />
          </Form.Item>
        )}
        <Form.Item name="token" label={t('admin.token.label')} rules={[{ required: true }]}
          extra={t('admin.token.hint')}>
          <Input.Password size="large" placeholder={t('admin.token.placeholder')} autoComplete="off" />
        </Form.Item>
        <Button type="primary" htmlType="submit" size="large" block loading={loading}>
          {t('admin.token.signin')}
        </Button>
      </Form>
    </div>
  );
}

/** 已连接:仪表盘 + client 管理 tabs。 */
function AdminConsole({
  onUnauthorized,
  canManageAccess,
  oidcSession,
}: {
  onUnauthorized: () => void;
  canManageAccess: boolean;
  oidcSession: boolean;
}) {
  const { t } = useTranslation();
  const [searchParams, setSearchParams] = useSearchParams();
  const tabKeys = ['overview', 'users', 'namespaces', 'clients', 'initial-access', 'federation', 'admin-sso', 'messages'] as const;
  const requestedTab = searchParams.get('tab');
  const activeTab = tabKeys.includes(requestedTab as (typeof tabKeys)[number])
    ? requestedTab!
    : 'overview';

  const setViewParam = (name: 'user_q' | 'client_q', value: string) => {
    const next = new URLSearchParams(searchParams);
    const normalized = value.trim();
    if (normalized) next.set(name, normalized);
    else next.delete(name);
    setSearchParams(next);
  };

  const userStatus = userStatusFilterFromParam(searchParams.get('user_status'));
  const setUserStatus = (value: UserStatusFilter) => {
    const next = new URLSearchParams(searchParams);
    if (value === 'non_deleted') next.delete('user_status');
    else next.set('user_status', value);
    setSearchParams(next);
  };

  const changeTab = (key: string) => {
    const next = new URLSearchParams(searchParams);
    if (key === 'overview') next.delete('tab');
    else next.set('tab', key);
    if (key !== 'users') {
      next.delete('user_q');
      next.delete('user_status');
    }
    if (key !== 'clients') next.delete('client_q');
    setSearchParams(next);
  };

  return (
    <Tabs
      activeKey={activeTab}
      onChange={changeTab}
      items={[
        { key: 'overview', label: t('admin.tab.overview'), children: <OverviewTab onUnauthorized={onUnauthorized} /> },
        {
          key: 'users',
          label: t('admin.tab.users'),
          children: (
            <UsersTab
              onUnauthorized={onUnauthorized}
              query={searchParams.get('user_q') ?? ''}
              onQueryChange={(value) => setViewParam('user_q', value)}
              status={userStatus}
              onStatusChange={setUserStatus}
            />
          ),
        },
        {
          key: 'namespaces',
          label: t('admin.tab.namespaces'),
          children: <AttributeNamespacesTab onUnauthorized={onUnauthorized} />,
        },
        {
          key: 'clients',
          label: t('admin.tab.clients'),
          children: (
            <ClientsTab
              onUnauthorized={onUnauthorized}
              query={searchParams.get('client_q') ?? ''}
              onQueryChange={(value) => setViewParam('client_q', value)}
            />
          ),
        },
        {
          key: 'initial-access',
          label: t('admin.tab.initialAccess'),
          children: <InitialAccessTokensTab onUnauthorized={onUnauthorized} />,
        },
        { key: 'federation', label: t('admin.tab.federation'), children: <FederationTab onUnauthorized={onUnauthorized} /> },
        {
          key: 'admin-sso',
          label: t('admin.tab.adminSso'),
          children: (
            <AdminOidcTab
              onUnauthorized={onUnauthorized}
              canManageAccess={canManageAccess}
              oidcSession={oidcSession}
            />
          ),
        },
        { key: 'messages', label: t('admin.tab.messages'), children: <MessagesTab onUnauthorized={onUnauthorized} /> },
      ]}
    />
  );
}

function AttributeNamespacesTab({
  onUnauthorized,
}: {
  onUnauthorized: () => void;
}) {
  const { t } = useTranslation();
  const [registrations, setRegistrations] = useState<NamespaceRegistrationView[]>([]);
  const [loading, setLoading] = useState(false);
  const [failed, setFailed] = useState(false);
  const [editing, setEditing] = useState<NamespaceRegistrationView | 'new' | null>(null);
  const [saving, setSaving] = useState(false);
  const [busyNamespace, setBusyNamespace] = useState<string | null>(null);
  const [form] = Form.useForm();

  const load = useCallback(async () => {
    setLoading(true);
    setFailed(false);
    const { data, response } = await adminApi.GET('/admin/attribute-namespaces');
    setLoading(false);
    if (response.status === 401) return onUnauthorized();
    if (!response.ok || !data) {
      setFailed(true);
      return;
    }
    setRegistrations(data.registrations);
  }, [onUnauthorized]);

  useEffect(() => {
    void load();
  }, [load]);

  const openEditor = (registration: NamespaceRegistrationView | 'new') => {
    setEditing(registration);
    form.setFieldsValue(
      registration === 'new'
        ? { canonical_namespace: '', exact_audiences: [] }
        : {
            canonical_namespace: registration.canonical_namespace,
            exact_audiences: registration.exact_audiences,
          },
    );
  };

  const save = async () => {
    const values = await form.validateFields() as {
      canonical_namespace: string;
      exact_audiences: string[];
    };
    const current = editing === 'new' || editing == null ? null : editing;
    setSaving(true);
    const { response } = await adminApi.PUT('/admin/attribute-namespaces', {
      body: {
        canonical_namespace: values.canonical_namespace.trim(),
        exact_audiences: [
          ...new Set(values.exact_audiences.map((value: string) => value.trim())),
        ],
        expected_revision: current?.revision ?? 0,
        operation_id: crypto.randomUUID(),
      },
    });
    setSaving(false);
    if (response.status === 401) return onUnauthorized();
    if (!response.ok) {
      message.error(response.status === 409
        ? t('admin.namespaces.conflict')
        : t('admin.namespaces.failed'));
      return;
    }
    setEditing(null);
    message.success(t('admin.namespaces.changeStarted'));
    await load();
  };

  const advance = async (initial: NamespaceRegistrationView) => {
    setBusyNamespace(initial.canonical_namespace);
    let current = initial;
    for (let page = 0; page < 200 && current.operation; page += 1) {
      const operation = current.operation;
      const { data, response } = await adminApi.POST('/admin/attribute-namespaces/advance', {
        body: {
          canonical_namespace: current.canonical_namespace,
          operation_id: operation.operation_id,
          expected_operation_revision: operation.revision,
        },
      });
      if (response.status === 401) {
        setBusyNamespace(null);
        return onUnauthorized();
      }
      if (!response.ok || !data) {
        message.error(response.status === 409
          ? t('admin.namespaces.migrationConflict')
          : t('admin.namespaces.failed'));
        break;
      }
      current = data;
    }
    setBusyNamespace(null);
    await load();
  };

  const cancel = async (registration: NamespaceRegistrationView) => {
    if (!registration.operation) return;
    setBusyNamespace(registration.canonical_namespace);
    const { response } = await adminApi.POST('/admin/attribute-namespaces/cancel', {
      body: {
        canonical_namespace: registration.canonical_namespace,
        operation_id: registration.operation.operation_id,
        expected_operation_revision: registration.operation.revision,
      },
    });
    setBusyNamespace(null);
    if (response.status === 401) return onUnauthorized();
    if (!response.ok) {
      message.error(t('admin.namespaces.failed'));
      return;
    }
    message.success(t('admin.namespaces.cancelled'));
    await load();
  };

  const retire = async (registration: NamespaceRegistrationView) => {
    setBusyNamespace(registration.canonical_namespace);
    const { response } = await adminApi.DELETE('/admin/attribute-namespaces', {
      params: {
        query: {
          canonical_namespace: registration.canonical_namespace,
          expected_revision: registration.revision,
          operation_id: crypto.randomUUID(),
        },
      },
    });
    setBusyNamespace(null);
    if (response.status === 401) return onUnauthorized();
    if (!response.ok) {
      message.error(response.status === 409
        ? t('admin.namespaces.conflict')
        : t('admin.namespaces.failed'));
      return;
    }
    message.success(t('admin.namespaces.retired'));
    await load();
  };

  const stateColor = (state: string) =>
    state === 'active' ? 'green' : state === 'pending' ? 'orange' : 'default';

  return (
    <Space direction="vertical" size="middle" style={{ width: '100%' }}>
      <Space style={{ width: '100%', justifyContent: 'space-between' }}>
        <Typography.Title level={4} style={{ margin: 0 }}>{t('admin.namespaces.title')}</Typography.Title>
        <Button type="primary" onClick={() => openEditor('new')}>
          {t('admin.namespaces.create')}
        </Button>
      </Space>
      {failed && <Alert type="error" showIcon message={t('admin.namespaces.failed')} />}
      <Table
        rowKey="canonical_namespace"
        loading={loading}
        pagination={false}
        dataSource={registrations}
        columns={[
          {
            title: t('admin.namespaces.canonical'),
            dataIndex: 'canonical_namespace',
            render: (value: string) => <Typography.Text code copyable>{value}</Typography.Text>,
          },
          {
            title: t('admin.namespaces.audiences'),
            dataIndex: 'exact_audiences',
            render: (values: string[]) => (
              <Space size={[4, 4]} wrap>
                {values.map((value) => <Tag key={value}>{value}</Tag>)}
              </Space>
            ),
          },
          {
            title: t('admin.namespaces.state'),
            dataIndex: 'state',
            width: 110,
            render: (value: string) => (
              <Tag color={stateColor(value)}>{t(`admin.namespaces.state.${value}`)}</Tag>
            ),
          },
          {
            title: t('admin.namespaces.progress'),
            key: 'progress',
            width: 190,
            render: (_: unknown, registration: NamespaceRegistrationView) => {
              const operation = registration.operation;
              if (!operation) return <Typography.Text type="secondary">-</Typography.Text>;
              return (
                <Space direction="vertical" size={0}>
                  <Typography.Text>{t(`admin.namespaces.phase.${operation.phase}`)}</Typography.Text>
                  <Typography.Text type="secondary">
                    {t('admin.namespaces.scanned', {
                      scanned: operation.users_scanned,
                      completed: operation.users_completed,
                    })}
                  </Typography.Text>
                  {operation.conflict_count > 0 && (
                    <Typography.Text type="danger">
                      {t('admin.namespaces.conflicts', { count: operation.conflict_count })}
                    </Typography.Text>
                  )}
                </Space>
              );
            },
          },
          {
            title: t('admin.users.col.actions'),
            key: 'actions',
            width: 250,
            render: (_: unknown, registration: NamespaceRegistrationView) => (
              <Space wrap>
                {registration.operation ? (
                  <>
                    <Button
                      size="small"
                      type="primary"
                      loading={busyNamespace === registration.canonical_namespace}
                      onClick={() => advance(registration)}
                    >
                      {t('admin.namespaces.continue')}
                    </Button>
                    {!registration.operation.started_mutation && (
                      <Popconfirm
                        title={t('admin.namespaces.cancelConfirm')}
                        onConfirm={() => cancel(registration)}
                      >
                        <Button size="small" disabled={busyNamespace !== null}>
                          {t('admin.namespaces.cancel')}
                        </Button>
                      </Popconfirm>
                    )}
                  </>
                ) : (
                  <>
                    <Button
                      size="small"
                      disabled={busyNamespace !== null}
                      onClick={() => openEditor(registration)}
                    >
                      {t('admin.namespaces.edit')}
                    </Button>
                    {registration.state === 'active' && (
                      <Popconfirm
                        title={t('admin.namespaces.retireConfirm')}
                        onConfirm={() => retire(registration)}
                      >
                        <Button size="small" danger disabled={busyNamespace !== null}>
                          {t('admin.namespaces.retire')}
                        </Button>
                      </Popconfirm>
                    )}
                  </>
                )}
              </Space>
            ),
          },
        ]}
      />
      <Modal
        open={editing !== null}
        title={editing === 'new' ? t('admin.namespaces.create') : t('admin.namespaces.edit')}
        okText={t('admin.namespaces.save')}
        confirmLoading={saving}
        onOk={save}
        onCancel={() => setEditing(null)}
      >
        <Form form={form} layout="vertical">
          <Form.Item
            name="canonical_namespace"
            label={t('admin.namespaces.canonical')}
            rules={[{ required: true }]}
          >
            <Input disabled={editing !== 'new'} />
          </Form.Item>
          <Form.Item
            name="exact_audiences"
            label={t('admin.namespaces.audiences')}
            rules={[{ required: true, type: 'array', max: 32 }]}
          >
            <Select mode="tags" tokenSeparators={[',']} />
          </Form.Item>
        </Form>
      </Modal>
    </Space>
  );
}

function ControlConsole({ onUnauthorized }: { onUnauthorized: () => void }) {
  const { t } = useTranslation();
  const screens = Grid.useBreakpoint();
  const [data, setData] = useState<ControlTenants | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    setError(false);
    const { data, response } = await adminApi.GET('/admin/control/tenants');
    setLoading(false);
    if (response.status === 401) return onUnauthorized();
    if (data) setData(data);
    else setError(true);
  }, [onUnauthorized]);

  useEffect(() => { void load(); }, [load]);

  const columns = [
    {
      title: t('admin.control.col.tenant'),
      dataIndex: 'tenant_id',
      key: 'tenant_id',
      width: 110,
    },
    {
      title: t('admin.control.col.issuer'),
      dataIndex: 'issuer',
      key: 'issuer',
      width: 240,
      render: (value: string) => (
        <Typography.Link href={value} style={{ overflowWrap: 'anywhere' }}>{value}</Typography.Link>
      ),
    },
    {
      title: t('admin.control.col.adminUrl'),
      dataIndex: 'admin_url',
      key: 'admin_url',
      width: 260,
      render: (value: string) => (
        <Typography.Link href={value} style={{ overflowWrap: 'anywhere' }}>{value}</Typography.Link>
      ),
    },
    {
      title: t('admin.control.col.secretArn'),
      dataIndex: 'admin_secret_arn',
      key: 'admin_secret_arn',
      width: 520,
      render: (value: string) => (
        <Typography.Text copyable={{ text: value }} style={{ overflowWrap: 'anywhere' }}>
          {value}
        </Typography.Text>
      ),
    },
  ];

  return (
    <Space direction="vertical" size="middle" style={{ width: '100%' }}>
      <Space style={{ width: '100%', justifyContent: 'space-between' }}>
        <Typography.Title level={4} style={{ margin: 0 }}>{t('admin.control.title')}</Typography.Title>
        <Button onClick={load} loading={loading}>{t('admin.overview.refresh')}</Button>
      </Space>
      {error && <Alert type="error" showIcon message={t('admin.control.error')} />}
      {screens.md ? (
        <Table<ControlTenantView>
          rowKey="tenant_id"
          columns={columns}
          dataSource={data?.tenants ?? []}
          loading={loading}
          pagination={false}
          size="small"
          tableLayout="fixed"
          scroll={{ x: 1130 }}
          locale={{ emptyText: t('admin.control.empty') }}
        />
      ) : (
        <div data-testid="control-tenant-list" style={{ borderTop: '1px solid #d9d9d9' }}>
          {(data?.tenants ?? []).map((tenant) => (
            <section
              key={tenant.tenant_id}
              style={{ padding: '16px 0', borderBottom: '1px solid #d9d9d9' }}
            >
              <Typography.Title level={5} style={{ margin: '0 0 12px' }}>
                {tenant.tenant_id}
              </Typography.Title>
              <Space direction="vertical" size={10} style={{ width: '100%' }}>
                <div>
                  <Typography.Text type="secondary">{t('admin.control.col.issuer')}</Typography.Text>
                  <br />
                  <Typography.Link href={tenant.issuer} style={{ overflowWrap: 'anywhere' }}>
                    {tenant.issuer}
                  </Typography.Link>
                </div>
                <div>
                  <Typography.Text type="secondary">{t('admin.control.col.adminUrl')}</Typography.Text>
                  <br />
                  <Typography.Link href={tenant.admin_url} style={{ overflowWrap: 'anywhere' }}>
                    {tenant.admin_url}
                  </Typography.Link>
                </div>
                <div>
                  <Typography.Text type="secondary">{t('admin.control.col.secretArn')}</Typography.Text>
                  <br />
                  <Typography.Text
                    copyable={{ text: tenant.admin_secret_arn }}
                    style={{ overflowWrap: 'anywhere', wordBreak: 'break-all' }}
                  >
                    {tenant.admin_secret_arn}
                  </Typography.Text>
                </div>
              </Space>
            </section>
          ))}
          {!loading && !(data?.tenants.length) && (
            <Typography.Text type="secondary">{t('admin.control.empty')}</Typography.Text>
          )}
        </div>
      )}
    </Space>
  );
}

function OverviewTab({ onUnauthorized }: { onUnauthorized: () => void }) {
  const { t } = useTranslation();
  const [data, setData] = useState<Overview | null>(null);
  const [error, setError] = useState(false);
  const [loading, setLoading] = useState(false);
  const issuer = data?.issuer.replace(/\/$/, '');
  const oidcDiscoveryUrl = issuer ? `${issuer}/.well-known/openid-configuration` : null;
  const oauthMetadataUrl = issuer ? `${issuer}/.well-known/oauth-authorization-server` : null;
  const openApiUrl = issuer ? `${issuer}/openapi.json` : null;

  const load = useCallback(async () => {
    setLoading(true);
    setError(false);
    const { data, response } = await adminApi.GET('/admin/overview');
    setLoading(false);
    if (response.status === 401) return onUnauthorized();
    if (data) setData(data);
    else setError(true);
  }, [onUnauthorized]);

  useEffect(() => { void load(); }, [load]);

  if (error) return <Alert type="error" showIcon message={t('admin.error.load')} />;

  return (
    <Space direction="vertical" size="large" style={{ width: '100%' }}>
      <Button onClick={load} loading={loading}>{t('admin.overview.refresh')}</Button>
      <Space size="large" wrap>
        <Statistic title={t('admin.overview.phase')} value={data?.phase ?? '—'} />
        <Statistic title={t('admin.overview.clientCount')} value={data?.client_count ?? 0} />
        <Statistic title={t('admin.overview.activeSessions')} value={data?.active_sessions ?? 0} />
      </Space>
      <Descriptions bordered column={1} size="small">
        <Descriptions.Item label={t('admin.overview.issuer')}>{data?.issuer ?? '—'}</Descriptions.Item>
        <Descriptions.Item label={t('admin.overview.oidcDiscoveryUrl')}>
          {oidcDiscoveryUrl
            ? <Typography.Link href={oidcDiscoveryUrl} style={{ overflowWrap: 'anywhere' }}>{oidcDiscoveryUrl}</Typography.Link>
            : '—'}
        </Descriptions.Item>
        <Descriptions.Item label={t('admin.overview.oauthMetadataUrl')}>
          {oauthMetadataUrl
            ? <Typography.Link href={oauthMetadataUrl} style={{ overflowWrap: 'anywhere' }}>{oauthMetadataUrl}</Typography.Link>
            : '—'}
        </Descriptions.Item>
        <Descriptions.Item label={t('admin.overview.openApi')}>
          {openApiUrl
            ? (
              <Typography.Link href={openApiUrl} download="agent-auth-openapi.json">
                {t('admin.overview.downloadOpenApi')}
              </Typography.Link>
            )
            : '—'}
        </Descriptions.Item>
        <Descriptions.Item label={t('admin.overview.endpoints')}>
          <Space wrap>
            {(data?.endpoints ?? []).map((e) => <Tag key={e}>{e}</Tag>)}
          </Space>
        </Descriptions.Item>
      </Descriptions>
    </Space>
  );
}

type FederationMappingForm = {
  enabled: boolean;
  mode: 'copy_string' | 'exact_membership';
  source_claim: string;
  source_value?: string;
  target_namespace: string;
  target_key: string;
  target_value?: string;
};

function FederationMappingsPanel({
  tenantId,
  idp,
  onUnauthorized,
}: {
  tenantId: string;
  idp: FederationIdpView;
  onUnauthorized: () => void;
}) {
  const { t } = useTranslation();
  const [registry, setRegistry] = useState<FederationAttributeMappingList | null>(null);
  const [namespaces, setNamespaces] = useState<NamespaceRegistrationView[]>([]);
  const [loading, setLoading] = useState(false);
  const [failed, setFailed] = useState(false);
  const [editing, setEditing] = useState<FederationAttributeMappingView | 'new' | null>(null);
  const [saving, setSaving] = useState(false);
  const [deleting, setDeleting] = useState<string | null>(null);
  const [form] = Form.useForm<FederationMappingForm>();
  const mode = Form.useWatch('mode', form);

  const load = useCallback(async () => {
    setLoading(true);
    setFailed(false);
    const [mappingsResult, namespacesResult] = await Promise.all([
      adminApi.GET('/admin/federation/{tenant_id}/{upstream_idp_id}/attribute-mappings', {
        params: {
          path: {
            tenant_id: tenantId,
            upstream_idp_id: idp.upstream_idp_id,
          },
        },
      }),
      adminApi.GET('/admin/attribute-namespaces'),
    ]);
    setLoading(false);
    if (mappingsResult.response.status === 401 || namespacesResult.response.status === 401) {
      return onUnauthorized();
    }
    if (!mappingsResult.data || !namespacesResult.data) {
      setFailed(true);
      return;
    }
    setRegistry(mappingsResult.data);
    setNamespaces(
      namespacesResult.data.registrations.filter(
        (registration) => registration.state === 'active' && registration.operation === null,
      ),
    );
  }, [idp.upstream_idp_id, onUnauthorized, tenantId]);

  useEffect(() => {
    void load();
  }, [load]);

  const openEditor = (mapping: FederationAttributeMappingView | 'new') => {
    setEditing(mapping);
    form.setFieldsValue(
      mapping === 'new'
        ? {
            enabled: true,
            mode: 'copy_string',
            source_claim: '',
            source_value: undefined,
            target_namespace: undefined,
            target_key: '',
            target_value: undefined,
          }
        : {
            enabled: mapping.enabled,
            mode: mapping.mode as FederationMappingForm['mode'],
            source_claim: mapping.source_claim,
            source_value: mapping.source_value ?? undefined,
            target_namespace: mapping.target_namespace,
            target_key: mapping.target_key,
            target_value: mapping.target_value ?? undefined,
          },
    );
  };

  const save = async () => {
    if (!registry || editing === null) return;
    const values = await form.validateFields();
    setSaving(true);
    const body = {
      expected_registry_revision: registry.registry_revision,
      mode: values.mode,
      source_claim: values.source_claim.trim(),
      source_value: values.mode === 'exact_membership'
        ? values.source_value?.trim() ?? null
        : null,
      target_namespace: values.target_namespace,
      target_key: values.target_key.trim(),
      target_value: values.mode === 'exact_membership'
        ? values.target_value?.trim() ?? null
        : null,
    };
    const result = editing === 'new'
      ? await adminApi.POST(
          '/admin/federation/{tenant_id}/{upstream_idp_id}/attribute-mappings',
          {
            params: {
              path: {
                tenant_id: tenantId,
                upstream_idp_id: idp.upstream_idp_id,
              },
            },
            body,
          },
        )
      : await adminApi.PUT(
          '/admin/federation/{tenant_id}/{upstream_idp_id}/attribute-mappings/{mapping_id}',
          {
            params: {
              path: {
                tenant_id: tenantId,
                upstream_idp_id: idp.upstream_idp_id,
                mapping_id: editing.mapping_id,
              },
            },
            body: {
              ...body,
              expected_mapping_revision: editing.revision,
              enabled: values.enabled,
            },
          },
        );
    setSaving(false);
    if (result.response.status === 401) return onUnauthorized();
    if (!result.response.ok) {
      message.error(result.response.status === 409
        ? t('admin.federation.mappings.conflict')
        : t('admin.federation.mappings.failed'));
      await load();
      return;
    }
    message.success(
      editing === 'new'
        ? t('admin.federation.mappings.created')
        : t('admin.federation.mappings.updated'),
    );
    setEditing(null);
    await load();
  };

  const remove = async (mapping: FederationAttributeMappingView) => {
    if (!registry) return;
    setDeleting(mapping.mapping_id);
    const { response } = await adminApi.DELETE(
      '/admin/federation/{tenant_id}/{upstream_idp_id}/attribute-mappings/{mapping_id}',
      {
        params: {
          path: {
            tenant_id: tenantId,
            upstream_idp_id: idp.upstream_idp_id,
            mapping_id: mapping.mapping_id,
          },
          query: {
            expected_registry_revision: registry.registry_revision,
            expected_mapping_revision: mapping.revision,
          },
        },
      },
    );
    setDeleting(null);
    if (response.status === 401) return onUnauthorized();
    if (!response.ok) {
      message.error(response.status === 409
        ? t('admin.federation.mappings.conflict')
        : t('admin.federation.mappings.failed'));
      await load();
      return;
    }
    message.success(t('admin.federation.mappings.deleted'));
    await load();
  };

  const setEnabled = async (mapping: FederationAttributeMappingView, enabled: boolean) => {
    if (!registry) return;
    setSaving(true);
    const { response } = await adminApi.PUT(
      '/admin/federation/{tenant_id}/{upstream_idp_id}/attribute-mappings/{mapping_id}',
      {
        params: {
          path: {
            tenant_id: tenantId,
            upstream_idp_id: idp.upstream_idp_id,
            mapping_id: mapping.mapping_id,
          },
        },
        body: {
          expected_registry_revision: registry.registry_revision,
          expected_mapping_revision: mapping.revision,
          enabled,
          mode: mapping.mode as FederationMappingForm['mode'],
          source_claim: mapping.source_claim,
          source_value: mapping.source_value,
          target_namespace: mapping.target_namespace,
          target_key: mapping.target_key,
          target_value: mapping.target_value,
        },
      },
    );
    setSaving(false);
    if (response.status === 401) return onUnauthorized();
    if (!response.ok) {
      message.error(response.status === 409
        ? t('admin.federation.mappings.conflict')
        : t('admin.federation.mappings.failed'));
    }
    await load();
  };

  return (
    <Space direction="vertical" size="middle" style={{ width: '100%', padding: '8px 0' }}>
      <Space style={{ width: '100%', justifyContent: 'space-between' }}>
        <Typography.Text strong>{t('admin.federation.mappings.title')}</Typography.Text>
        <Button
          size="small"
          type="primary"
          disabled={namespaces.length === 0 || loading}
          onClick={() => openEditor('new')}
        >
          {t('admin.federation.mappings.create')}
        </Button>
      </Space>
      {failed && <Alert type="error" showIcon message={t('admin.federation.mappings.failed')} />}
      {!loading && namespaces.length === 0 && (
        <Alert type="warning" showIcon message={t('admin.federation.mappings.noNamespaces')} />
      )}
      <Table<FederationAttributeMappingView>
        size="small"
        rowKey="mapping_id"
        loading={loading}
        pagination={false}
        dataSource={registry?.mappings ?? []}
        locale={{ emptyText: t('admin.federation.mappings.empty') }}
        columns={[
          {
            title: t('admin.federation.mappings.source'),
            key: 'source',
            render: (_, mapping) => (
              <Space direction="vertical" size={0}>
                <Typography.Text code>{mapping.source_claim}</Typography.Text>
                {mapping.mode === 'exact_membership' && (
                  <Typography.Text type="secondary">
                    {t('admin.federation.mappings.equals', { value: mapping.source_value })}
                  </Typography.Text>
                )}
              </Space>
            ),
          },
          {
            title: t('admin.federation.mappings.target'),
            key: 'target',
            render: (_, mapping) => (
              <Space direction="vertical" size={0}>
                <Typography.Text code>{mapping.target_namespace}</Typography.Text>
                <Typography.Text>
                  {mapping.target_key}
                  {mapping.mode === 'exact_membership'
                    ? ` = ${mapping.target_value ?? ''}`
                    : ''}
                </Typography.Text>
              </Space>
            ),
          },
          {
            title: t('admin.federation.mappings.mode'),
            dataIndex: 'mode',
            width: 150,
            render: (value: string) => (
              <Tag>{t(`admin.federation.mappings.mode.${value}`)}</Tag>
            ),
          },
          {
            title: t('admin.federation.mappings.enabled'),
            dataIndex: 'enabled',
            width: 100,
            render: (enabled: boolean, mapping) => (
              <Switch
                checked={enabled}
                loading={saving}
                onChange={(checked) => void setEnabled(mapping, checked)}
                aria-label={t('admin.federation.mappings.enabled')}
              />
            ),
          },
          {
            title: t('admin.clients.col.actions'),
            key: 'actions',
            width: 170,
            render: (_, mapping) => (
              <Space>
                <Button size="small" onClick={() => openEditor(mapping)}>
                  {t('admin.clients.edit')}
                </Button>
                <Popconfirm
                  title={t('admin.federation.mappings.deleteConfirm')}
                  onConfirm={() => remove(mapping)}
                >
                  <Button
                    size="small"
                    danger
                    loading={deleting === mapping.mapping_id}
                  >
                    {t('admin.clients.delete')}
                  </Button>
                </Popconfirm>
              </Space>
            ),
          },
        ]}
      />
      <Modal
        open={editing !== null}
        title={editing === 'new'
          ? t('admin.federation.mappings.create')
          : t('admin.federation.mappings.edit')}
        okText={t('admin.form.submit')}
        cancelText={t('admin.form.cancel')}
        confirmLoading={saving}
        onOk={() => void save()}
        onCancel={() => setEditing(null)}
      >
        <Form<FederationMappingForm> form={form} layout="vertical">
          {editing !== 'new' && (
            <Form.Item
              name="enabled"
              label={t('admin.federation.mappings.enabled')}
              valuePropName="checked"
            >
              <Switch />
            </Form.Item>
          )}
          <Form.Item
            name="mode"
            label={t('admin.federation.mappings.mode')}
            rules={[{ required: true }]}
          >
            <Select
              options={[
                {
                  value: 'copy_string',
                  label: t('admin.federation.mappings.mode.copy_string'),
                },
                {
                  value: 'exact_membership',
                  label: t('admin.federation.mappings.mode.exact_membership'),
                },
              ]}
            />
          </Form.Item>
          <Form.Item
            name="source_claim"
            label={t('admin.federation.mappings.sourceClaim')}
            rules={[{ required: true }]}
          >
            <Input />
          </Form.Item>
          {mode === 'exact_membership' && (
            <Form.Item
              name="source_value"
              label={t('admin.federation.mappings.sourceValue')}
              rules={[{ required: true }]}
            >
              <Input />
            </Form.Item>
          )}
          <Form.Item
            name="target_namespace"
            label={t('admin.federation.mappings.targetNamespace')}
            rules={[{ required: true }]}
          >
            <Select
              showSearch
              optionFilterProp="label"
              options={namespaces.map((namespace) => ({
                value: namespace.canonical_namespace,
                label: namespace.canonical_namespace,
              }))}
            />
          </Form.Item>
          <Form.Item
            name="target_key"
            label={t('admin.federation.mappings.targetKey')}
            rules={[{ required: true }]}
          >
            <Input />
          </Form.Item>
          {mode === 'exact_membership' && (
            <Form.Item
              name="target_value"
              label={t('admin.federation.mappings.targetValue')}
              rules={[{ required: true }]}
            >
              <Input />
            </Form.Item>
          )}
        </Form>
      </Modal>
    </Space>
  );
}

// 联邦上游 IdP 管理(spec 003 §4)。列/登记/删 `/admin/federation`。SelfHosted 单租户固定 tenant="default"。
// secret 只收**引用名**(client_secret_ref;Secrets Manager 前缀 agent-auth/federation/*),后端不回显。
function FederationTab({ onUnauthorized }: { onUnauthorized: () => void }) {
  const { t } = useTranslation();
  const TENANT = 'default'; // 自部署单租户;SaaS 多租户由 Host 派生(此 admin 面按当前部署)
  const [idps, setIdps] = useState<FederationIdpView[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(false);
  const [adding, setAdding] = useState(false);
  const [form] = Form.useForm();

  const load = useCallback(async () => {
    setLoading(true);
    setError(false);
    const { data, response } = await adminApi.GET('/admin/federation/{tenant_id}', {
      params: { path: { tenant_id: TENANT } },
    });
    setLoading(false);
    if (response.status === 401) return onUnauthorized();
    if (data) setIdps(data.idps);
    else setError(true);
  }, [onUnauthorized]);

  useEffect(() => {
    void load();
  }, [load]);

  const remove = async (idpId: string) => {
    const { response } = await adminApi.DELETE('/admin/federation/{tenant_id}/{upstream_idp_id}', {
      params: { path: { tenant_id: TENANT, upstream_idp_id: idpId } },
    });
    if (response.status === 401) return onUnauthorized();
    if (response.ok) {
      message.success(t('admin.federation.delete.ok'));
      void load();
    }
  };

  const submit = async (v: {
    upstream_idp_id: string;
    upstream_issuer: string;
    client_id: string;
    client_secret_ref: string;
    authorization_endpoint: string;
    token_endpoint: string;
    jwks_uri: string;
    scopes: string;
    strong_acr_values: string;
  }) => {
    const { response } = await adminApi.PUT('/admin/federation', {
      body: {
        tenant_id: TENANT,
        upstream_idp_id: v.upstream_idp_id,
        upstream_issuer: v.upstream_issuer,
        client_id: v.client_id,
        client_secret_ref: v.client_secret_ref,
        authorization_endpoint: v.authorization_endpoint,
        token_endpoint: v.token_endpoint,
        jwks_uri: v.jwks_uri,
        scopes: v.scopes.split(/[\s,]+/).filter(Boolean),
        strong_acr_values: v.strong_acr_values.split(/[\s,]+/).filter(Boolean),
      },
    });
    if (response.status === 401) return onUnauthorized();
    if (response.ok) {
      message.success(t('admin.federation.register.ok'));
      setAdding(false);
      form.resetFields();
      void load();
    } else {
      message.error(t('admin.federation.register.fail'));
    }
  };

  const columns = [
    { title: t('admin.federation.col.idp'), dataIndex: 'upstream_idp_id', key: 'idp',
      render: (v: string) => <Typography.Text code>{v}</Typography.Text> },
    { title: t('admin.federation.col.issuer'), dataIndex: 'upstream_issuer', key: 'issuer' },
    { title: t('admin.federation.col.clientId'), dataIndex: 'client_id', key: 'cid' },
    { title: t('admin.federation.col.scopes'), dataIndex: 'scopes', key: 'scopes',
      render: (v: string[]) => v.map((s) => <Tag key={s}>{s}</Tag>) },
    { title: t('admin.federation.col.strongAcr'), dataIndex: 'strong_acr_values', key: 'strongAcr',
      render: (v: string[]) => v.map((acr) => <Tag key={acr}>{acr}</Tag>) },
    {
      title: t('admin.clients.col.actions'), key: 'actions',
      render: (_: unknown, r: FederationIdpView) => (
        <Popconfirm title={t('admin.federation.delete.confirm')} onConfirm={() => remove(r.upstream_idp_id)}>
          <Button size="small" danger>{t('admin.clients.delete')}</Button>
        </Popconfirm>
      ),
    },
  ];

  return (
    <Space direction="vertical" size="middle" style={{ width: '100%' }}>
      <Space style={{ justifyContent: 'space-between', width: '100%' }}>
        <Typography.Title level={4} style={{ margin: 0 }}>{t('admin.federation.title')}</Typography.Title>
        <Button type="primary" onClick={() => setAdding(true)}>{t('admin.federation.register')}</Button>
      </Space>
      <Alert type="info" showIcon message={t('admin.federation.hint')} />
      {error && <Alert type="error" showIcon message={t('error.generic')} />}
      <Table
        rowKey="upstream_idp_id"
        loading={loading}
        columns={columns}
        dataSource={idps}
        pagination={false}
        locale={{ emptyText: t('admin.federation.empty') }}
        expandable={{
          expandedRowRender: (idp) => (
            <FederationMappingsPanel
              tenantId={TENANT}
              idp={idp}
              onUnauthorized={onUnauthorized}
            />
          ),
          rowExpandable: () => true,
        }}
      />
      <Modal
        title={t('admin.federation.register')}
        open={adding}
        onCancel={() => setAdding(false)}
        onOk={() => form.submit()}
        okText={t('admin.form.submit')}
        cancelText={t('admin.form.cancel')}
      >
        <Form form={form} layout="vertical" onFinish={submit}
          initialValues={{ scopes: 'openid', strong_acr_values: '' }}>
          <Form.Item name="upstream_idp_id" label={t('admin.federation.col.idp')} rules={[{ required: true }]}>
            <Input placeholder="okta" />
          </Form.Item>
          <Form.Item name="upstream_issuer" label={t('admin.federation.col.issuer')} rules={[{ required: true }]}>
            <Input placeholder="https://xxx.okta.com" />
          </Form.Item>
          <Form.Item name="client_id" label={t('admin.federation.col.clientId')} rules={[{ required: true }]}>
            <Input />
          </Form.Item>
          <Form.Item name="client_secret_ref" label={t('admin.federation.form.secretRef')} rules={[{ required: true }]}
            extra={t('admin.federation.form.secretRefHint')}>
            <Input placeholder="agent-auth/federation/okta" />
          </Form.Item>
          <Form.Item name="authorization_endpoint" label={t('admin.federation.form.authzEp')} rules={[{ required: true }]}>
            <Input placeholder="https://…/authorize" />
          </Form.Item>
          <Form.Item name="token_endpoint" label={t('admin.federation.form.tokenEp')} rules={[{ required: true }]}>
            <Input placeholder="https://…/token" />
          </Form.Item>
          <Form.Item name="jwks_uri" label={t('admin.federation.form.jwksUri')} rules={[{ required: true }]}>
            <Input placeholder="https://…/jwks" />
          </Form.Item>
          <Form.Item name="scopes" label={t('admin.federation.form.scopes')}>
            <Input placeholder="openid profile email" />
          </Form.Item>
          <Form.Item name="strong_acr_values" label={t('admin.federation.form.strongAcr')}>
            <Input placeholder="urn:okta:loa:2fa" />
          </Form.Item>
        </Form>
      </Modal>
    </Space>
  );
}

type AdminOidcForm = {
  issuer: string;
  client_id: string;
  client_secret_ref: string;
  authorization_endpoint: string;
  token_endpoint: string;
  jwks_uri: string;
  redirect_uri: string;
  scopes: string;
  strong_acr_values: string;
  identity_claim: string;
  identity_field: 'user_id' | 'user_name';
};

function AdminOidcTab({
  onUnauthorized,
  canManageAccess,
  oidcSession,
}: {
  onUnauthorized: () => void;
  canManageAccess: boolean;
  oidcSession: boolean;
}) {
  const { t } = useTranslation();
  const [config, setConfig] = useState<AdminOidcConfigView | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(false);
  const [form] = Form.useForm<AdminOidcForm>();

  const load = useCallback(async () => {
    setLoading(true);
    setError(false);
    const { data, response } = await adminApi.GET('/admin/oidc');
    setLoading(false);
    if (response.status === 401) return onUnauthorized();
    if (response.status === 404) {
      setConfig(null);
      form.setFieldsValue({
        redirect_uri: `${window.location.origin}/admin/sso/callback`,
        scopes: 'openid email',
        strong_acr_values: '',
        identity_claim: 'email',
        identity_field: 'user_name',
      });
      return;
    }
    if (!data) {
      setError(true);
      return;
    }
    setConfig(data);
    form.setFieldsValue({
      issuer: data.issuer,
      client_id: data.client_id,
      client_secret_ref: '',
      authorization_endpoint: data.authorization_endpoint,
      token_endpoint: data.token_endpoint,
      jwks_uri: data.jwks_uri,
      redirect_uri: data.redirect_uri,
      scopes: data.scopes.join(' '),
      strong_acr_values: data.strong_acr_values.join(' '),
      identity_claim: data.identity_claim,
      identity_field: data.identity_field,
    });
  }, [form, onUnauthorized]);

  useEffect(() => { void load(); }, [load]);

  const submit = async (values: AdminOidcForm) => {
    const { data, response } = await adminApi.PUT('/admin/oidc', {
      body: {
        issuer: values.issuer,
        client_id: values.client_id,
        client_secret_ref: values.client_secret_ref,
        authorization_endpoint: values.authorization_endpoint,
        token_endpoint: values.token_endpoint,
        jwks_uri: values.jwks_uri,
        redirect_uri: values.redirect_uri,
        scopes: values.scopes.split(/\s+/).filter(Boolean),
        strong_acr_values: values.strong_acr_values.split(/\s+/).filter(Boolean),
        identity_claim: values.identity_claim,
        identity_field: values.identity_field,
        expected_revision: config?.revision ?? 0,
      },
    });
    if (response.status === 401) return onUnauthorized();
    if (response.status === 403) {
      message.error(t('admin.sso.forbidden'));
      return;
    }
    if (response.status === 409) {
      message.error(t('admin.sso.conflict'));
      void load();
      return;
    }
    if (!data) {
      message.error(t('admin.sso.saveFailed'));
      return;
    }
    setConfig(data);
    form.setFieldValue('client_secret_ref', '');
    message.success(t('admin.sso.saved'));
  };

  const remove = async () => {
    if (!config) return;
    const { response } = await adminApi.DELETE('/admin/oidc', {
      params: { query: { expected_revision: config.revision } },
    });
    if (response.status === 401) return onUnauthorized();
    if (response.status === 403) {
      message.error(t('admin.sso.forbidden'));
      return;
    }
    if (response.status === 409) {
      message.error(t('admin.sso.conflict'));
      void load();
      return;
    }
    if (!response.ok) {
      message.error(t('admin.sso.deleteFailed'));
      return;
    }
    message.success(t('admin.sso.deleted'));
    if (oidcSession) {
      onUnauthorized();
      return;
    }
    setConfig(null);
    form.resetFields();
    form.setFieldsValue({
      redirect_uri: `${window.location.origin}/admin/sso/callback`,
      scopes: 'openid email',
      strong_acr_values: '',
      identity_claim: 'email',
      identity_field: 'user_name',
    });
  };

  return (
    <Space direction="vertical" size="middle" style={{ width: '100%' }}>
      <Space style={{ justifyContent: 'space-between', width: '100%' }}>
        <Typography.Title level={4} style={{ margin: 0 }}>{t('admin.sso.configTitle')}</Typography.Title>
        <Button onClick={load} loading={loading}>{t('admin.overview.refresh')}</Button>
      </Space>
      {error && <Alert type="error" showIcon message={t('admin.error.load')} />}
      {!canManageAccess && (
        <Alert type="info" showIcon message={t('admin.sso.ownerOnly')} />
      )}
      <Form<AdminOidcForm>
        form={form}
        layout="vertical"
        onFinish={submit}
        disabled={!canManageAccess}
        requiredMark={false}
      >
        <Form.Item name="issuer" label={t('admin.sso.issuer')} rules={[{ required: true }]}>
          <Input placeholder="https://idp.example.com" />
        </Form.Item>
        <Form.Item name="client_id" label={t('admin.sso.clientId')} rules={[{ required: true }]}>
          <Input />
        </Form.Item>
        <Form.Item
          name="client_secret_ref"
          label={t('admin.sso.secretRef')}
          extra={config?.client_secret_configured
            ? `${t('admin.sso.secretConfigured')} ${t('admin.sso.secretRefHint')}`
            : t('admin.sso.secretRefHint')}
          rules={[{ required: canManageAccess }]}
        >
          <Input.Password
            autoComplete="off"
            placeholder="agent-auth/admin-oidc/<tenant-id>"
          />
        </Form.Item>
        <Form.Item name="authorization_endpoint" label={t('admin.sso.authzEndpoint')} rules={[{ required: true }]}>
          <Input placeholder="https://idp.example.com/authorize" />
        </Form.Item>
        <Form.Item name="token_endpoint" label={t('admin.sso.tokenEndpoint')} rules={[{ required: true }]}>
          <Input placeholder="https://idp.example.com/token" />
        </Form.Item>
        <Form.Item name="jwks_uri" label={t('admin.sso.jwksUri')} rules={[{ required: true }]}>
          <Input placeholder="https://idp.example.com/jwks" />
        </Form.Item>
        <Form.Item name="redirect_uri" label={t('admin.sso.redirectUri')} rules={[{ required: true }]}>
          <Input />
        </Form.Item>
        <Form.Item name="scopes" label={t('admin.sso.scopes')} rules={[{ required: true }]}>
          <Input />
        </Form.Item>
        <Form.Item name="strong_acr_values" label={t('admin.sso.strongAcr')}>
          <Input placeholder="urn:okta:loa:2fa" />
        </Form.Item>
        <Form.Item name="identity_claim" label={t('admin.sso.identityClaim')} rules={[{ required: true }]}>
          <Input placeholder="email" />
        </Form.Item>
        <Form.Item name="identity_field" label={t('admin.sso.identityField')} rules={[{ required: true }]}>
          <Select
            options={[
              { value: 'user_name', label: t('admin.sso.identityUserName') },
              { value: 'user_id', label: t('admin.sso.identityUserId') },
            ]}
          />
        </Form.Item>
        {canManageAccess && (
          <Space>
            <Button type="primary" htmlType="submit">{t('admin.form.submit')}</Button>
            {config && (
              <Popconfirm title={t('admin.sso.deleteConfirm')} onConfirm={remove}>
                <Button danger>{t('admin.sso.delete')}</Button>
              </Popconfirm>
            )}
          </Space>
        )}
      </Form>
    </Space>
  );
}

function MessagesTab({ onUnauthorized }: { onUnauthorized: () => void }) {
  const { t } = useTranslation();
  const [msgs, setMsgs] = useState<MessageView[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    setError(false);
    const { data, response } = await adminApi.GET('/admin/messages');
    setLoading(false);
    if (response.status === 401) return onUnauthorized();
    if (data) setMsgs(data.messages);
    else setError(true);
  }, [onUnauthorized]);

  useEffect(() => { void load(); }, [load]);

  const columns = [
    { title: t('admin.messages.col.kind'), dataIndex: 'kind', key: 'kind', width: 120,
      render: (v: string) => <Tag color={v === 'magic_link' ? 'blue' : 'orange'}>{v}</Tag> },
    { title: t('admin.messages.col.recipient'), dataIndex: 'recipient', key: 'recipient', width: 220 },
    { title: t('admin.messages.col.body'), dataIndex: 'body', key: 'body', width: 420,
      render: (v: string) => (
        <Typography.Text copyable={{ text: v }} ellipsis={{ tooltip: v }} style={{ maxWidth: 420 }}>
          {v}
        </Typography.Text>
      ) },
    { title: t('admin.messages.col.time'), dataIndex: 'created_at', key: 'created_at', width: 190,
      render: (v: number) => new Date(v * 1000).toLocaleString() },
  ];

  return (
    <Space direction="vertical" size="middle" style={{ width: '100%' }}>
      <Space style={{ justifyContent: 'space-between', width: '100%' }}>
        <div>
          <Typography.Title level={4} style={{ margin: 0 }}>{t('admin.messages.title')}</Typography.Title>
          <Typography.Text type="secondary">{t('admin.messages.hint')}</Typography.Text>
        </div>
        <Button onClick={load} loading={loading}>{t('admin.overview.refresh')}</Button>
      </Space>
      {error && <Alert type="error" showIcon message={t('admin.error.load')} />}
      <Table
        rowKey="message_id"
        loading={loading}
        columns={columns}
        dataSource={msgs}
        locale={{ emptyText: t('admin.messages.empty') }}
        pagination={false}
        scroll={{ x: 950 }}
        tableLayout="fixed"
      />
    </Space>
  );
}

// 人类用户管理(spec 003 §1.4,类 Cognito User Pool)。create 预建本地 email 用户;
// list/get/status/delete 同时覆盖已登录落表的联邦用户。
function UsersTab({
  onUnauthorized,
  query,
  onQueryChange,
  status,
  onStatusChange,
}: {
  onUnauthorized: () => void;
  query: string;
  onQueryChange: (query: string) => void;
  status: UserStatusFilter;
  onStatusChange: (status: UserStatusFilter) => void;
}) {
  const { t } = useTranslation();
  const [users, setUsers] = useState<UserView[]>([]);
  const [cursor, setCursor] = useState<string | null>(null); // 下一页 cursor(null=无更多)
  const [refreshVersion, setRefreshVersion] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(false);
  const [creating, setCreating] = useState(false);
  const [creatingBusy, setCreatingBusy] = useState(false);
  const [issuingInvitation, setIssuingInvitation] = useState(false);
  const [regeneratingUserId, setRegeneratingUserId] = useState<string | null>(null);
  const [invitation, setInvitation] = useState<InvitationSecretResponse | null>(null);
  const [resetting, setResetting] = useState<UserView | null>(null);
  const [searchInput, setSearchInput] = useState(query);
  const [detail, setDetail] = useState<UserDetail | null>(null);
  const [resourceOptions, setResourceOptions] = useState<string[]>([]);
  const [form] = Form.useForm();
  const [resetForm] = Form.useForm();
  const loadGeneration = useRef(0);
  const regeneratingInvitation = useRef(false);
  const bootstrapMethod = Form.useWatch('bootstrap_method', form) ?? 'temporary_password';
  const invitationAtRisk = invitation !== null
    || issuingInvitation
    || regeneratingUserId !== null;
  const invitationBlocker = useBlocker(invitationAtRisk);

  useEffect(() => {
    if (!invitationAtRisk) return undefined;
    const warnBeforeUnload = (event: BeforeUnloadEvent) => {
      event.preventDefault();
      event.returnValue = '';
    };
    window.addEventListener('beforeunload', warnBeforeUnload);
    return () => window.removeEventListener('beforeunload', warnBeforeUnload);
  }, [invitationAtRisk]);

  useEffect(() => {
    if (invitationBlocker.state !== 'blocked') return;
    if (window.confirm(t('admin.users.invitation.dismissWarning'))) {
      setInvitation(null);
      invitationBlocker.proceed();
    } else {
      invitationBlocker.reset();
    }
  }, [invitationBlocker, t]);

  useEffect(() => {
    setSearchInput(query);
  }, [query]);

  // 属性编辑只以 active canonical namespace 为候选；unbound namespace 仍允许显式输入。
  useEffect(() => {
    void (async () => {
      const { data, response } = await adminApi.GET('/admin/attribute-namespaces');
      if (response.ok && data) {
        setResourceOptions(data.registrations
          .filter((registration) => registration.state === 'active')
          .map((registration) => registration.canonical_namespace)
          .sort());
      }
    })();
  }, []);

  // 首页加载(reset=true)或翻页(append)。cursor 为不透明 token,原样回传。
  const load = useCallback(
    async (reset: boolean) => {
      const generation = reset ? ++loadGeneration.current : loadGeneration.current;
      setLoading(true);
      setError(false);
      const { data, response } = await adminApi.GET('/admin/users', {
        params: {
          query: reset
            ? { limit: 20, q: query || undefined, status }
            : {
              limit: 20,
              cursor: cursor ?? undefined,
              q: query || undefined,
              status,
            },
        },
      });
      if (generation !== loadGeneration.current) return;
      setLoading(false);
      if (response.status === 401) return onUnauthorized();
      if (data) {
        setUsers((prev) => (reset ? data.users : [...prev, ...data.users]));
        setCursor(data.next_cursor ?? null);
      } else {
        setError(true);
      }
    },
    [cursor, onUnauthorized, query, status],
  );

  useEffect(() => {
    setCursor(null);
    void load(true);
    // cursor 变化不自动重拉,翻页显式调 load(false)。
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [onUnauthorized, query, refreshVersion, status]);

  const reload = () => {
    setCursor(null);
    // 异步 mutation 可能在旧 query/status render 下启动；只发刷新信号，让最新 render
    // 的 effect 使用当前 URL 参数拉取，避免旧闭包覆盖新筛选结果。
    setRefreshVersion((version) => version + 1);
  };

  const setStatusAction = async (uid: string, action: 'disable' | 'enable') => {
    const path = action === 'disable' ? '/admin/users/{id}/disable' : '/admin/users/{id}/enable';
    const { response } = await adminApi.POST(path, { params: { path: { id: uid } } });
    if (response.status === 401) return onUnauthorized();
    if (response.ok) {
      message.success(t(action === 'disable' ? 'admin.users.disable.ok' : 'admin.users.enable.ok'));
      reload();
    } else {
      message.error(t('admin.users.action.fail'));
    }
  };

  const remove = async (uid: string) => {
    const { response } = await adminApi.DELETE('/admin/users/{id}', { params: { path: { id: uid } } });
    if (response.status === 401) return onUnauthorized();
    if (response.ok) {
      message.success(t('admin.users.delete.ok'));
      reload();
    } else {
      message.error(t('admin.users.action.fail'));
    }
  };

  const openDetail = async (uid: string) => {
    const { data, response } = await adminApi.GET('/admin/users/{id}', { params: { path: { id: uid } } });
    if (response.status === 401) return onUnauthorized();
    if (data) setDetail(data);
    else message.error(t('admin.users.action.fail'));
  };

  const create = async (v: {
    email: string;
    bootstrap_method: 'temporary_password' | 'invitation';
    initial_password?: string;
  }) => {
    setCreatingBusy(true);
    const invitationMode = v.bootstrap_method === 'invitation';
    setIssuingInvitation(invitationMode);
    try {
      const { data, response } = await adminApi.POST('/admin/users', {
        body: {
          email: v.email.trim(),
          initial_password: invitationMode ? undefined : v.initial_password,
          issue_invitation: invitationMode,
        },
      });
      if (response.status === 401) return onUnauthorized();
      if (response.ok) {
        message.success(t('admin.users.create.ok'));
        setCreating(false);
        form.resetFields();
        if (data?.invitation) {
          setInvitation(data.invitation);
        } else {
          reload();
        }
      } else if (response.status === 409) {
        message.error(t('admin.users.create.conflict'));
      } else {
        message.error(t('admin.users.action.fail'));
      }
    } catch {
      message.error(t('admin.users.action.fail'));
    } finally {
      setCreatingBusy(false);
      setIssuingInvitation(false);
    }
  };

  const regenerateInvitation = async (user: UserView) => {
    if (regeneratingInvitation.current) return;
    regeneratingInvitation.current = true;
    setRegeneratingUserId(user.user_id);
    try {
      const { data, response } = await adminApi.POST('/admin/users/{id}/invitation', {
        params: { path: { id: user.user_id } },
      });
      if (response.status === 401) return onUnauthorized();
      if (response.ok && data) {
        setInvitation(data);
      } else if (response.status === 409) {
        message.error(t('admin.users.invitation.ineligible'));
      } else {
        message.error(t('admin.users.action.fail'));
      }
    } catch {
      message.error(t('admin.users.action.fail'));
    } finally {
      regeneratingInvitation.current = false;
      setRegeneratingUserId(null);
    }
  };

  const copyInvitation = async () => {
    if (!invitation) return;
    try {
      await navigator.clipboard.writeText(invitation.invitation_url);
      message.success(t('admin.users.invitation.copied'));
    } catch {
      message.error(t('admin.users.invitation.copyFailed'));
    }
  };

  const confirmDismissInvitation = () => {
    Modal.confirm({
      title: t('admin.users.invitation.dismissTitle'),
      content: t('admin.users.invitation.dismissWarning'),
      okText: t('admin.users.invitation.discard'),
      cancelText: t('admin.form.cancel'),
      okButtonProps: { danger: true },
      onOk: () => {
        setInvitation(null);
        reload();
      },
    });
  };

  const resetPassword = async (v: { temporary_password: string }) => {
    if (!resetting) return;
    const { response } = await adminApi.POST('/admin/users/{id}/reset-password', {
      params: { path: { id: resetting.user_id } },
      body: { temporary_password: v.temporary_password },
    });
    if (response.status === 401) return onUnauthorized();
    if (response.ok) {
      message.success(t('admin.users.reset.ok'));
      setResetting(null);
      resetForm.resetFields();
      reload();
    } else if (response.status === 409) {
      message.error(t('admin.users.reset.conflict'));
    } else {
      message.error(t('admin.users.action.fail'));
    }
  };

  const statusTag = (s: string) => {
    const color = s === 'active' ? 'green' : s === 'disabled' ? 'orange' : 'red';
    return <Tag color={color}>{t(`admin.users.status.${s}`)}</Tag>;
  };

  const columns = [
    { title: t('admin.users.col.email'), dataIndex: 'email', key: 'email', width: 220,
      render: (v: string) => <Typography.Text copyable>{v}</Typography.Text> },
    { title: t('admin.users.col.userId'), dataIndex: 'user_id', key: 'user_id', width: 260,
      render: (v: string) => <Typography.Text code>{v}</Typography.Text> },
    { title: t('admin.users.col.status'), dataIndex: 'status', key: 'status', width: 110, render: statusTag },
    { title: t('admin.users.col.created'), dataIndex: 'created_at', key: 'created_at', width: 180,
      render: (v: number) => new Date(v * 1000).toLocaleString() },
    { title: t('admin.users.col.lastLogin'), dataIndex: 'last_login_at', key: 'last_login_at', width: 180,
      render: (v?: number | null) => v == null
        ? t('admin.users.neverLoggedIn')
        : formatUtcTimestamp(v) },
    {
      title: t('admin.users.col.actions'), key: 'actions', width: 350, fixed: 'right' as const,
      render: (_: unknown, u: UserView) => (
        <Space wrap>
          <Button size="small" onClick={() => openDetail(u.user_id)}>{t('admin.users.action.view')}</Button>
          {u.status !== 'tombstoned' && isLocalEmailUser(u) && (
            <Button size="small" onClick={() => setResetting(u)}>
              {t('admin.users.action.resetPassword')}
            </Button>
          )}
          {u.status === 'active' && isLocalEmailUser(u) && (
            <Button
              size="small"
              loading={regeneratingUserId === u.user_id}
              disabled={regeneratingUserId !== null}
              onClick={() => void regenerateInvitation(u)}
            >
              {t('admin.users.action.invite')}
            </Button>
          )}
          {u.status === 'active' && (
            <Popconfirm title={t('admin.users.disable.confirm')} onConfirm={() => setStatusAction(u.user_id, 'disable')}>
              <Button size="small">{t('admin.users.action.disable')}</Button>
            </Popconfirm>
          )}
          {u.status === 'disabled' && (
            <Button size="small" type="primary" ghost onClick={() => setStatusAction(u.user_id, 'enable')}>
              {t('admin.users.action.enable')}
            </Button>
          )}
          {u.status !== 'tombstoned' && (
            <Popconfirm title={t('admin.users.delete.confirm')} onConfirm={() => remove(u.user_id)}>
              <Button size="small" danger>{t('admin.users.action.delete')}</Button>
            </Popconfirm>
          )}
        </Space>
      ),
    },
  ];

  return (
    <Space direction="vertical" size="middle" style={{ width: '100%' }}>
      <Space style={{ justifyContent: 'space-between', width: '100%' }}>
        <Typography.Title level={4} style={{ margin: 0 }}>{t('admin.users.title')}</Typography.Title>
        <Button type="primary" onClick={() => setCreating(true)}>{t('admin.users.create')}</Button>
      </Space>
      <Alert type="info" showIcon message={t('admin.users.hint')} />
      <div
        style={{
          display: 'flex',
          flexWrap: 'wrap',
          gap: 8,
          minWidth: 0,
          width: '100%',
        }}
      >
        <Input.Search
          allowClear
          value={searchInput}
          placeholder={t('admin.users.searchPlaceholder')}
          enterButton={t('admin.search')}
          onChange={(event) => {
            setSearchInput(event.target.value);
            if (!event.target.value && query) onQueryChange('');
          }}
          onSearch={(value) => onQueryChange(value)}
          style={{ flex: '1 1 320px', minWidth: 0, maxWidth: '100%' }}
        />
        <Select<UserStatusFilter>
          aria-label={t('admin.users.filter.label')}
          value={status}
          onChange={onStatusChange}
          options={[
            { value: 'non_deleted', label: t('admin.users.filter.nonDeleted') },
            { value: 'active', label: t('admin.users.status.active') },
            { value: 'disabled', label: t('admin.users.status.disabled') },
            { value: 'tombstoned', label: t('admin.users.status.tombstoned') },
            { value: 'all', label: t('admin.users.filter.all') },
          ]}
          style={{ flex: '0 1 190px', minWidth: 0, maxWidth: '100%' }}
        />
      </div>
      {error && <Alert type="error" showIcon message={t('admin.error.load')} />}
      <Table
        rowKey="user_id"
        loading={loading}
        columns={columns}
        dataSource={users}
        pagination={false}
        locale={{
          emptyText: t(
            query || status !== 'non_deleted'
              ? 'admin.users.emptyFiltered'
              : 'admin.users.empty',
          ),
        }}
        scroll={{ x: 1300 }}
        tableLayout="fixed"
      />
      {cursor && (
        <Button onClick={() => void load(false)} loading={loading} block>
          {t('admin.users.loadMore')}
        </Button>
      )}
      <Modal
        title={t('admin.users.create.title')}
        open={creating}
        onCancel={() => {
          if (!creatingBusy) setCreating(false);
        }}
        onOk={() => form.submit()}
        okText={t('admin.form.submit')}
        cancelText={t('admin.form.cancel')}
        confirmLoading={creatingBusy}
        maskClosable={!creatingBusy}
      >
        <Form
          form={form}
          layout="vertical"
          onFinish={create}
          requiredMark={false}
          initialValues={{ bootstrap_method: 'temporary_password' }}
        >
          <Form.Item name="email" label={t('admin.users.col.email')} rules={[{ required: true, type: 'email' }]}
            extra={t('admin.users.create.emailHint')}>
            <Input placeholder="alice@example.com" autoComplete="off" />
          </Form.Item>
          <Form.Item
            name="bootstrap_method"
            label={t('admin.users.create.bootstrapMethod')}
            rules={[{ required: true }]}
          >
            <Segmented
              block
              options={[
                {
                  label: t('admin.users.create.temporaryPassword'),
                  value: 'temporary_password',
                },
                {
                  label: t('admin.users.create.invitation'),
                  value: 'invitation',
                },
              ]}
            />
          </Form.Item>
          {bootstrapMethod === 'invitation' && (
            <Alert
              type="info"
              showIcon
              message={t('admin.users.create.invitationHint')}
              style={{ marginBottom: 16 }}
            />
          )}
          {bootstrapMethod === 'temporary_password' && (
          <Form.Item
            name="initial_password"
            label={t('admin.users.create.initialPassword')}
            rules={[passwordRule(t('admin.users.create.passwordPolicy'))]}
          >
            <Input.Password autoComplete="new-password" />
          </Form.Item>
          )}
        </Form>
      </Modal>
      <Modal
        title={t('admin.users.invitation.title')}
        open={!!invitation}
        destroyOnHidden
        closable={false}
        maskClosable={false}
        keyboard={false}
        footer={[
          <Button key="copy" type="primary" onClick={() => void copyInvitation()}>
            {t('admin.users.invitation.copy')}
          </Button>,
          <Button key="dismiss" danger onClick={confirmDismissInvitation}>
            {t('admin.users.invitation.done')}
          </Button>,
        ]}
      >
        <Alert
          type="warning"
          showIcon
          message={t('admin.users.invitation.warning')}
          style={{ marginBottom: 16 }}
        />
        <Typography.Paragraph strong>
          {t('admin.users.invitation.expires', {
            value: invitation ? new Date(invitation.expires_at * 1000).toLocaleString() : '',
          })}
        </Typography.Paragraph>
        <Input.TextArea
          aria-label={t('admin.users.invitation.url')}
          value={invitation?.invitation_url ?? ''}
          readOnly
          autoSize={{ minRows: 3, maxRows: 6 }}
        />
      </Modal>
      <Modal
        title={t('admin.users.reset.title')}
        open={!!resetting}
        onCancel={() => {
          setResetting(null);
          resetForm.resetFields();
        }}
        onOk={() => resetForm.submit()}
        okText={t('admin.users.reset.submit')}
        cancelText={t('admin.form.cancel')}
        okButtonProps={{ danger: true }}
      >
        <Alert
          type="warning"
          showIcon
          message={t('admin.users.reset.hint', { email: resetting?.email })}
          style={{ marginBottom: 16 }}
        />
        <Form form={resetForm} layout="vertical" onFinish={resetPassword} requiredMark={false}>
          <Form.Item
            name="temporary_password"
            label={t('admin.users.reset.temporaryPassword')}
            rules={[passwordRule(t('admin.users.create.passwordPolicy'))]}
          >
            <Input.Password autoComplete="new-password" />
          </Form.Item>
          <Form.Item
            name="confirm_password"
            label={t('admin.users.reset.confirmPassword')}
            dependencies={['temporary_password']}
            rules={[
              { required: true },
              ({ getFieldValue }) => ({
                validator: (_rule, value) => value === getFieldValue('temporary_password')
                  ? Promise.resolve()
                  : Promise.reject(new Error(t('admin.users.reset.mismatch'))),
              }),
            ]}
          >
            <Input.Password autoComplete="new-password" />
          </Form.Item>
        </Form>
      </Modal>
      <UserDetailModal
        detail={detail}
        onClose={() => setDetail(null)}
        resourceOptions={resourceOptions}
        onSaved={() => detail && void openDetail(detail.user_id)}
      />
    </Space>
  );
}

/** 用户详情(聚合计数 + 状态;绝不含敏感值)。Count 可能是数字或 {unavailable:true}(store 失败标记)。 */
function UserDetailModal({
  detail,
  onClose,
  onSaved,
  resourceOptions,
}: {
  detail: UserDetail | null;
  onClose: () => void;
  onSaved: () => void;
  resourceOptions: string[];
}) {
  const { t } = useTranslation();
  if (!detail) return null;
  // Count union:数字直显;{unavailable:true} 显 "unavailable"(§1.4 codex #4:绝不当 0)。
  const count = (c: components['schemas']['Count']) =>
    typeof c === 'number' ? c : t('admin.users.detail.unavailable');
  const recovery =
    detail.recovery_unavailable
      ? t('admin.users.detail.unavailable')
      : detail.has_recovery
        ? t('admin.users.detail.recovery.yes')
        : t('admin.users.detail.recovery.no');
  const statusColor = detail.status === 'active' ? 'green' : detail.status === 'disabled' ? 'orange' : 'red';
  return (
    <Modal open title={t('admin.users.detail.title')} width={680} onCancel={onClose} footer={[
      <Button key="close" type="primary" onClick={onClose}>{t('admin.secret.close')}</Button>,
    ]}>
      <Descriptions column={1} size="small" bordered>
        <Descriptions.Item label={t('admin.users.col.email')}>
          <Typography.Text copyable>{detail.email}</Typography.Text>
        </Descriptions.Item>
        <Descriptions.Item label={t('admin.users.col.userId')}>
          <Typography.Text code>{detail.user_id}</Typography.Text>
        </Descriptions.Item>
        <Descriptions.Item label={t('admin.users.col.status')}>
          <Tag color={statusColor}>{t(`admin.users.status.${detail.status}`)}</Tag>
        </Descriptions.Item>
        <Descriptions.Item label={t('admin.users.col.created')}>
          {new Date(detail.created_at * 1000).toLocaleString()}
        </Descriptions.Item>
        <Descriptions.Item label={t('admin.users.col.lastLogin')}>
          {detail.last_login_at == null
            ? t('admin.users.neverLoggedIn')
            : formatUtcTimestamp(detail.last_login_at)}
        </Descriptions.Item>
        <Descriptions.Item label={t('admin.users.detail.grants')}>{count(detail.active_grants)}</Descriptions.Item>
        <Descriptions.Item label={t('admin.users.detail.passkeys')}>{count(detail.passkeys)}</Descriptions.Item>
        <Descriptions.Item label={t('admin.users.detail.sessions')}>{count(detail.sessions)}</Descriptions.Item>
        <Descriptions.Item label={t('admin.users.detail.recovery')}>{recovery}</Descriptions.Item>
        <Descriptions.Item label={t('admin.users.detail.password')}>
          {t(`admin.users.detail.passwordStatus.${detail.password_status}`)}
        </Descriptions.Item>
      </Descriptions>
      <UserAttributesEditor
        userId={detail.user_id}
        attributes={detail.attributes ?? {}}
        resourceOptions={resourceOptions}
        onSaved={onSaved}
      />
    </Modal>
  );
}

// spec 007 §6.1:RS 命名空间用户属性编辑区。按 namespace 分组展示;admin 选/填 namespace(候选=已注册
// RS resource)后在其下增/改/删单个 key。提交走 read-modify-write:整 namespace 现有 kv 本地改后带
// If-Match(该 namespace revision)整体 PUT 回,复用全量替换端点(不加 PATCH)。
type AttrNsView = components['schemas']['AttrNamespaceView'];
function UserAttributesEditor({
  userId,
  attributes,
  resourceOptions,
  onSaved,
}: {
  userId: string;
  attributes: Record<string, AttrNsView>;
  resourceOptions: string[];
  onSaved: () => void;
}) {
  const { t } = useTranslation();
  const [namespace, setNamespace] = useState('');
  const [newKey, setNewKey] = useState('');
  const [newVal, setNewVal] = useState('');
  const [saving, setSaving] = useState(false);

  // 整命名空间 read-modify-write:取当前 kv+revision → mutate → 带 If-Match PUT。
  const writeNamespace = async (ns: string, kv: Record<string, string>, revision: number) => {
    setSaving(true);
    const { response, data } = await adminApi.PUT('/admin/users/{id}/attributes', {
      params: { path: { id: userId }, query: { namespace: ns }, header: { 'if-match': String(revision) } },
      body: kv,
    });
    setSaving(false);
    if (response.ok) {
      message.success(t('admin.attrs.saved'));
      onSaved();
      return;
    }
    if (response.status === 409) {
      // 并发冲突:自动重取该用户详情(拿最新 revision + attributes),用户无需手动重开 Modal。
      message.warning(t('admin.attrs.conflict'));
      onSaved();
    } else if (response.status === 413) {
      message.error(t('admin.attrs.tooLarge'));
    } else if (response.status === 400) {
      message.error(t('admin.attrs.badInput'));
    } else if (response.status === 401) {
      message.error(t('admin.error.unauthorized'));
    } else {
      message.error(t('admin.attrs.failed') + (data ? `: ${JSON.stringify(data)}` : ''));
    }
  };

  const addKey = async () => {
    const ns = namespace.trim();
    const k = newKey.trim();
    if (!ns || !k) {
      message.warning(t('admin.attrs.nsKeyRequired'));
      return;
    }
    // 前端只做绝对 URI/fragment 快速校验；服务端仍是 1024-byte 与模式限制的权威。
    try {
      const u = new URL(ns);
      if (u.hash || !u.protocol) throw new Error('bad');
    } catch {
      message.error(t('admin.attrs.nsNotUri'));
      return;
    }
    const existing = attributes[ns];
    const kv = { ...(existing?.kv ?? {}), [k]: newVal };
    await writeNamespace(ns, kv, existing?.revision ?? 0);
    setNewKey('');
    setNewVal('');
  };

  const deleteKey = async (view: AttrNsView, key: string) => {
    if (view.federation_owners[key]) return;
    const kv = { ...view.kv };
    delete kv[key];
    // 空 kv = 清空该 namespace(后端 {} 语义)。
    await writeNamespace(view.canonical_namespace, kv, view.revision);
  };

  const purgeStaleOwner = async (view: AttrNsView, key: string) => {
    setSaving(true);
    const { response, data } = await adminApi.DELETE(
      '/admin/users/{id}/attributes/federation-owner',
      {
        params: {
          path: { id: userId },
          query: { namespace: view.canonical_namespace, key },
          header: { 'if-match': String(view.revision) },
        },
      },
    );
    setSaving(false);
    if (response.ok) {
      message.success(t('admin.attrs.purgeOk'));
      onSaved();
      return;
    }
    if (response.status === 409) {
      message.warning(t('admin.attrs.conflict'));
      onSaved();
    } else if (response.status === 401) {
      message.error(t('admin.error.unauthorized'));
    } else {
      message.error(t('admin.attrs.purgeFailed') + (data ? `: ${JSON.stringify(data)}` : ''));
    }
  };

  const nsEntries = Object.entries(attributes);
  const managedTarget = attributes[namespace]?.federation_owners[newKey.trim()];
  return (
    <div style={{ marginTop: 16 }}>
      <Typography.Title level={5}>{t('admin.attrs.title')}</Typography.Title>
      <Alert type="info" showIcon style={{ marginBottom: 8 }} message={t('admin.attrs.hint')} />
      {nsEntries.length === 0 && (
        <Typography.Text type="secondary">{t('admin.attrs.empty')}</Typography.Text>
      )}
      {nsEntries.map(([ns, view]) => (
        <div key={ns} style={{ marginBottom: 12 }}>
          <Space size={[4, 4]} wrap>
            <Typography.Text code copyable>{view.canonical_namespace}</Typography.Text>
            <Tag color={view.registration_state === 'active' ? 'green' : view.registration_state === 'pending' ? 'orange' : 'default'}>
              {t(`admin.namespaces.state.${view.registration_state}`)}
            </Tag>
            <Typography.Text type="secondary">rev {view.revision}</Typography.Text>
            {view.exact_audiences.map((audience) => <Tag key={audience}>{audience}</Tag>)}
          </Space>
          <Table
            rowKey={(r) => r.key}
            size="small"
            pagination={false}
            style={{ marginTop: 4 }}
            columns={[
              { title: t('admin.attrs.key'), dataIndex: 'key', key: 'key' },
              { title: t('admin.attrs.value'), dataIndex: 'value', key: 'value' },
              {
                title: t('admin.attrs.owner'),
                key: 'owner',
                render: (_: unknown, r: { key: string }) => {
                  const owner = view.federation_owners[r.key];
                  return owner ? (
                    <Space size={[4, 4]} wrap>
                      <Tag color={owner.state === 'active' ? 'blue' : 'orange'}>
                        {t(owner.state === 'active' ? 'admin.attrs.managed' : 'admin.attrs.managedStale')}
                      </Tag>
                      <Typography.Text type="secondary">
                        {owner.upstream_idp_id} / {owner.mapping_id} rev {owner.mapping_revision}
                      </Typography.Text>
                    </Space>
                  ) : (
                    <Typography.Text type="secondary">{t('admin.attrs.adminOwned')}</Typography.Text>
                  );
                },
              },
              {
                title: t('admin.users.col.actions'),
                key: 'act',
                render: (_: unknown, r: { key: string }) => {
                  const owner = view.federation_owners[r.key];
                  const stale = owner?.state === 'stale';
                  return (
                  <Popconfirm
                    title={t(stale ? 'admin.attrs.purgeConfirm' : 'admin.attrs.deleteConfirm')}
                    disabled={!!owner && !stale}
                    onConfirm={() => (stale
                      ? purgeStaleOwner(view, r.key)
                      : deleteKey(view, r.key))}
                  >
                    <Button
                      size="small"
                      danger
                      disabled={
                        saving
                        || (!!owner && !stale)
                        || !['active', 'unbound'].includes(view.registration_state)
                      }
                    >
                      {t(stale ? 'admin.attrs.purge' : 'admin.attrs.delete')}
                    </Button>
                  </Popconfirm>
                  );
                },
              },
            ]}
            dataSource={Object.entries(view.kv).map(([key, value]) => ({ key, value }))}
          />
        </div>
      ))}
      <Space.Compact style={{ display: 'flex', marginTop: 8 }}>
        <AutoComplete
          style={{ minWidth: 200 }}
          placeholder={t('admin.attrs.nsPlaceholder')}
          value={namespace || undefined}
          onChange={setNamespace}
          // 允许手填 unbound resource；已注册项只提供 canonical 候选。
          options={resourceOptions.map((r) => ({ label: r, value: r }))}
          filterOption={(input, opt) => (opt?.value ?? '').toLowerCase().includes(input.toLowerCase())}
        />
        <Input placeholder={t('admin.attrs.key')} value={newKey} onChange={(e) => setNewKey(e.target.value)} style={{ width: 140 }} />
        <Input placeholder={t('admin.attrs.value')} value={newVal} onChange={(e) => setNewVal(e.target.value)} style={{ width: 160 }} />
        <Button
          type="primary"
          loading={saving}
          disabled={!!managedTarget}
          onClick={addKey}
        >
          {t('admin.attrs.addOrUpdate')}
        </Button>
      </Space.Compact>
      {managedTarget && (
        <Typography.Text type="danger">{t('admin.attrs.managedReadOnly')}</Typography.Text>
      )}
    </div>
  );
}

function ClientsTab({
  onUnauthorized,
  query,
  onQueryChange,
}: {
  onUnauthorized: () => void;
  query: string;
  onQueryChange: (query: string) => void;
}) {
  const { t } = useTranslation();
  const [clients, setClients] = useState<ClientView[]>([]);
  const [authMethods, setAuthMethods] = useState<string[]>([]);
  const [searchInput, setSearchInput] = useState(query);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(false);
  const [editing, setEditing] = useState<ClientView | 'new' | null>(null);
  const [credentialClient, setCredentialClient] = useState<ClientView | null>(null);
  const [secretModal, setSecretModal] = useState<{ clientId: string; secret: string } | null>(null);
  const [columnWidths, setColumnWidths] = useState<Record<ClientColumnKey, number>>(
    () => ({ ...CLIENT_COLUMN_DEFAULT_WIDTHS }),
  );
  const loadGeneration = useRef(0);

  useEffect(() => {
    setSearchInput(query);
  }, [query]);

  const load = useCallback(async () => {
    const generation = ++loadGeneration.current;
    setLoading(true);
    setError(false);
    const { data, response } = await adminApi.GET('/admin/clients');
    if (generation !== loadGeneration.current) return;
    setLoading(false);
    if (response.status === 401) return onUnauthorized();
    if (data) {
      setClients(data.clients);
      setAuthMethods(data.registered_client_auth_methods_supported);
    }
    else setError(true);
  }, [onUnauthorized]);

  useEffect(() => { void load(); }, [load]);

  const remove = async (clientId: string) => {
    const { response } = await adminApi.DELETE('/admin/clients/{client_id}', {
      params: { path: { client_id: clientId } },
    });
    if (response.status === 401) return onUnauthorized();
    if (response.ok) {
      message.success(t('admin.clients.delete.ok'));
      void load();
    } else if (response.status === 403) {
      message.error(t('admin.sso.forbidden'));
    }
  };

  const resizeColumn = useCallback((key: ClientColumnKey, width: number) => {
    setColumnWidths((current) => (
      current[key] === width ? current : { ...current, [key]: width }
    ));
  }, []);
  const resizableHeader = (key: ClientColumnKey, label: string) => ({
    width: columnWidths[key],
    onHeaderCell: () => ({
      width: columnWidths[key],
      minWidth: CLIENT_COLUMN_MIN_WIDTHS[key],
      resizeLabel: label,
      onColumnResize: (width: number) => resizeColumn(key, width),
    } as ResizableHeaderCellProps),
  });
  const clientTableWidth = Object.values(columnWidths).reduce((total, width) => total + width, 0);

  const columns: TableColumnsType<ClientView> = [
    { title: t('admin.clients.col.id'), dataIndex: 'client_id', key: 'client_id',
      ...resizableHeader('client_id', t('admin.clients.col.id')),
      render: (v: string) => (
        <Typography.Text code copyable style={{ whiteSpace: 'nowrap' }}>{v}</Typography.Text>
      ) },
    { title: t('admin.clients.col.authMethod'), dataIndex: 'token_endpoint_auth_method', key: 'auth',
      ...resizableHeader('auth', t('admin.clients.col.authMethod')),
      render: (v: string) => <Tag>{v}</Tag> },
    { title: t('admin.clients.col.redirects'), dataIndex: 'redirect_uris', key: 'redirects',
      ...resizableHeader('redirects', t('admin.clients.col.redirects')),
      render: (v: string[]) => v.map((u) => (
        <Typography.Text key={u} ellipsis={{ tooltip: u }} style={{ display: 'block' }}>{u}</Typography.Text>
      )) },
    { title: t('admin.clients.col.resource'), dataIndex: 'default_resource', key: 'resource',
      ...resizableHeader('resource', t('admin.clients.col.resource')),
      render: (v?: string | null) => v
        ? <Typography.Text ellipsis={{ tooltip: v }} style={{ display: 'block' }}>{v}</Typography.Text>
        : '—' },
    { title: t('admin.clients.col.introspect'), dataIndex: 'introspect_enabled', key: 'introspect',
      ...resizableHeader('introspect', t('admin.clients.col.introspect')),
      render: (v: boolean) => (v ? <Tag color="blue">✓</Tag> : '—') },
    { title: t('admin.clients.col.lastTokenIssued'), dataIndex: 'last_used_at', key: 'last_used_at',
      ...resizableHeader('last_used_at', t('admin.clients.col.lastTokenIssued')),
      render: (v?: number | null) => v == null
        ? t('admin.clients.neverUsed')
        : formatUtcDay(v) },
    {
      title: t('admin.clients.col.actions'), key: 'actions',
      ...resizableHeader('actions', t('admin.clients.col.actions')),
      render: (_: unknown, c: ClientView) => (
        <Space>
          <Button size="small" onClick={() => setCredentialClient(c)}>
            {t('admin.clients.credentials')}
          </Button>
          <Button size="small" onClick={() => setEditing(c)}>{t('admin.clients.edit')}</Button>
          <Popconfirm title={t('admin.clients.delete.confirm')} onConfirm={() => remove(c.client_id)}>
            <Button size="small" danger>{t('admin.clients.delete')}</Button>
          </Popconfirm>
        </Space>
      ),
    },
  ];
  const normalizedQuery = query.trim().toLowerCase();
  const filteredClients = normalizedQuery
    ? clients.filter((client) => [
      client.client_id,
      client.default_resource ?? '',
      ...(client.redirect_uris ?? []),
      ...(client.post_logout_redirect_uris ?? []),
      ...(client.resource_ids ?? []),
    ].some((value) => value.toLowerCase().includes(normalizedQuery)))
    : clients;

  return (
    <Space direction="vertical" size="middle" style={{ width: '100%' }}>
      <Space style={{ justifyContent: 'space-between', width: '100%' }}>
        <Typography.Title level={4} style={{ margin: 0 }}>{t('admin.clients.title')}</Typography.Title>
        <Button type="primary" onClick={() => setEditing('new')}>{t('admin.clients.register')}</Button>
      </Space>
      <Input.Search
        allowClear
        value={searchInput}
        placeholder={t('admin.clients.searchPlaceholder')}
        enterButton={t('admin.search')}
        onChange={(event) => {
          setSearchInput(event.target.value);
          if (!event.target.value && query) onQueryChange('');
        }}
        onSearch={(value) => onQueryChange(value)}
        style={{ width: '100%', maxWidth: 480 }}
      />
      {error && <Alert type="error" showIcon message={t('admin.error.load')} />}
      <Table
        rowKey="client_id"
        loading={loading}
        components={{ header: { cell: ResizableHeaderCell } }}
        columns={columns}
        dataSource={filteredClients}
        locale={{ emptyText: t('admin.clients.empty') }}
        pagination={false}
        scroll={{ x: clientTableWidth }}
        tableLayout="fixed"
      />
      {editing && (
        <ClientForm
          target={editing}
          authMethods={authMethods}
          onUnauthorized={onUnauthorized}
          onClose={() => setEditing(null)}
          onDone={(created) => {
            setEditing(null);
            if (created) setSecretModal(created);
            void load();
          }}
        />
      )}
      {credentialClient && (
        <CredentialManagementModal
          client={credentialClient}
          onUnauthorized={onUnauthorized}
          onClose={() => setCredentialClient(null)}
          onChanged={() => { void load(); }}
        />
      )}
      {secretModal && <SecretModal data={secretModal} onClose={() => setSecretModal(null)} />}
    </Space>
  );
}

function effectiveCredentialStatus(credential: CredentialView | InitialAccessTokenView): string {
  return credential.status === 'active' && credential.expires_at <= Math.floor(Date.now() / 1000)
    ? 'expired'
    : credential.status;
}

function CredentialStatusTag({ credential }: { credential: CredentialView | InitialAccessTokenView }) {
  const { t } = useTranslation();
  const status = effectiveCredentialStatus(credential);
  const color = status === 'active'
    ? 'green'
    : status === 'expired'
      ? 'default'
      : status === 'consumed'
        ? 'blue'
        : 'red';
  return <Tag color={color}>{t(`admin.credentials.status.${status}`)}</Tag>;
}

function CredentialManagementModal({
  client,
  onUnauthorized,
  onClose,
  onChanged,
}: {
  client: ClientView;
  onUnauthorized: () => void;
  onClose: () => void;
  onChanged: () => void;
}) {
  const { t } = useTranslation();
  const [sets, setSets] = useState<Record<ClientCredentialKind, CredentialSetView>>({
    'client-secret': client.client_secret_credentials,
    'registration-token': client.registration_token_credentials,
  });
  const [rotateKind, setRotateKind] = useState<ClientCredentialKind | null>(null);
  const [rotationRequestId, setRotationRequestId] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [revealed, setRevealed] = useState<{ label: string; value: string } | null>(null);
  const [rotateForm] = Form.useForm();

  const updateSet = (kind: ClientCredentialKind, credentials: CredentialSetView) => {
    setSets((current) => ({ ...current, [kind]: credentials }));
    onChanged();
  };

  const handleFailure = (status: number) => {
    if (status === 401) {
      onUnauthorized();
      return;
    }
    if (status === 409) {
      message.warning(t('admin.credentials.conflict'));
      onChanged();
      onClose();
      return;
    }
    message.error(t('admin.credentials.actionFailed'));
  };

  const rotate = async () => {
    if (!rotateKind || !rotationRequestId) return;
    const values = await rotateForm.validateFields();
    const currentSet = sets[rotateKind];
    setBusy(`rotate:${rotateKind}`);
    const { data, response } = await adminApi.POST(
      '/admin/clients/{client_id}/credentials/{kind}/rotate',
      {
        params: { path: { client_id: client.client_id, kind: rotateKind } },
        body: {
          rotation_request_id: rotationRequestId,
          expected_version: currentSet.version,
          expires_in_seconds: values.expires_in_days * 86_400,
          overlap_seconds: values.overlap_in_hours * 3_600,
        },
      },
    );
    setBusy(null);
    if (!response.ok || !data) return handleFailure(response.status);
    updateSet(rotateKind, data.credentials);
    setRotateKind(null);
    setRotationRequestId(null);
    rotateForm.resetFields();
    if (data.credential) {
      setRevealed({
        label: t(`admin.credentials.kind.${rotateKind}`),
        value: data.credential,
      });
    } else {
      message.info(t('admin.credentials.retryNoReveal'));
    }
  };

  const mutate = async (
    action: 'cutover' | 'revoke',
    kind: ClientCredentialKind,
    credential: CredentialView,
  ) => {
    const currentSet = sets[kind];
    setBusy(`${action}:${credential.credential_id}`);
    const path = action === 'cutover'
      ? '/admin/clients/{client_id}/credentials/{kind}/cutover' as const
      : '/admin/clients/{client_id}/credentials/{kind}/revoke' as const;
    const { data, response } = await adminApi.POST(path, {
      params: { path: { client_id: client.client_id, kind } },
      body: {
        credential_id: credential.credential_id,
        expected_version: currentSet.version,
      },
    });
    setBusy(null);
    if (!response.ok || !data) return handleFailure(response.status);
    updateSet(kind, data.credentials);
    message.success(t(`admin.credentials.${action}.ok`));
  };

  const credentialSection = (kind: ClientCredentialKind) => {
    const set = sets[kind];
    const rows: CredentialSlotRow[] = [
      ...(set.current ? [{ role: 'current' as const, credential: set.current }] : []),
      ...(set.next ? [{ role: 'next' as const, credential: set.next }] : []),
    ];
    const secretUnsupported = kind === 'client-secret'
      && !['client_secret_basic', 'client_secret_post'].includes(client.token_endpoint_auth_method);
    const hasPending = set.next != null && effectiveCredentialStatus(set.next) === 'active';
    return (
      <section key={kind} style={{ marginBottom: 24 }}>
        <Space style={{ justifyContent: 'space-between', width: '100%', marginBottom: 8 }} wrap>
          <div>
            <Typography.Title level={5} style={{ margin: 0 }}>
              {t(`admin.credentials.kind.${kind}`)}
            </Typography.Title>
            <Typography.Text type="secondary">
              {t('admin.credentials.version', { version: set.version })}
              {set.overlap_expires_at
                ? ` · ${t('admin.credentials.overlapUntil', { time: formatUtcTimestamp(set.overlap_expires_at) })}`
                : ''}
            </Typography.Text>
          </div>
          <Button
            type="primary"
            size="small"
            disabled={secretUnsupported || hasPending}
            onClick={() => {
              rotateForm.setFieldsValue({ expires_in_days: 365, overlap_in_hours: 24 });
              setRotationRequestId(crypto.randomUUID());
              setRotateKind(kind);
            }}
          >
            {rows.length === 0 ? t('admin.credentials.issue') : t('admin.credentials.rotate')}
          </Button>
        </Space>
        {secretUnsupported && (
          <Alert
            type="info"
            showIcon
            message={t('admin.credentials.secretUnsupported')}
            style={{ marginBottom: 8 }}
          />
        )}
        <Table<CredentialSlotRow>
          rowKey={(row) => row.credential.credential_id}
          size="small"
          pagination={false}
          dataSource={rows}
          locale={{ emptyText: t('admin.credentials.empty') }}
          scroll={{ x: 900 }}
          columns={[
            {
              title: t('admin.credentials.col.role'),
              dataIndex: 'role',
              width: 90,
              render: (role: string) => <Tag>{t(`admin.credentials.role.${role}`)}</Tag>,
            },
            {
              title: t('admin.credentials.col.id'),
              key: 'id',
              width: 210,
              render: (_: unknown, row) => (
                <Typography.Text code copyable>{row.credential.credential_id}</Typography.Text>
              ),
            },
            {
              title: t('admin.credentials.col.status'),
              key: 'status',
              width: 100,
              render: (_: unknown, row) => (
                <CredentialStatusTag credential={row.credential} />
              ),
            },
            {
              title: t('admin.credentials.col.expires'),
              key: 'expires',
              width: 190,
              render: (_: unknown, row) =>
                formatUtcTimestamp(row.credential.expires_at),
            },
            {
              title: t('admin.credentials.col.audit'),
              key: 'audit',
              width: 180,
              render: (_: unknown, row) => (
                <Typography.Text ellipsis={{ tooltip: row.credential.audit_identity }}>
                  {row.credential.audit_identity}
                </Typography.Text>
              ),
            },
            {
              title: t('admin.clients.col.actions'),
              key: 'actions',
              width: 190,
              fixed: 'right',
              render: (_: unknown, row) => {
                const active = effectiveCredentialStatus(row.credential) === 'active';
                return (
                  <Space>
                    {row.role === 'next' && active && (
                      <Popconfirm
                        title={t('admin.credentials.cutover.confirm')}
                        onConfirm={() => mutate('cutover', kind, row.credential)}
                      >
                        <Button size="small" disabled={busy != null}>
                          {t('admin.credentials.cutover')}
                        </Button>
                      </Popconfirm>
                    )}
                    {active && (
                      <Popconfirm
                        title={t('admin.credentials.revoke.confirm')}
                        onConfirm={() => mutate('revoke', kind, row.credential)}
                      >
                        <Button size="small" danger disabled={busy != null}>
                          {t('admin.credentials.revoke')}
                        </Button>
                      </Popconfirm>
                    )}
                  </Space>
                );
              },
            },
          ]}
        />
      </section>
    );
  };

  return (
    <>
      <Modal
        open
        width={980}
        title={t('admin.credentials.title', { clientId: client.client_id })}
        onCancel={onClose}
        footer={<Button type="primary" onClick={onClose}>{t('admin.secret.close')}</Button>}
      >
        {credentialSection('client-secret')}
        {credentialSection('registration-token')}
      </Modal>
      <Modal
        open={rotateKind != null}
        title={rotateKind ? t('admin.credentials.rotateTitle', {
          kind: t(`admin.credentials.kind.${rotateKind}`),
        }) : ''}
        okText={t('admin.credentials.rotate')}
        cancelText={t('admin.form.cancel')}
        confirmLoading={busy?.startsWith('rotate:')}
        onCancel={() => {
          setRotateKind(null);
          setRotationRequestId(null);
        }}
        onOk={() => { void rotate(); }}
      >
        <Alert
          type="warning"
          showIcon
          message={t('admin.credentials.rotateWarning')}
          style={{ marginBottom: 16 }}
        />
        <Form form={rotateForm} layout="vertical" requiredMark={false}>
          <Form.Item
            name="expires_in_days"
            label={t('admin.credentials.expiresInDays')}
            rules={[{ required: true }]}
          >
            <InputNumber min={1} max={730} precision={0} style={{ width: '100%' }} />
          </Form.Item>
          <Form.Item
            name="overlap_in_hours"
            label={t('admin.credentials.overlapInHours')}
            rules={[{ required: true }]}
          >
            <InputNumber min={1} max={168} precision={0} style={{ width: '100%' }} />
          </Form.Item>
        </Form>
      </Modal>
      {revealed && (
        <OneTimeValueModal
          title={t('admin.credentials.revealedTitle')}
          warning={t('admin.credentials.revealedWarning')}
          label={revealed.label}
          value={revealed.value}
          onClose={() => setRevealed(null)}
        />
      )}
    </>
  );
}

function InitialAccessTokensTab({ onUnauthorized }: { onUnauthorized: () => void }) {
  const { t } = useTranslation();
  const [tokens, setTokens] = useState<InitialAccessTokenView[]>([]);
  const [loading, setLoading] = useState(false);
  const [creating, setCreating] = useState(false);
  const [revealed, setRevealed] = useState<string | null>(null);
  const [form] = Form.useForm();

  const load = useCallback(async () => {
    setLoading(true);
    const { data, response } = await adminApi.GET('/admin/initial-access-tokens');
    setLoading(false);
    if (response.status === 401) return onUnauthorized();
    if (data) setTokens(data.tokens);
    else message.error(t('admin.error.load'));
  }, [onUnauthorized, t]);

  useEffect(() => { void load(); }, [load]);

  const create = async () => {
    const values = await form.validateFields();
    setLoading(true);
    const { data, response } = await adminApi.POST('/admin/initial-access-tokens', {
      body: {
        owner: values.owner.trim(),
        scopes: values.scopes.split(/\s+/).filter(Boolean),
        expires_in_seconds: values.expires_in_hours * 3_600,
        rate_limit_per_minute: values.rate_limit_per_minute,
        one_time: values.one_time,
      },
    });
    setLoading(false);
    if (response.status === 401) return onUnauthorized();
    if (!response.ok || !data) {
      message.error(t('admin.iat.createFailed'));
      return;
    }
    setCreating(false);
    form.resetFields();
    setRevealed(data.token);
    void load();
  };

  const revoke = async (token: InitialAccessTokenView) => {
    setLoading(true);
    const { response } = await adminApi.POST('/admin/initial-access-tokens/{token_id}/revoke', {
      params: { path: { token_id: token.token_id } },
      body: {
        credential_id: token.token_id,
        expected_version: token.version,
      },
    });
    setLoading(false);
    if (response.status === 401) return onUnauthorized();
    if (response.ok) {
      message.success(t('admin.iat.revokeOk'));
      void load();
    } else if (response.status === 409) {
      message.warning(t('admin.credentials.conflict'));
      void load();
    } else {
      message.error(t('admin.credentials.actionFailed'));
    }
  };

  return (
    <>
      <Space direction="vertical" size="middle" style={{ width: '100%' }}>
        <Space style={{ justifyContent: 'space-between', width: '100%' }} wrap>
          <div>
            <Typography.Title level={4} style={{ margin: 0 }}>{t('admin.iat.title')}</Typography.Title>
            <Typography.Text type="secondary">{t('admin.iat.subtitle')}</Typography.Text>
          </div>
          <Button type="primary" onClick={() => {
            form.setFieldsValue({
              scopes: 'dcr:register',
              expires_in_hours: 24,
              rate_limit_per_minute: 30,
              one_time: false,
            });
            setCreating(true);
          }}>
            {t('admin.iat.create')}
          </Button>
        </Space>
        <Table
          rowKey="token_id"
          loading={loading}
          dataSource={tokens}
          pagination={false}
          scroll={{ x: 1280 }}
          locale={{ emptyText: t('admin.iat.empty') }}
          columns={[
            {
              title: t('admin.iat.col.id'),
              dataIndex: 'token_id',
              width: 220,
              render: (value: string) => <Typography.Text code copyable>{value}</Typography.Text>,
            },
            { title: t('admin.iat.col.owner'), dataIndex: 'owner', width: 180 },
            {
              title: t('admin.iat.col.scopes'),
              dataIndex: 'scopes',
              width: 180,
              render: (scopes: string[]) => scopes.map((scope) => <Tag key={scope}>{scope}</Tag>),
            },
            {
              title: t('admin.credentials.col.status'),
              key: 'status',
              width: 110,
              render: (_: unknown, token: InitialAccessTokenView) => (
                <CredentialStatusTag credential={token} />
              ),
            },
            {
              title: t('admin.credentials.col.expires'),
              dataIndex: 'expires_at',
              width: 190,
              render: (value: number) => formatUtcTimestamp(value),
            },
            {
              title: t('admin.iat.col.policy'),
              key: 'policy',
              width: 190,
              render: (_: unknown, token: InitialAccessTokenView) => (
                <Typography.Text>
                  {t('admin.iat.rate', { count: token.rate_limit_per_minute })}
                  {token.one_time ? ` · ${t('admin.iat.oneTime')}` : ''}
                </Typography.Text>
              ),
            },
            {
              title: t('admin.credentials.col.audit'),
              dataIndex: 'audit_identity',
              width: 180,
              ellipsis: true,
            },
            {
              title: t('admin.clients.col.actions'),
              key: 'actions',
              width: 110,
              fixed: 'right',
              render: (_: unknown, token: InitialAccessTokenView) =>
                effectiveCredentialStatus(token) === 'active' ? (
                  <Popconfirm
                    title={t('admin.iat.revokeConfirm')}
                    onConfirm={() => revoke(token)}
                  >
                    <Button size="small" danger>{t('admin.credentials.revoke')}</Button>
                  </Popconfirm>
                ) : null,
            },
          ]}
        />
      </Space>
      <Modal
        open={creating}
        title={t('admin.iat.createTitle')}
        okText={t('admin.iat.create')}
        cancelText={t('admin.form.cancel')}
        confirmLoading={loading}
        onCancel={() => setCreating(false)}
        onOk={() => { void create(); }}
      >
        <Form form={form} layout="vertical" requiredMark={false}>
          <Form.Item name="owner" label={t('admin.iat.owner')} rules={[{ required: true, max: 256 }]}>
            <Input autoComplete="off" />
          </Form.Item>
          <Form.Item name="scopes" label={t('admin.iat.scopes')} rules={[{ required: true }]}>
            <Input placeholder="dcr:register" />
          </Form.Item>
          <Form.Item name="expires_in_hours" label={t('admin.iat.expiresInHours')} rules={[{ required: true }]}>
            <InputNumber min={1} max={720} precision={0} style={{ width: '100%' }} />
          </Form.Item>
          <Form.Item name="rate_limit_per_minute" label={t('admin.iat.rateLimit')} rules={[{ required: true }]}>
            <InputNumber min={1} max={600} precision={0} style={{ width: '100%' }} />
          </Form.Item>
          <Form.Item name="one_time" label={t('admin.iat.oneTime')}>
            <Switch />
          </Form.Item>
        </Form>
      </Modal>
      {revealed && (
        <OneTimeValueModal
          title={t('admin.iat.revealedTitle')}
          warning={t('admin.iat.revealedWarning')}
          label={t('admin.iat.token')}
          value={revealed}
          onClose={() => setRevealed(null)}
        />
      )}
    </>
  );
}

function OneTimeValueModal({
  title,
  warning,
  label,
  value,
  onClose,
}: {
  title: string;
  warning: string;
  label: string;
  value: string;
  onClose: () => void;
}) {
  const { t } = useTranslation();
  const copy = async () => {
    await navigator.clipboard.writeText(value);
    message.success(t('admin.secret.copied'));
  };
  return (
    <Modal open title={title} closable={false} maskClosable={false} footer={[
      <Button key="close" type="primary" onClick={onClose}>{t('admin.secret.close')}</Button>,
    ]}>
      <Alert type="warning" showIcon message={warning} style={{ marginBottom: 16 }} />
      <Descriptions column={1} size="small" bordered>
        <Descriptions.Item label={label}>
          <Typography.Text
            code
            copyable={{ text: value }}
            style={{ overflowWrap: 'anywhere', wordBreak: 'break-all' }}
          >
            {value}
          </Typography.Text>
        </Descriptions.Item>
      </Descriptions>
      <Button style={{ marginTop: 12 }} onClick={copy}>{t('admin.secret.copy')}</Button>
    </Modal>
  );
}

/** 注册/编辑表单(Modal)。注册成功若回 secret,交由父组件弹一次性 secret modal。 */
function ClientForm({
  target,
  authMethods,
  onClose,
  onDone,
  onUnauthorized,
}: {
  target: ClientView | 'new';
  authMethods: string[];
  onClose: () => void;
  onDone: (created: { clientId: string; secret: string } | null) => void;
  onUnauthorized: () => void;
}) {
  const { t } = useTranslation();
  const isNew = target === 'new';
  const existing = isNew ? null : target;
  const [form] = Form.useForm();
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [downgradeFields, setDowngradeFields] = useState<string[] | null>(null);
  const authMethod = Form.useWatch('token_endpoint_auth_method', form);
  const privateKeySource = Form.useWatch('private_key_source', form);

  const initial = {
    redirect_uris: (existing?.redirect_uris ?? []).join('\n'),
    token_endpoint_auth_method: existing?.token_endpoint_auth_method ?? 'none',
    private_key_source: existing?.jwks_uri ? 'uri' : 'inline',
    token_endpoint_auth_signing_alg: existing?.token_endpoint_auth_signing_alg ?? 'RS256',
    jwks_json: existing?.jwks ? JSON.stringify(existing.jwks, null, 2) : '',
    jwks_uri: existing?.jwks_uri ?? '',
    default_resource: existing?.default_resource ?? '',
    post_logout_redirect_uris: (existing?.post_logout_redirect_uris ?? []).join('\n'),
  };

  const lines = (s?: string) => (s ?? '').split('\n').map((x) => x.trim()).filter(Boolean);
  const parseJwks = (value?: string): RegisteredClientJwks | null => {
    try {
      const parsed: unknown = JSON.parse(value ?? '');
      if (
        !parsed
        || typeof parsed !== 'object'
        || !('keys' in parsed)
        || !Array.isArray(parsed.keys)
        || parsed.keys.length === 0
      ) return null;
      return parsed as RegisteredClientJwks;
    } catch {
      return null;
    }
  };

  const submit = async (confirmDowngrade: boolean) => {
    const values = form.getFieldsValue();
    setSubmitting(true);
    setError(null);
    const redirect_uris = lines(values.redirect_uris);
    const post_logout_redirect_uris = lines(values.post_logout_redirect_uris);
    const default_resource = values.default_resource?.trim() || null;
    const usesPrivateKey = values.token_endpoint_auth_method === 'private_key_jwt';
    const usesInlineJwks = usesPrivateKey && values.private_key_source === 'inline';
    const jwks = usesInlineJwks ? parseJwks(values.jwks_json) : null;
    if (usesInlineJwks && !jwks) {
      setSubmitting(false);
      setError(t('admin.form.privateKey.invalidJwks'));
      return;
    }
    const jwks_uri = usesPrivateKey && !usesInlineJwks ? values.jwks_uri?.trim() || null : null;
    const token_endpoint_auth_signing_alg = usesPrivateKey
      ? values.token_endpoint_auth_signing_alg
      : null;

    if (isNew) {
      const { data, response } = await adminApi.POST('/admin/clients', {
        body: {
          redirect_uris,
          token_endpoint_auth_method: values.token_endpoint_auth_method,
          jwks,
          jwks_uri,
          token_endpoint_auth_signing_alg,
          default_resource,
          post_logout_redirect_uris,
        },
      });
      setSubmitting(false);
      if (response.status === 401) return onUnauthorized();
      if (response.ok && data) {
        onDone(data.client_secret ? { clientId: data.client_id, secret: data.client_secret } : null);
      } else {
        setError(t('admin.error.load'));
      }
      return;
    }

    // 编辑 = PUT 全量替换(带 confirm_downgrade)。
    const { data, response, error: errBody } = await adminApi.PUT('/admin/clients/{client_id}', {
      params: { path: { client_id: existing!.client_id } },
      body: {
        redirect_uris,
        token_endpoint_auth_method: values.token_endpoint_auth_method,
        jwks,
        jwks_uri,
        token_endpoint_auth_signing_alg,
        default_resource,
        post_logout_redirect_uris,
        confirm_downgrade: confirmDowngrade,
      },
    });
    setSubmitting(false);
    if (response.status === 401) return onUnauthorized();
    if (response.status === 400 && errBody && typeof errBody === 'object' && 'downgraded_fields' in errBody) {
      setDowngradeFields((errBody as { downgraded_fields: string[] }).downgraded_fields);
      return;
    }
    // 编辑若切换 auth_method 进入 client_secret_*,后端铸造并回显新 secret 一次(spec 025 M3)。
    if (response.ok && data) {
      onDone(data.client_secret ? { clientId: existing!.client_id, secret: data.client_secret } : null);
    } else {
      setError(t('admin.error.load'));
    }
  };

  return (
    <>
      <Modal
        open
        title={isNew ? t('admin.form.register.title') : t('admin.form.edit.title')}
        onCancel={onClose}
        okText={t('admin.form.submit')}
        cancelText={t('admin.form.cancel')}
        confirmLoading={submitting}
        onOk={() => form.submit()}
      >
        <Form form={form} layout="vertical" initialValues={initial} onFinish={() => submit(false)} requiredMark={false}>
          {error && <Form.Item><Alert type="error" showIcon message={error} /></Form.Item>}
          <Form.Item name="redirect_uris" label={t('admin.form.redirects')} rules={[{ required: true }]}>
            <Input.TextArea rows={3} placeholder="https://app.example.com/callback" />
          </Form.Item>
          <Form.Item name="token_endpoint_auth_method" label={t('admin.form.authMethod')}>
            <Select
              options={authMethods.map((method) => ({
                value: method,
                label: method === 'none' ? 'none (public + PKCE)' : method,
              }))}
            />
          </Form.Item>
          {authMethod === 'private_key_jwt' && (
            <>
              <Form.Item name="private_key_source" label={t('admin.form.privateKey.source')}>
                <Segmented
                  block
                  options={[
                    { label: t('admin.form.privateKey.inline'), value: 'inline' },
                    { label: t('admin.form.privateKey.uri'), value: 'uri' },
                  ]}
                />
              </Form.Item>
              <Form.Item
                name="token_endpoint_auth_signing_alg"
                label={t('admin.form.privateKey.alg')}
                rules={[{ required: true }]}
              >
                <Segmented block options={['RS256', 'ES256']} />
              </Form.Item>
              {privateKeySource === 'inline' ? (
                <Form.Item
                  name="jwks_json"
                  label={t('admin.form.privateKey.jwks')}
                  rules={[{
                    validator: (_, value) => parseJwks(value)
                      ? Promise.resolve()
                      : Promise.reject(new Error(t('admin.form.privateKey.invalidJwks'))),
                  }]}
                >
                  <Input.TextArea
                    autoSize={{ minRows: 6, maxRows: 12 }}
                    placeholder={'{\n  "keys": []\n}'}
                  />
                </Form.Item>
              ) : (
                <Form.Item
                  name="jwks_uri"
                  label={t('admin.form.privateKey.jwksUri')}
                  rules={[
                    { required: true },
                    {
                      validator: (_, value) => {
                        try {
                          return new URL(value).protocol === 'https:'
                            ? Promise.resolve()
                            : Promise.reject(new Error(t('admin.form.privateKey.invalidUri')));
                        } catch {
                          return Promise.reject(new Error(t('admin.form.privateKey.invalidUri')));
                        }
                      },
                    },
                  ]}
                >
                  <Input placeholder="https://client.example.com/jwks.json" />
                </Form.Item>
              )}
            </>
          )}
          <Form.Item name="default_resource" label={t('admin.form.resource')}>
            <Input placeholder="https://mcp.example.com" />
          </Form.Item>
          <Form.Item name="post_logout_redirect_uris" label={t('admin.form.postLogout')}>
            <Input.TextArea rows={2} placeholder="https://app.example.com/after-logout" />
          </Form.Item>
        </Form>
      </Modal>
      {/* C4.7 降级二次确认 */}
      <Modal
        open={!!downgradeFields}
        title={t('admin.form.downgrade.title')}
        okText={t('admin.form.downgrade.ok')}
        cancelText={t('admin.form.cancel')}
        okButtonProps={{ danger: true }}
        confirmLoading={submitting}
        onCancel={() => setDowngradeFields(null)}
        onOk={() => { setDowngradeFields(null); void submit(true); }}
      >
        <Alert
          type="warning"
          showIcon
          message={t('admin.form.downgrade.body', { fields: (downgradeFields ?? []).join(', ') })}
        />
      </Modal>
    </>
  );
}

/** 注册成功后一次性显示 client_secret(H5:仅此一次,关闭不可找回)。 */
function SecretModal({
  data,
  onClose,
}: {
  data: { clientId: string; secret: string };
  onClose: () => void;
}) {
  const { t } = useTranslation();
  const copy = async (v: string) => {
    await navigator.clipboard.writeText(v);
    message.success(t('admin.secret.copied'));
  };
  return (
    <Modal open title={t('admin.secret.title')} onCancel={onClose} footer={[
      <Button key="close" type="primary" onClick={onClose}>{t('admin.secret.close')}</Button>,
    ]}>
      <Alert type="warning" showIcon message={t('admin.secret.warn')} style={{ marginBottom: 16 }} />
      <Descriptions column={1} size="small" bordered>
        <Descriptions.Item label={t('admin.secret.clientId')}>
          <Typography.Text code copyable>{data.clientId}</Typography.Text>
        </Descriptions.Item>
        <Descriptions.Item label={t('admin.secret.secret')}>
          <Space>
            <Typography.Text code style={{ overflowWrap: 'anywhere', wordBreak: 'break-all' }}>
              {data.secret}
            </Typography.Text>
            <Button size="small" onClick={() => copy(data.secret)}>{t('admin.secret.copy')}</Button>
          </Space>
        </Descriptions.Item>
      </Descriptions>
    </Modal>
  );
}
