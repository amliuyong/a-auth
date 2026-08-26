import { useCallback, useEffect, useState } from 'react';
import {
  Alert,
  Button,
  Divider,
  Empty,
  Grid,
  List,
  Popconfirm,
  Space,
  Spin,
  Tag,
  Typography,
  message,
} from 'antd';
import { useTranslation } from 'react-i18next';
import { useNavigate } from 'react-router-dom';
import { Layout } from '../Layout';
import { api } from '../api/client';
import { RecoverySetup } from './RecoverySetup';
import { AccountCredentials } from './AccountCredentials';

/**
 * 用户自助 Grant 管理页(spec 011 §5.1 / FAPI Grant Management,P2)。path = /account,可 bookmark。
 *
 * 展示**当前登录用户**已授权的应用(client + 逐 resource scopes + 状态 + 到期),支持一键吊销
 * (DELETE /grants/{id} → 级联吊销 refresh family + 删宽限缓存,C7.6b)。
 *
 * 鉴权 = AS 登录会话(magic-link 建的 `__Host-` session cookie);未登录 → 后端 401,页面引导去 /login。
 * page path `/account` 与动作 path `/grants`(API)分离——CloudFront 按 path 选 origin,SPA 页显式挂 S3、
 * `/grants` 落 default→API,避免同 path 冲突(spec 025 收敛,同 /consent↔/consent/decision)。
 */

type GrantView = {
  grant_id: string;
  client_id: string;
  resources: { resource: string; scopes: string[] }[];
  status: string;
  expires_at: number;
};

type LoginSessionView = {
  id: string;
  current: boolean;
  device: string;
  created_at: number;
  last_used_at: number;
  expires_at: number;
};

export function Account() {
  const { t, i18n } = useTranslation();
  const navigate = useNavigate();
  const screens = Grid.useBreakpoint();
  const [grants, setGrants] = useState<GrantView[] | null>(null);
  const [sessions, setSessions] = useState<LoginSessionView[] | null>(null);
  const [needLogin, setNeedLogin] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [revoking, setRevoking] = useState<string | null>(null);
  const [revokingOthers, setRevokingOthers] = useState(false);

  const load = useCallback(async () => {
    setError(null);
    setNeedLogin(false);
    try {
      const [grantResult, sessionResult] = await Promise.all([
        api.GET('/grants'),
        api.GET('/account/sessions'),
      ]);
      if (grantResult.response.status === 401 || sessionResult.response.status === 401) {
        setNeedLogin(true);
        setGrants([]);
        setSessions([]);
      } else if (
        (grantResult.response.ok || grantResult.response.status === 404) &&
        sessionResult.response.ok
      ) {
        setGrants(grantResult.response.ok ? ((grantResult.data as GrantView[]) ?? []) : []);
        setSessions((sessionResult.data as LoginSessionView[]) ?? []);
      } else {
        setError(t('error.generic'));
        setGrants([]);
        setSessions([]);
      }
    } catch (e) {
      setError(e instanceof TypeError ? t('error.network') : t('error.generic'));
      setGrants([]);
      setSessions([]);
    }
  }, [t]);

  useEffect(() => {
    void load();
  }, [load]);

  const revoke = async (grantId: string) => {
    setRevoking(grantId);
    try {
      const { response } = await api.DELETE('/grants/{grant_id}', {
        params: { path: { grant_id: grantId } },
      });
      if (response.status === 401) {
        setNeedLogin(true);
      } else if (response.ok) {
        void message.success(t('account.revoke.ok'));
        await load();
      } else {
        void message.error(t('error.generic'));
      }
    } catch (e) {
      void message.error(e instanceof TypeError ? t('error.network') : t('error.generic'));
    } finally {
      setRevoking(null);
    }
  };

  const revokeSession = async (session: LoginSessionView) => {
    setRevoking(session.id);
    try {
      const { response } = await api.DELETE('/account/sessions/{session_id}', {
        params: { path: { session_id: session.id } },
      });
      if (response.status === 401) {
        setNeedLogin(true);
      } else if (response.ok) {
        if (session.current) {
          setNeedLogin(true);
          setGrants([]);
          setSessions([]);
          void message.success(t('account.sessions.signedOut'));
        } else {
          void message.success(t('account.sessions.revokeOk'));
          await load();
        }
      } else {
        void message.error(t('error.generic'));
      }
    } catch (e) {
      void message.error(e instanceof TypeError ? t('error.network') : t('error.generic'));
    } finally {
      setRevoking(null);
    }
  };

  const revokeOtherSessions = async () => {
    setRevokingOthers(true);
    try {
      const { response } = await api.DELETE('/account/sessions');
      if (response.status === 401) {
        setNeedLogin(true);
      } else if (response.ok) {
        void message.success(t('account.sessions.revokeOthersOk'));
        await load();
      } else {
        void message.error(t('error.generic'));
      }
    } catch (e) {
      void message.error(e instanceof TypeError ? t('error.network') : t('error.generic'));
    } finally {
      setRevokingOthers(false);
    }
  };

  const statusTag = (status: string) => {
    const color = status === 'active' ? 'green' : status === 'revoked' ? 'red' : 'default';
    return <Tag color={color}>{t(`account.status.${status}`, status)}</Tag>;
  };

  // 到期时间:秒级 unix → 本地化日期(随 i18n 语言)。
  const fmtExpiry = (secs: number) =>
    new Intl.DateTimeFormat(i18n.language.startsWith('zh') ? 'zh-CN' : 'en-US', {
      dateStyle: 'medium',
    }).format(new Date(secs * 1000));

  const fmtDateTime = (secs: number) =>
    new Intl.DateTimeFormat(i18n.language.startsWith('zh') ? 'zh-CN' : 'en-US', {
      dateStyle: 'medium',
      timeStyle: 'short',
    }).format(new Date(secs * 1000));

  const loading = grants === null || sessions === null;
  const credentialSessionRevoked = useCallback(() => {
    setNeedLogin(true);
    setGrants([]);
    setSessions([]);
  }, []);

  return (
    <Layout wide>
      <Typography.Title level={3}>{t('account.title')}</Typography.Title>

      {error && <Alert type="error" showIcon message={error} style={{ marginBottom: 16 }} />}

      {needLogin ? (
        <Alert
          type="info"
          showIcon
          message={t('account.signin')}
          action={
            // 带 next=当前页,登录后回原页(后端 sanitize 同源相对路径,spec 003 P0.5)。
            <Button
              type="link"
              onClick={() =>
                navigate(
                  `/login?next=${encodeURIComponent(location.pathname + location.search)}`,
                )
              }
            >
              {t('account.signinLink')}
            </Button>
          }
        />
      ) : loading ? (
        <div style={{ textAlign: 'center', padding: 32 }}>
          <Spin />
        </div>
      ) : (
        <>
          <Space style={{ width: '100%', justifyContent: 'flex-end', marginBottom: 12 }}>
            <Button size="small" onClick={() => void load()}>
              {t('account.refresh')}
            </Button>
          </Space>
          <Space
            align="center"
            wrap
            style={{ width: '100%', justifyContent: 'space-between', marginBottom: 8 }}
          >
            <Typography.Title level={4} style={{ margin: 0 }}>
              {t('account.sessions.title')}
            </Typography.Title>
            <Popconfirm
              title={t('account.sessions.revokeOthersConfirm')}
              okText={t('account.sessions.revokeOthers')}
              okButtonProps={{ danger: true }}
              disabled={(sessions?.length ?? 0) <= 1}
              onConfirm={() => void revokeOtherSessions()}
            >
              <Button
                danger
                size="small"
                loading={revokingOthers}
                disabled={(sessions?.length ?? 0) <= 1}
              >
                {t('account.sessions.revokeOthers')}
              </Button>
            </Popconfirm>
          </Space>
          {sessions?.length === 0 ? (
            <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={t('account.sessions.empty')} />
          ) : (
            <List
              itemLayout={screens.sm ? 'horizontal' : 'vertical'}
              dataSource={sessions ?? []}
              rowKey={(session) => session.id}
              renderItem={(session) => (
                <List.Item
                  actions={[
                    <Popconfirm
                      key="revoke"
                      title={
                        session.current
                          ? t('account.sessions.signOutConfirm')
                          : t('account.sessions.revokeConfirm')
                      }
                      okText={
                        session.current
                          ? t('account.sessions.signOut')
                          : t('account.sessions.revoke')
                      }
                      okButtonProps={{ danger: true }}
                      onConfirm={() => void revokeSession(session)}
                    >
                      <Button danger size="small" loading={revoking === session.id}>
                        {session.current
                          ? t('account.sessions.signOut')
                          : t('account.sessions.revoke')}
                      </Button>
                    </Popconfirm>,
                  ]}
                >
                  <List.Item.Meta
                    title={
                      <Space wrap>
                        <Typography.Text strong style={{ overflowWrap: 'anywhere' }}>
                          {session.device}
                        </Typography.Text>
                        {session.current && <Tag color="green">{t('account.sessions.current')}</Tag>}
                      </Space>
                    }
                    description={
                      <Space direction="vertical" size={0}>
                        <Typography.Text type="secondary">
                          {t('account.sessions.lastUsed')}: {fmtDateTime(session.last_used_at)}
                        </Typography.Text>
                        <Typography.Text type="secondary">
                          {t('account.sessions.created')}: {fmtDateTime(session.created_at)}
                        </Typography.Text>
                        <Typography.Text type="secondary">
                          {t('account.sessions.expires')}: {fmtDateTime(session.expires_at)}
                        </Typography.Text>
                      </Space>
                    }
                  />
                </List.Item>
              )}
            />
          )}

          <Divider />
          <Typography.Title level={4}>{t('account.grants.title')}</Typography.Title>
          {grants?.length === 0 ? (
            <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={t('account.empty')} />
          ) : (
          <List
            itemLayout="vertical"
            dataSource={grants ?? []}
            rowKey={(g) => g.grant_id}
            renderItem={(g) => (
              <List.Item
                actions={
                  g.status === 'active'
                    ? [
                        <Popconfirm
                          key="revoke"
                          title={t('account.revoke.confirm')}
                          okText={t('account.revoke')}
                          okButtonProps={{ danger: true }}
                          onConfirm={() => revoke(g.grant_id)}
                        >
                          <Button danger size="small" loading={revoking === g.grant_id}>
                            {t('account.revoke')}
                          </Button>
                        </Popconfirm>,
                      ]
                    : []
                }
              >
                <List.Item.Meta
                  title={
                    <Space>
                      <Typography.Text strong>{g.client_id}</Typography.Text>
                      {statusTag(g.status)}
                    </Space>
                  }
                  description={
                    <Typography.Text type="secondary">
                      {t('account.col.expires')}: {fmtExpiry(g.expires_at)}
                    </Typography.Text>
                  }
                />
                {g.resources.length > 0 ? (
                  g.resources.map((r) => (
                    <div key={r.resource} style={{ marginBottom: 6 }}>
                      <Typography.Text code>{r.resource}</Typography.Text>{' '}
                      {r.scopes.map((s) => (
                        <Tag color="blue" key={s}>
                          {s}
                        </Tag>
                      ))}
                    </div>
                  ))
                ) : (
                  <Typography.Text type="secondary">{t('account.noResources')}</Typography.Text>
                )}
              </List.Item>
            )}
          />
          )}
        </>
      )}

      {/* 恢复码自助设置(spec 003 §2.3 / C9.3,P0.5 gate):消费已部署的 POST /recovery/generate,
          补齐 show-once 恢复码注册仪式。**始终挂载**(不随 needLogin 卸载),由 visible 控制显隐——
          否则明文码在屏时父级切 needLogin 会 unmount 组件、明文无警告消失(评审 Kiro MEDIUM)。
          visible=登录态(未登录且未在加载时隐藏);组件内部若明文码在屏会拒绝隐藏兜底。 */}
      <AccountCredentials
        visible={!needLogin && !loading}
        onSessionRevoked={credentialSessionRevoked}
      />

      <RecoverySetup
        visible={!needLogin && !loading}
        onSessionRevoked={credentialSessionRevoked}
      />
    </Layout>
  );
}
