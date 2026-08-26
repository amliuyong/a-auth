import { useCallback, useEffect, useState } from 'react';
import {
  Alert,
  Button,
  Divider,
  Empty,
  Form,
  Input,
  List,
  Popconfirm,
  Space,
  Spin,
  Tag,
  Typography,
  message,
} from 'antd';
import { useTranslation } from 'react-i18next';
import type { components } from '../api/schema';
import { api } from '../api/client';
import { passwordRule } from '../passwordPolicy';
import { PasskeySetup } from './PasskeySetup';

type CredentialSummary = components['schemas']['AccountCredentialSummary'];
type AccountPasskey = components['schemas']['AccountPasskeyView'];

type Props = {
  visible: boolean;
  onSessionRevoked: () => void;
};

function errorCode(value: unknown): string | undefined {
  if (typeof value !== 'object' || value === null || !('error' in value)) return undefined;
  return typeof value.error === 'string' ? value.error : undefined;
}

export function AccountCredentials({ visible, onSessionRevoked }: Props) {
  const { t, i18n } = useTranslation();
  const [summary, setSummary] = useState<CredentialSummary | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [reauthRequired, setReauthRequired] = useState(false);
  const [editing, setEditing] = useState<string | null>(null);
  const [passkeyName, setPasskeyName] = useState('');
  const [busy, setBusy] = useState<string | null>(null);
  const [passwordForm] = Form.useForm();

  const load = useCallback(async () => {
    if (!visible) return;
    setLoading(true);
    setError(null);
    try {
      const { data, response } = await api.GET('/account/credentials');
      if (response.status === 401) {
        onSessionRevoked();
      } else if (response.ok && data) {
        setSummary(data);
        setReauthRequired(!data.reauthenticated);
      } else {
        setError(t('account.credentials.loadFailed'));
      }
    } catch (cause) {
      setError(cause instanceof TypeError ? t('error.network') : t('error.generic'));
    } finally {
      setLoading(false);
    }
  }, [onSessionRevoked, t, visible]);

  useEffect(() => {
    void load();
  }, [load]);

  const handleAuthFailure = (status: number) => {
    if (status === 401) {
      onSessionRevoked();
      return true;
    }
    if (status === 403) {
      setReauthRequired(true);
      return true;
    }
    return false;
  };

  const rename = async (passkey: AccountPasskey) => {
    const name = passkeyName.trim();
    if (!name) return;
    setBusy(`rename:${passkey.id}`);
    try {
      const { response } = await api.PATCH('/account/passkeys/{passkey_id}', {
        params: { path: { passkey_id: passkey.id } },
        body: { name },
      });
      if (handleAuthFailure(response.status)) return;
      if (response.ok) {
        setEditing(null);
        setPasskeyName('');
        void message.success(t('account.credentials.passkeys.renameOk'));
        await load();
      } else {
        void message.error(t('account.credentials.passkeys.renameFailed'));
      }
    } catch (cause) {
      void message.error(cause instanceof TypeError ? t('error.network') : t('error.generic'));
    } finally {
      setBusy(null);
    }
  };

  const remove = async (passkey: AccountPasskey) => {
    setBusy(`delete:${passkey.id}`);
    try {
      const { error: responseError, response } = await api.DELETE(
        '/account/passkeys/{passkey_id}',
        {
        params: { path: { passkey_id: passkey.id } },
        },
      );
      if (handleAuthFailure(response.status)) return;
      if (response.ok) {
        void message.success(t('account.credentials.passkeys.deleteOk'));
        onSessionRevoked();
      } else if (response.status === 409) {
        void message.error(
          errorCode(responseError) === 'last_viable_factor'
            ? t('account.credentials.passkeys.lastFactor')
            : t('account.credentials.conflict'),
        );
        await load();
      } else {
        void message.error(t('account.credentials.passkeys.deleteFailed'));
      }
    } catch (cause) {
      void message.error(cause instanceof TypeError ? t('error.network') : t('error.generic'));
    } finally {
      setBusy(null);
    }
  };

  const setPassword = async (values: { newPassword: string }) => {
    setBusy('password');
    try {
      const { response } = await api.PUT('/account/password', {
        body: { new_password: values.newPassword },
      });
      if (handleAuthFailure(response.status)) return;
      if (response.ok) {
        passwordForm.resetFields();
        void message.success(t('account.credentials.password.saved'));
        onSessionRevoked();
      } else if (response.status === 400) {
        void message.error(t('account.credentials.password.invalid'));
      } else if (response.status === 409) {
        void message.error(t('account.credentials.conflict'));
        await load();
      } else {
        void message.error(t('account.credentials.password.failed'));
      }
    } catch (cause) {
      void message.error(cause instanceof TypeError ? t('error.network') : t('error.generic'));
    } finally {
      setBusy(null);
    }
  };

  if (!visible) return null;

  const needsReauth = reauthRequired || summary?.reauthenticated === false;
  const hasReplacement =
    summary?.password_status === 'active' || summary?.recovery_configured === true;
  const blocksLastPasskey = (summary?.passkeys.length ?? 0) <= 1 && !hasReplacement;
  const dateFormatter = new Intl.DateTimeFormat(
    i18n.language.startsWith('zh') ? 'zh-CN' : 'en-US',
    { dateStyle: 'medium' },
  );

  return (
    <section style={{ marginTop: 32 }} aria-labelledby="account-credentials-title">
      <Divider />
      <Typography.Title id="account-credentials-title" level={4}>
        {t('account.credentials.title')}
      </Typography.Title>
      <Typography.Paragraph type="secondary">
        {t('account.credentials.subtitle')}
      </Typography.Paragraph>

      {needsReauth && (
        <Alert
          type="warning"
          showIcon
          message={t('account.credentials.reauthTitle')}
          description={t('account.credentials.reauthDescription')}
          action={
            <Button type="primary" href="/login?next=%2Faccount">
              {t('account.credentials.reauthenticate')}
            </Button>
          }
          style={{ marginBottom: 16 }}
        />
      )}
      {error && <Alert type="error" showIcon message={error} style={{ marginBottom: 16 }} />}

      {loading && !summary ? (
        <div style={{ textAlign: 'center', padding: 24 }}>
          <Spin />
        </div>
      ) : summary ? (
        <>
          <Typography.Title level={5}>{t('account.credentials.passkeys.title')}</Typography.Title>
          {summary.passkeys.length === 0 ? (
            <Empty
              image={Empty.PRESENTED_IMAGE_SIMPLE}
              description={t('account.credentials.passkeys.empty')}
            />
          ) : (
            <List
              dataSource={summary.passkeys}
              rowKey={(passkey) => passkey.id}
              renderItem={(passkey) => {
                const isEditing = editing === passkey.id;
                return (
                  <List.Item
                    actions={
                      isEditing
                        ? [
                            <Button
                              key="save"
                              type="primary"
                              size="small"
                              loading={busy === `rename:${passkey.id}`}
                              disabled={!passkeyName.trim()}
                              onClick={() => void rename(passkey)}
                            >
                              {t('account.credentials.passkeys.save')}
                            </Button>,
                            <Button
                              key="cancel"
                              size="small"
                              onClick={() => {
                                setEditing(null);
                                setPasskeyName('');
                              }}
                            >
                              {t('account.credentials.passkeys.cancel')}
                            </Button>,
                          ]
                        : [
                            <Button
                              key="rename"
                              size="small"
                              disabled={needsReauth}
                              onClick={() => {
                                setEditing(passkey.id);
                                setPasskeyName(passkey.name);
                              }}
                            >
                              {t('account.credentials.passkeys.rename')}
                            </Button>,
                            <Popconfirm
                              key="delete"
                              title={t('account.credentials.passkeys.deleteConfirm')}
                              okText={t('account.credentials.passkeys.delete')}
                              okButtonProps={{ danger: true }}
                              disabled={needsReauth || blocksLastPasskey}
                              onConfirm={() => void remove(passkey)}
                            >
                              <Button
                                danger
                                size="small"
                                disabled={needsReauth || blocksLastPasskey}
                                loading={busy === `delete:${passkey.id}`}
                              >
                                {t('account.credentials.passkeys.delete')}
                              </Button>
                            </Popconfirm>,
                          ]
                    }
                  >
                    <List.Item.Meta
                      title={
                        isEditing ? (
                          <Input
                            value={passkeyName}
                            maxLength={64}
                            aria-label={t('account.credentials.passkeys.name')}
                            onChange={(event) => setPasskeyName(event.target.value)}
                            onPressEnter={() => void rename(passkey)}
                          />
                        ) : (
                          <Typography.Text strong>{passkey.name}</Typography.Text>
                        )
                      }
                      description={
                        passkey.created_at
                          ? t('account.credentials.passkeys.created', {
                              date: dateFormatter.format(new Date(passkey.created_at * 1000)),
                            })
                          : t('account.credentials.passkeys.createdUnknown')
                      }
                    />
                  </List.Item>
                );
              }}
            />
          )}
          {blocksLastPasskey && summary.passkeys.length > 0 && (
            <Alert
              type="info"
              showIcon
              message={t('account.credentials.passkeys.lastFactor')}
              style={{ marginTop: 12 }}
            />
          )}

          <PasskeySetup
            visible={!needsReauth}
            knownStatus={{
              configured: summary.passkeys.length > 0,
              count: summary.passkeys.length,
            }}
            onRegistered={() => void load()}
            onReauthenticationRequired={() => setReauthRequired(true)}
          />

          <Divider />
          <Space align="center" wrap>
            <Typography.Title level={5} style={{ margin: 0 }}>
              {t('account.credentials.password.title')}
            </Typography.Title>
            <Tag color={summary.password_status === 'active' ? 'green' : 'default'}>
              {t(`account.credentials.password.status.${summary.password_status}`)}
            </Tag>
          </Space>
          {summary.password_supported && summary.password_status !== 'change_required' ? (
            <Form
              form={passwordForm}
              layout="vertical"
              requiredMark={false}
              onFinish={(values) => void setPassword(values)}
              style={{ marginTop: 16, maxWidth: 440 }}
            >
              <Form.Item
                name="newPassword"
                label={t('account.credentials.password.new')}
                rules={[
                  { required: true, message: t('account.credentials.password.required') },
                  passwordRule(t('login.passwordPolicy')),
                ]}
              >
                <Input.Password autoComplete="new-password" />
              </Form.Item>
              <Form.Item
                name="confirmPassword"
                label={t('account.credentials.password.confirm')}
                dependencies={['newPassword']}
                rules={[
                  { required: true, message: t('account.credentials.password.confirmRequired') },
                  ({ getFieldValue }) => ({
                    validator(_, value) {
                      return !value || getFieldValue('newPassword') === value
                        ? Promise.resolve()
                        : Promise.reject(
                            new Error(t('account.credentials.password.mismatch')),
                          );
                    },
                  }),
                ]}
              >
                <Input.Password autoComplete="new-password" />
              </Form.Item>
              <Button
                type="primary"
                htmlType="submit"
                loading={busy === 'password'}
                disabled={needsReauth}
              >
                {summary.password_status === 'active'
                  ? t('account.credentials.password.rotate')
                  : t('account.credentials.password.enroll')}
              </Button>
            </Form>
          ) : (
            <Typography.Paragraph type="secondary" style={{ marginTop: 12 }}>
              {summary.password_status === 'change_required'
                ? t('account.credentials.password.changeRequired')
                : t('account.credentials.password.unsupported')}
            </Typography.Paragraph>
          )}
        </>
      ) : null}
    </section>
  );
}
