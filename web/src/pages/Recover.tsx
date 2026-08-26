import { useRef, useState } from 'react';
import { Alert, Button, Form, Input, Space, Typography } from 'antd';
import { useTranslation } from 'react-i18next';
import { Layout } from '../Layout';
import { api } from '../api/client';

function newRecoveryOperationId(): string {
  const bytes = window.crypto.getRandomValues(new Uint8Array(32));
  const encoded = window.btoa(String.fromCharCode(...bytes));
  return encoded.replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
}

/**
 * 账户恢复页(C9.3,P0.5 硬 gate)。path = /recover,可 bookmark。
 *
 * 流程(决策见 crates/http/src/recover.rs):输入一次性恢复码 → POST /recovery/verify →
 * 验码消费 → 建会话登入(Set-Cookie)→ 引导绑新登录因子(next=bind_new_factor)。
 * 一次性:成功后码作废;失败限流(per-user 锁定 → 429)。类型由生成的 OpenAPI 契约约束。
 */
export function Recover() {
  const { t } = useTranslation();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [recovered, setRecovered] = useState(false);
  const pendingOperation = useRef<{ code: string; operationId: string } | null>(null);

  const onFinish = async (values: { code: string }) => {
    const code = values.code.trim();
    if (pendingOperation.current?.code !== code) {
      pendingOperation.current = { code, operationId: newRecoveryOperationId() };
    }
    const operationId = pendingOperation.current.operationId;
    setLoading(true);
    setError(null);
    try {
      const { data, response } = await api.POST('/recovery/verify', {
        body: { code, operation_id: operationId },
      });
      if (response.status === 429) {
        pendingOperation.current = null;
        setError(t('recover.locked'));
      } else if (data?.recovered) {
        pendingOperation.current = null;
        setRecovered(true);
      } else if (response.status === 400 || response.status === 403) {
        pendingOperation.current = null;
        // Terminal rejection: do not carry an operation into a later attempt.
        setError(response.status === 400 ? t('recover.invalid') : t('error.generic'));
      } else {
        // 503 and other ambiguous failures retain the operation ID for retry.
        setError(t('error.generic'));
      }
    } catch (e) {
      setError(e instanceof TypeError ? t('error.network') : t('error.generic'));
    } finally {
      setLoading(false);
    }
  };

  return (
    <Layout>
      <Typography.Title level={3}>{t('recover.title')}</Typography.Title>
      <Typography.Paragraph type="secondary">{t('recover.subtitle')}</Typography.Paragraph>
      {recovered ? (
        <>
          <Alert type="success" showIcon message={t('recover.success')} style={{ marginBottom: 16 }} />
          {/* 恢复后引导:此前是静态警告无动作(死胡同)——用户刚消费了一个一次性码、已登入,
              却无处可点。现给可点动作去 /account(本会话新增恢复码管理区:重新生成消费掉的码、
              查剩余、管理授权)。闭合 bind_new_factor 引导。 */}
          <Alert
            type="warning"
            showIcon
            message={t('recover.bindFactor')}
            action={
              <Space>
                <Button type="primary" size="small" href="/account">
                  {t('recover.manageAccount')}
                </Button>
              </Space>
            }
          />
        </>
      ) : (
        <Form layout="vertical" onFinish={onFinish} requiredMark={false}>
          {error && (
            <Form.Item>
              <Alert type="error" showIcon message={error} />
            </Form.Item>
          )}
          <Form.Item name="code" label={t('recover.code')} rules={[{ required: true }]}>
            <Input size="large" autoComplete="one-time-code" placeholder="v1.…" />
          </Form.Item>
          <Button type="primary" htmlType="submit" size="large" block loading={loading}>
            {loading ? t('recover.recovering') : t('recover.submit')}
          </Button>
        </Form>
      )}
    </Layout>
  );
}
