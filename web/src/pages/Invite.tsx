import { Alert, Button, Result, Typography } from 'antd';
import { useLayoutEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { api } from '../api/client';
import { Layout } from '../Layout';

function tokenFromFragment(): string | null {
  const fragment = window.location.hash.startsWith('#')
    ? window.location.hash.slice(1)
    : window.location.hash;
  return new URLSearchParams(fragment).get('token');
}

export function Invite() {
  const { t } = useTranslation();
  const [token] = useState(tokenFromFragment);
  const [state, setState] = useState<'idle' | 'submitting' | 'error'>(
    token ? 'idle' : 'error',
  );

  useLayoutEffect(() => {
    if (window.location.hash) {
      window.history.replaceState(
        window.history.state,
        '',
        `${window.location.pathname}${window.location.search}`,
      );
    }
  }, []);

  const accept = async () => {
    if (!token || state === 'submitting') return;
    setState('submitting');
    try {
      const { data, response } = await api.POST('/login/invitation', {
        body: { token },
      });
      if (response.ok && data?.authenticated && data.redirect_to === '/account') {
        window.location.replace('/account');
        return;
      }
    } catch {
      // Preserve the in-memory token for failures known to precede consumption.
      // An ambiguous failure after commit remains fail-closed on retry.
    }
    setState('error');
  };

  return (
    <Layout>
      <Typography.Title level={3}>{t('invite.title')}</Typography.Title>
      {state === 'error' ? (
        <Result
          status="error"
          title={t('invite.invalid')}
          extra={token ? (
            <Button type="primary" onClick={() => void accept()}>
              {t('invite.retry')}
            </Button>
          ) : undefined}
        />
      ) : (
        <>
          <Alert
            type="info"
            showIcon
            message={t('invite.ready')}
            style={{ marginBottom: 20 }}
          />
          <Button
            type="primary"
            block
            size="large"
            disabled={state === 'submitting'}
            loading={state === 'submitting'}
            onClick={() => void accept()}
          >
            {t('invite.accept')}
          </Button>
        </>
      )}
    </Layout>
  );
}
