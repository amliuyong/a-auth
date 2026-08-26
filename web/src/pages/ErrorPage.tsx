import { Alert, Typography } from 'antd';
import { useTranslation } from 'react-i18next';
import { useSearchParams } from 'react-router-dom';
import { Layout } from '../Layout';

/** 错误页(OAuth error 回显)。path = /error?error=..&error_description=..,可 bookmark。 */
export function ErrorPage() {
  const { t } = useTranslation();
  const [params] = useSearchParams();
  const desc = params.get('error_description') ?? t('error.generic');
  const code = params.get('error');

  return (
    <Layout>
      <Typography.Title level={3}>{t('error.title')}</Typography.Title>
      <Alert
        type="error"
        showIcon
        message={code ?? 'error'}
        description={desc}
      />
    </Layout>
  );
}
