import { Layout as AntLayout, Button, Card, Typography } from 'antd';
import { useTranslation } from 'react-i18next';
import { setLang } from './i18n';
import type { ReactNode } from 'react';

const { Header, Content, Footer } = AntLayout;

/**
 * 企业级外壳:居中卡片 + 语言切换 + 品牌。所有交互页共用。
 * `wide`:列表类页(如 /account 授权管理)用更宽卡片;默认窄卡片(表单类页)。
 */
export function Layout({ children, wide }: { children: ReactNode; wide?: boolean }) {
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
          {t('app.name')}
        </Typography.Text>
        <Button size="small" onClick={toggle} ghost>
          {t('lang.switch')}
        </Button>
      </Header>
      <Content
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          padding: '48px 16px',
        }}
      >
        <Card
          style={{
            width: '100%',
            maxWidth: wide ? 720 : 420,
            boxShadow: '0 4px 24px rgba(0,0,0,0.08)',
          }}
        >
          {children}
        </Card>
      </Content>
      <Footer style={{ textAlign: 'center', color: '#8c8c8c' }}>{t('footer.secured')}</Footer>
    </AntLayout>
  );
}
