import { Layout as AntLayout, Button, Card, ConfigProvider, Typography } from 'antd';
import { useTranslation } from 'react-i18next';
import { setLang } from './i18n';
import type { ReactNode } from 'react';
import { brandingColors, useBranding, type BrandingSettings } from './branding';
import './branding.css';

const { Header, Content, Footer } = AntLayout;

/**
 * 企业级外壳:居中卡片 + 语言切换 + 品牌。所有交互页共用。
 * `wide`:列表类页(如 /account 授权管理)用更宽卡片;默认窄卡片(表单类页)。
 */
export function Layout({ children, wide, branded = false, branding, preview = false }: {
  children: ReactNode; wide?: boolean; branded?: boolean; branding?: BrandingSettings; preview?: boolean;
}) {
  const { t, i18n } = useTranslation();
  const toggle = () => {
    if (!preview) setLang(i18n.language.startsWith('zh') ? 'en' : 'zh');
  };
  const settings = useBranding(branded, branding);
  const primary = brandingColors[settings.primary];

  return (
    <ConfigProvider theme={branded ? { token: {
      colorPrimary: primary, colorTextSecondary: '#595959',
    } } : undefined}>
    <AntLayout className={branded ? 'auth-presentation' : undefined}
      style={{ minHeight: preview ? undefined : '100vh', background: '#f0f2f5' }}>
      <Header
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          gap: branded ? 16 : undefined,
          height: branded ? 'auto' : undefined,
          minHeight: branded ? 64 : undefined,
          background: branded ? primary : '#001529',
          padding: '0 24px',
        }}
      >
        <Typography.Text strong style={{
          color: '#fff', fontSize: 18, lineHeight: branded ? 1.5 : undefined,
          overflowWrap: branded ? 'anywhere' : undefined,
          flex: branded ? 1 : undefined, minWidth: branded ? 0 : undefined,
          padding: branded ? '12px 0' : undefined,
        }}>
          {branded && settings.logo !== 'none' && <svg
            aria-hidden="true" width="24" height="24" viewBox="0 0 24 24"
            fill="none" stroke="currentColor" strokeWidth="2"
            style={{ verticalAlign: 'middle', marginRight: 8 }}
          >
            {settings.logo === 'shield'
              ? <path d="M12 2 3 6v6c0 5 9 10 9 10s9-5 9-10V6L12 2Zm-5 10 3 3 7-7" />
              : <path d="M14 10a5 5 0 1 0-4 4l3 3h3v3h4v-4l-6-6Z" />}
          </svg>}
          {branded ? settings.name ?? t('app.name') : t('app.name')}
        </Typography.Text>
        <Button size="small" onClick={toggle} disabled={preview} ghost>
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
      <Footer style={{ textAlign: 'center', color: branded ? '#595959' : '#8c8c8c' }}>
        {t('footer.secured')}
      </Footer>
    </AntLayout>
    </ConfigProvider>
  );
}
