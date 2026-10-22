import { useEffect, useState, type ReactNode } from 'react';
import { Button, ConfigProvider, Drawer, Grid, Layout, Tag, Typography } from 'antd';
import { GlobalOutlined, LogoutOutlined, MenuOutlined, SafetyOutlined } from '@ant-design/icons';
import { useTranslation } from 'react-i18next';
import { setLang } from './i18n';
import './AdminShell.css';

export type AdminPage = {
  key: string;
  label: string;
  icon: ReactNode;
  group?: string;
  children: ReactNode;
};

type Navigation = {
  pages: AdminPage[];
  activeKey: string;
  onChange: (key: string) => void;
};

function AdminNavigation({ pages, activeKey, onChange }: Navigation) {
  const { t } = useTranslation();
  return (
    <nav aria-label={t('admin.nav.label')} className="admin-navigation">
      <div
        role="tablist"
        aria-label={t('admin.nav.label')}
        aria-orientation="vertical"
        onKeyDown={(event) => {
          const tabs = Array.from(event.currentTarget.querySelectorAll<HTMLButtonElement>('[role="tab"]'));
          const index = tabs.indexOf(event.target as HTMLButtonElement);
          if (index < 0) return;
          let next: number;
          switch (event.key) {
            case 'ArrowDown': next = (index + 1) % tabs.length; break;
            case 'ArrowUp': next = (index + tabs.length - 1) % tabs.length; break;
            case 'Home': next = 0; break;
            case 'End': next = tabs.length - 1; break;
            default: return;
          }
          event.preventDefault();
          tabs[next].focus();
        }}
      >
        {pages.map((page, index) => (
          <div key={page.key} role="presentation">
            {page.group && page.group !== pages[index - 1]?.group && (
              <div className="admin-navigation-group">{page.group}</div>
            )}
            <button
              type="button"
              role="tab"
              id={`admin-tab-${page.key}`}
              aria-controls={`admin-panel-${page.key}`}
              aria-selected={page.key === activeKey}
              tabIndex={page.key === activeKey ? 0 : -1}
              data-node-key={page.key}
              onClick={() => onChange(page.key)}
            >
              <span aria-hidden="true">{page.icon}</span>
              {page.label}
            </button>
          </div>
        ))}
      </div>
    </nav>
  );
}

/** Preserve visited page state, including one-time invitation navigation guards. */
export function AdminPagePanel({ page, active }: { page: AdminPage; active: boolean }) {
  const [visited, setVisited] = useState(active);
  useEffect(() => {
    if (active) setVisited(true);
  }, [active]);
  return (
    <section
      id={`admin-panel-${page.key}`}
      role="tabpanel"
      aria-label={page.label}
      hidden={!active}
    >
      {(active || visited) && page.children}
    </section>
  );
}

export function AdminShell({
  children,
  navigation,
  onSignout,
  scope,
  tenantId,
}: {
  children: ReactNode;
  navigation?: Navigation;
  onSignout?: () => void | Promise<void>;
  scope?: 'tenant' | 'control';
  tenantId?: string;
}) {
  const { t, i18n } = useTranslation();
  const screens = Grid.useBreakpoint();
  const [menuOpen, setMenuOpen] = useState(false);
  const activePage = navigation?.pages.find((page) => page.key === navigation.activeKey);
  const brand = (
    <div className="admin-brand">
      <img src="/assets/favicon.svg" alt="" width={32} height={32} />
      <div><strong>{t('app.name')}</strong><span>{t('admin.title')}</span></div>
    </div>
  );
  const nav = navigation && (
    <AdminNavigation {...navigation} onChange={(key) => {
      if (key !== navigation.activeKey) navigation.onChange(key);
      setMenuOpen(false);
    }} />
  );
  return (
    <ConfigProvider theme={{
      token: {
        colorPrimary: '#244c73',
        colorPrimaryBg: '#eaf0f7',
        colorInfo: '#244c73',
        colorInfoBg: '#edf3f9',
        colorInfoBorder: '#d7e4f0',
        colorText: '#1c2d3e',
        colorTextSecondary: '#617386',
        colorBorder: '#dbe3ec',
        colorBgLayout: '#f5f7fa',
        borderRadius: 8,
        controlHeight: 36,
        fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", "Noto Sans SC", sans-serif',
      },
      components: {
        Table: { headerBg: '#f5f7fa', headerColor: '#617386', cellPaddingBlock: 16 },
        Tabs: { titleFontSize: 14 },
      },
    }}>
      <Layout className={`admin-workbench${navigation ? ' admin-workbench-connected' : ''}`}>
        {navigation && screens.lg && (
          <Layout.Sider width={232} theme="light" className="admin-sidebar">
            {brand}
            {nav}
            <div className="admin-sidebar-footer"><SafetyOutlined />{t('admin.scope.tenant')}</div>
          </Layout.Sider>
        )}
        <Layout className="admin-main">
          <Layout.Header className="admin-header">
            <div className="admin-header-context">
              {navigation && !screens.lg && (
                <Button
                  type="text"
                  icon={<MenuOutlined />}
                  aria-label={t('admin.nav.open')}
                  aria-expanded={menuOpen}
                  onClick={() => setMenuOpen(true)}
                />
              )}
              {!navigation && brand}
              {scope && (
                <div className="admin-context-label">
                  <Typography.Text type="secondary">{t(`admin.scope.${scope}`)}</Typography.Text>
                  {tenantId && <Tag>{tenantId}</Tag>}
                  {activePage && <><span aria-hidden="true">/</span><span>{activePage.label}</span></>}
                </div>
              )}
            </div>
            <div className="admin-header-actions">
              <Button
                type="text"
                icon={<GlobalOutlined />}
                onClick={() => setLang(i18n.language.startsWith('zh') ? 'en' : 'zh')}
              >{t('lang.switch')}</Button>
              {onSignout && (
                <Button type="text" icon={<LogoutOutlined />} onClick={onSignout}>
                  {t('admin.token.signout')}
                </Button>
              )}
            </div>
          </Layout.Header>
          <Layout.Content className="admin-content">{children}</Layout.Content>
          <Layout.Footer className="admin-footer">{t('footer.secured')}</Layout.Footer>
        </Layout>
        {navigation && !screens.lg && (
          <Drawer
            title={brand}
            placement="left"
            width={288}
            open={menuOpen}
            onClose={() => setMenuOpen(false)}
            rootClassName="admin-navigation-drawer"
            forceRender
          >
            {nav}
          </Drawer>
        )}
      </Layout>
    </ConfigProvider>
  );
}
