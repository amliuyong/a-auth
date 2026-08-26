import { useEffect, useRef, useState } from 'react';
import { Alert, Button, Divider, Popconfirm, Space, Typography, message } from 'antd';
import { useTranslation } from 'react-i18next';
import { useBlocker } from 'react-router-dom';
import { api } from '../api/client';

function errorCode(value: unknown): string | undefined {
  if (typeof value !== 'object' || value === null || !('error' in value)) return undefined;
  return typeof value.error === 'string' ? value.error : undefined;
}

/**
 * 恢复码自助设置(spec 003 §2.3 / C9.3,P0.5 硬 gate)。嵌入 /account 页。
 *
 * 消费已就位、已部署、有测试的 `POST /recovery/generate`(show-once 明文恢复码;鉴权 = AS 登录会话
 * `__Host-` cookie,后端 401 未登录)。此前该端点无前端消费方——真实用户无从生成/保存恢复码,
 * P0.5 恢复 gate 名存实亡。本组件补齐"注册时下发、用户离线保存"的仪式(DESIGN §7 恢复方案①)。
 *
 * **show-once 安全仪式**(codes 明文仅此一次返回,不可再取;评审 codex CONFIRMED×2 收敛):
 * - **生成前必确认**:后端不暴露"用户是否已有码"(避免信息泄露),故 fail-safe——每次生成前
 *   都用 Popconfirm 警告"会使此前所有恢复码失效"(覆盖跨会话/跨设备已有旧码却无警告的场景)。
 * - 生成后醒目警告"只显示一次";提供复制 / 下载;
 * - **未保存离开守卫**:明文展示期间挂 beforeunload,防用户没存就刷新/关页(新码丢失且旧码已失效)。
 * - 必须显式点"我已保存"才收起明文。
 *
 * 未登录时后端返 401 → 本组件静默不渲染(父页 /account 已统一引导 /login)。
 *
 * **挂载稳定性(评审 Kiro MEDIUM)**:父页 MUST **始终挂载**本组件(不随 needLogin 条件卸载),
 * 由 `visible` prop 控制显隐。否则明文码在屏时,若父页因会话过期 unmount 本组件,明文码会随组件
 * 消失(且 beforeunload 守卫被 cleanup 解绑)——一条 show-once 丢失路径。这里做兜底:只要 `codes`
 * 非空(明文在屏)就 MUST 继续渲染,忽略 `visible=false`,保住未保存的码。
 */
export function RecoverySetup({
  visible = true,
  onSessionRevoked,
  onReauthenticationRequired,
}: {
  visible?: boolean;
  onSessionRevoked?: () => void;
  onReauthenticationRequired?: () => void;
}) {
  const { t } = useTranslation();
  const [codes, setCodes] = useState<string[] | null>(null);
  const [loading, setLoading] = useState(false);
  const [hasGenerated, setHasGenerated] = useState(false);
  const [unauthorized, setUnauthorized] = useState(false);
  const [reauthRequired, setReauthRequired] = useState(false);
  const generationStarted = useRef(false);
  // 已配置状态(GET /recovery/status):null=未知/加载中,否则 {configured, remaining}。
  // 用于闭环 UX——此前前端无从得知用户是否已设恢复,只能无条件显示"生成"按钮。
  const [status, setStatus] = useState<{ configured: boolean; remaining: number } | null>(null);
  const blocker = useBlocker(codes !== null);

  // 挂载即查当前用户是否已配置恢复码(仅查自己,零跨用户)。visible 时才查(未登录父页会引导)。
  useEffect(() => {
    if (!visible) return;
    let alive = true;
    void (async () => {
      try {
        const { data, response } = await api.GET('/recovery/status');
        if (!alive) return;
        if (response.status === 401 && !generationStarted.current) {
          setUnauthorized(true);
        } else if (response.ok && data) {
          setStatus({ configured: !!data.configured, remaining: data.remaining ?? 0 });
        }
      } catch {
        // status 查询失败不阻塞生成能力:保持 status=null(仅少展示"已配置"提示)。
      }
    })();
    return () => {
      alive = false;
    };
  }, [visible]);

  // 未保存守卫(评审 codex CONFIRMED#2):明文码在屏且未确认保存时,拦截刷新/关页/前进后退。
  // 明文后端不可再取,离开即永久丢失(且旧码已被本次生成失效)。
  useEffect(() => {
    if (!codes) return;
    const warn = (e: BeforeUnloadEvent) => {
      e.preventDefault();
      e.returnValue = '';
    };
    window.addEventListener('beforeunload', warn);
    return () => window.removeEventListener('beforeunload', warn);
  }, [codes]);

  useEffect(() => {
    if (blocker.state !== 'blocked') return;
    if (window.confirm(t('recoverySetup.leaveWarning'))) {
      blocker.proceed();
    } else {
      blocker.reset();
    }
  }, [blocker, t]);

  const generate = async () => {
    generationStarted.current = true;
    setUnauthorized(false);
    setLoading(true);
    try {
      const { data, error: responseError, response } = await api.POST('/recovery/generate', {});
      if (response.status === 401) {
        // 未登录:静默隐藏(父页负责引导登录)。
        setUnauthorized(true);
        onSessionRevoked?.();
      } else if (response.status === 403) {
        setReauthRequired(true);
        onReauthenticationRequired?.();
      } else if (
        response.status === 409 &&
        errorCode(responseError) === 'last_viable_factor'
      ) {
        void message.error(t('recoverySetup.lastFactor'));
      } else if (response.ok && data?.recovery_codes) {
        setUnauthorized(false);
        setReauthRequired(false);
        setCodes(data.recovery_codes);
        setHasGenerated(true);
        // 生成成功 → 本地反映"已配置、剩全量"(免再查一次;收起后仍显示已配置)。
        setStatus({ configured: true, remaining: data.recovery_codes.length });
        onSessionRevoked?.();
      } else {
        void message.error(t('error.generic'));
      }
    } catch (e) {
      void message.error(e instanceof TypeError ? t('error.network') : t('error.generic'));
    } finally {
      setLoading(false);
    }
  };

  const copy = async () => {
    if (!codes) return;
    try {
      await navigator.clipboard.writeText(codes.join('\n'));
      void message.success(t('recoverySetup.copied'));
    } catch {
      // 剪贴板不可用(权限拒绝/非安全上下文):明确报错(评审 codex PLAUSIBLE#3),
      // 提示用户改用下载或手抄——不能静默让用户误以为已保存。
      void message.error(t('recoverySetup.copyFailed'));
    }
  };

  const download = () => {
    if (!codes) return;
    const blob = new Blob([codes.join('\n') + '\n'], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'agent-auth-recovery-codes.txt';
    a.click();
    URL.revokeObjectURL(url);
  };

  // 未登录 → 不渲染(父页 /account 的 needLogin 分支统一引导)。show-once 明文优先级更高:
  // 迟到的 status 401 不能遮住已经返回且不可再次读取的恢复码。
  if (unauthorized && !codes) return null;
  // 父页请求隐藏(如会话过期)时,**若明文码仍在屏则拒绝隐藏**——保住未保存的 show-once 码
  // (评审 Kiro MEDIUM:防父级切 needLogin 卸载导致明文无警告消失)。
  if (!visible && !codes) return null;

  return (
    <section style={{ marginTop: 32 }} aria-labelledby="recovery-setup-title">
      <Divider />
      <Typography.Title id="recovery-setup-title" level={4}>
        {t('recoverySetup.title')}
      </Typography.Title>
      <Typography.Paragraph type="secondary">{t('recoverySetup.subtitle')}</Typography.Paragraph>

      {codes ? (
        <>
          <Alert
            type="warning"
            showIcon
            message={t('recoverySetup.shownOnce')}
            style={{ marginBottom: 12 }}
          />
          <pre
            data-testid="recovery-codes"
            style={{
              background: '#f5f5f5',
              padding: 12,
              borderRadius: 4,
              fontFamily: 'monospace',
              margin: 0,
              whiteSpace: 'pre-wrap',
              wordBreak: 'break-all',
            }}
          >
            {codes.join('\n')}
          </pre>
          <Typography.Paragraph type="secondary" style={{ marginTop: 8, marginBottom: 12 }}>
            {t('recoverySetup.eachOneTime')}
          </Typography.Paragraph>
          <Space wrap>
            <Button onClick={() => void copy()}>{t('recoverySetup.copy')}</Button>
            <Button onClick={download}>{t('recoverySetup.download')}</Button>
            {/* 必须显式确认已保存才收起明文(防没存就离开);收起同时解除 beforeunload 守卫。 */}
            <Button type="primary" onClick={() => setCodes(null)}>
              {t('recoverySetup.savedAck')}
            </Button>
          </Space>
        </>
      ) : (
        <>
          {reauthRequired && (
            <Alert
              type="warning"
              showIcon
              message={t('account.credentials.reauthTitle')}
              action={
                <Button type="primary" href="/login?next=%2Faccount">
                  {t('account.credentials.reauthenticate')}
                </Button>
              }
              style={{ marginBottom: 12 }}
            />
          )}
          {/* 已配置状态提示(GET /recovery/status):闭环 UX——用户能看到自己是否已设恢复、剩几个。 */}
          {status?.configured && (
            <Alert
              type="success"
              showIcon
              message={t('recoverySetup.configured', { count: status.remaining })}
              style={{ marginBottom: 12 }}
            />
          )}
          {/* 生成前必确认(评审 codex CONFIRMED#1):fail-safe 警告会使此前所有恢复码失效
              (后端不暴露"是否已有码",故已配置 或 本会话已生成过 都按 regenerate 危险态警告)。 */}
          <Popconfirm
            title={t('recoverySetup.regenWarning')}
            okText={
              status?.configured || hasGenerated
                ? t('recoverySetup.regenerate')
                : t('recoverySetup.generate')
            }
            okButtonProps={{ danger: status?.configured || hasGenerated }}
            onConfirm={() => void generate()}
          >
            <Button type="primary" loading={loading} disabled={reauthRequired}>
              {loading
                ? t('recoverySetup.generating')
                : status?.configured || hasGenerated
                  ? t('recoverySetup.regenerate')
                  : t('recoverySetup.generate')}
            </Button>
          </Popconfirm>
        </>
      )}
    </section>
  );
}
