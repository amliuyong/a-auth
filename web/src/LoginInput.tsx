import { forwardRef, useState, type ComponentPropsWithoutRef, type CSSProperties } from 'react';
import { theme } from 'antd';
import { useTranslation } from 'react-i18next';
import './LoginInput.css';

type Props = Omit<ComponentPropsWithoutRef<'input'>, 'value' | 'defaultValue' | 'size'>;

// Keep the browser in charge of credential values. AntD's internally controlled
// input can restore a stale value when HtmlUnit misses React change events and
// asynchronous branding updates the theme. Native inputs retain edits on render.
export const LoginInput = forwardRef<HTMLInputElement, Props>(function LoginInput(
  { type, disabled, style, ...props }, ref,
) {
  const { token } = theme.useToken();
  const { t } = useTranslation();
  const [visible, setVisible] = useState(false);
  const password = type === 'password';
  const colors = {
    '--login-input-text': token.colorText,
    '--login-input-bg': token.colorBgContainer,
    '--login-input-border': token.colorBorder,
    '--login-input-primary': token.colorPrimary,
    '--login-input-error': token.colorError,
    '--login-input-disabled': token.colorBgContainerDisabled,
    '--login-input-placeholder': token.colorTextPlaceholder,
    '--login-input-radius': `${token.borderRadiusLG}px`,
  } as CSSProperties;

  return <span className="login-input" style={colors}
    data-invalid={Boolean(props['aria-invalid'] && props['aria-invalid'] !== 'false')}
    data-disabled={Boolean(disabled)}>
    <input {...props} ref={ref} disabled={disabled} style={style}
      type={password && visible ? 'text' : type} />
    {password && <button type="button" disabled={disabled} aria-pressed={visible}
      aria-label={t(visible ? 'login.hidePassword' : 'login.showPassword')}
      onMouseDown={(event) => event.preventDefault()}
      onClick={() => setVisible((value) => !value)}>
      <svg aria-hidden="true" width="16" height="16" viewBox="0 0 24 24"
        fill="none" stroke="currentColor" strokeWidth="2">
        <path d="M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7Z" />
        <circle cx="12" cy="12" r="3" />
        {!visible && <path d="m3 3 18 18" />}
      </svg>
    </button>}
  </span>;
});
