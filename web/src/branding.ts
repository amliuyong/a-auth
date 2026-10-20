import { useEffect, useState } from 'react';
import { api } from './api/client';
import type { components } from './api/schema';

export type BrandingSettings = components['schemas']['BrandingSettings'];

export const defaultBranding: BrandingSettings = { name: null, logo: 'none', primary: 'blue' };
export const brandingColors = { blue: '#155eef', teal: '#0f766e', violet: '#6d28d9' } as const;

export function parseBrandingSettings(value: unknown): BrandingSettings | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const raw = value as Record<string, unknown>;
  if (raw.name !== null && (typeof raw.name !== 'string' || !raw.name ||
    raw.name.trim() !== raw.name || Array.from(raw.name).length > 64 ||
    /[\u0000-\u001f\u007f-\u009f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/.test(raw.name))) return null;
  if (raw.logo !== 'none' && raw.logo !== 'shield' && raw.logo !== 'key') return null;
  if (raw.primary !== 'blue' && raw.primary !== 'teal' && raw.primary !== 'violet') return null;
  return { name: raw.name, logo: raw.logo, primary: raw.primary };
}

export function useBranding(enabled: boolean, override?: BrandingSettings): BrandingSettings {
  const [stored, setStored] = useState<BrandingSettings>(defaultBranding);
  useEffect(() => {
    if (!enabled || override !== undefined) return;
    let active = true;
    setStored(defaultBranding);
    void (async () => {
      try {
        const { data, response } = await api.GET('/ui/branding');
        const settings = response.ok && data?.status === 'ready' && data.version === 1 &&
          Number.isSafeInteger(data.revision) && data.revision >= 0
          ? parseBrandingSettings(data.settings) : null;
        if (active) setStored(settings ?? defaultBranding);
      } catch {
        // Presentation availability must not block the existing authentication.
        if (active) setStored(defaultBranding);
      }
    })();
    return () => { active = false; };
  }, [enabled, override]);
  if (!enabled) return defaultBranding;
  return override === undefined ? stored : parseBrandingSettings(override) ?? defaultBranding;
}
