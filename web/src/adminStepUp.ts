function challengeParam(challenge: string, name: string): string | null {
  const match = challenge.match(
    new RegExp(`(?:^|[,\\s])${name}=(?:"([^"]*)"|([^,\\s]+))`, 'i'),
  );
  return match?.[1] ?? match?.[2] ?? null;
}

export function adminStepUpPath(challenge: string | null): string | null {
  if (
    !challenge ||
    !/^Bearer\b/i.test(challenge) ||
    challengeParam(challenge, 'error') !== 'insufficient_user_authentication'
  ) {
    return null;
  }
  const acrValues = challengeParam(challenge, 'acr_values');
  const maxAge = challengeParam(challenge, 'max_age');
  if (!acrValues && !maxAge) return null;

  const params = new URLSearchParams();
  if (acrValues) params.set('acr_values', acrValues);
  if (maxAge) params.set('max_age', maxAge);
  return `/admin/sso/start?${params.toString()}`;
}
