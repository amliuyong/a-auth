export function passwordRule(messageText: string) {
  return {
    validator: (_: unknown, value?: string) => {
      const bytes = new TextEncoder().encode(value ?? '').length;
      return bytes >= 12 && bytes <= 128
        ? Promise.resolve()
        : Promise.reject(new Error(messageText));
    },
  };
}
