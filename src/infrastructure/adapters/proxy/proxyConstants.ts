declare const __PROXY_API_URL__: string | undefined;

export const PROXY_CONFIG = Object.freeze({
  BASE_URL: (typeof __PROXY_API_URL__ !== 'undefined' ? __PROXY_API_URL__ : null)
    ?? 'http://3.34.210.236:3000',
  TIMEOUT_MS: 10_000,
  MAX_RETRIES: 2,
  RETRY_BASE_DELAY_MS: 500,
  HEALTH_ENDPOINT: '/health',
  ANALYZE_ENDPOINT: '/analyze',
  HEALTH_CHECK_TIMEOUT_MS: 3_000,
});
