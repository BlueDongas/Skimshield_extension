/**
 * ============================================================================
 * 파일: injected.ts
 * ============================================================================
 *
 * [역할]
 * 웹페이지의 "메인 월드"에서 실행되어 네트워크 요청을 직접 인터셉트합니다.
 * 이 파일은 manifest.json에서 world: "MAIN"으로 설정되어 있습니다.
 *
 * [비유]
 * "잠입 요원"과 같습니다:
 * - 웹페이지 내부에 직접 들어가서
 * - fetch, XHR, sendBeacon을 모니터링하고
 * - 발견한 정보를 외부(콘텐츠 스크립트)로 전송
 *
 * [왜 메인 월드에서 실행해야 하는가?]
 *
 * Chrome 확장 프로그램의 세계:
 * ┌─────────────────────────────────────────────────────┐
 * │  웹페이지                                           │
 * │  ┌─────────────────────────────────────────────┐  │
 * │  │ 메인 월드 (웹페이지 JavaScript)              │  │
 * │  │  - fetch, XHR 등 네이티브 함수               │  │
 * │  │  - 웹페이지가 사용하는 모든 JS               │  │
 * │  │  ← injected.ts가 여기서 실행 ★              │  │
 * │  └─────────────────────────────────────────────┘  │
 * │  ┌─────────────────────────────────────────────┐  │
 * │  │ 격리된 세계 (콘텐츠 스크립트)                │  │
 * │  │  - 확장 프로그램의 content script            │  │
 * │  │  - 메인 월드와 분리됨                        │  │
 * │  │  - fetch 등을 직접 가로챌 수 없음            │  │
 * │  └─────────────────────────────────────────────┘  │
 * └─────────────────────────────────────────────────────┘
 *
 * [인터셉트 방식]
 * 원본 함수를 저장하고, 래퍼 함수로 교체합니다:
 * 1. 요청 정보를 window.postMessage로 콘텐츠 스크립트에 전송
 * 2. 원본 함수 호출하여 정상 동작 유지
 *
 * [중복 실행 방지]
 * window.__FJ_GUARD_INJECTED__ 플래그로 한 번만 실행되도록 보장
 *
 * [다른 파일과의 관계]
 * - PageInjector.ts: 이 파일이 보낸 메시지를 수신
 * - content/index.ts: PageInjector를 통해 데이터 처리
 * - manifest.json: 이 파일을 메인 월드에 주입하도록 설정
 *
 * [메시지 형식]
 * ```javascript
 * window.postMessage({
 *   type: '__FJ_GUARD_REQUEST__',
 *   payload: { type, url, method, body, timestamp }
 * }, '*');
 * ```
 * ============================================================================
 */

/* eslint-disable no-console */

(function() {
  'use strict';

  // 이미 주입되었는지 확인
  if ((window as Window & { __FJ_GUARD_INJECTED__?: boolean }).__FJ_GUARD_INJECTED__) {
    return;
  }
  (window as Window & { __FJ_GUARD_INJECTED__?: boolean }).__FJ_GUARD_INJECTED__ = true;

  // 원본 함수 저장
  const originalFetch = window.fetch;
  const originalXHROpen = XMLHttpRequest.prototype.open;
  const originalXHRSend = XMLHttpRequest.prototype.send;
  const originalSendBeacon = navigator.sendBeacon.bind(navigator);

  // 상대 URL을 절대 URL로 변환
  function toAbsoluteUrl(url: string): string {
    try {
      // 이미 절대 URL인 경우
      if (url.startsWith('http://') || url.startsWith('https://') || url.startsWith('//')) {
        return new URL(url, window.location.href).href;
      }
      // 상대 URL을 절대 URL로 변환
      return new URL(url, window.location.href).href;
    } catch {
      return url;
    }
  }

  // 요청을 시작한 외부 스크립트 URL 추출 (콜 스택 분석)
  function getInitiatorScript(): string | undefined {
    try {
      const stack = new Error().stack ?? '';
      const lines = stack.split('\n');
      for (const line of lines) {
        // 스택 라인에서 http(s):// URL 추출 (chrome-extension:// 제외)
        const match = line.match(/at (?:.*? \()?(https?:\/\/[^:)\s]+)/);
        if (match !== null && match[1] !== undefined) {
          return match[1];
        }
      }
      return undefined;
    } catch {
      return undefined;
    }
  }

  // 콘텐츠 스크립트로 메시지 전송
  function notifyContentScript(type: string, url: string, method: string, body?: string): void {
    try {
      const absoluteUrl = toAbsoluteUrl(url);
      const initiatorScript = getInitiatorScript();
      window.postMessage({
        type: '__FJ_GUARD_REQUEST__',
        payload: {
          type: type,
          url: absoluteUrl,
          method: method,
          body: body,
          initiatorScript: initiatorScript,
          timestamp: Date.now()
        }
      }, '*');
    } catch {
      // 조용히 실패
    }
  }

  // body를 문자열로 변환
  function bodyToString(body: BodyInit | Document | null | undefined): string | undefined {
    if (!body) return undefined;
    if (typeof body === 'string') return body;
    if (body instanceof URLSearchParams) return body.toString();
    if (body instanceof FormData) {
      const parts: string[] = [];
      body.forEach((value, key) => {
        if (value instanceof File) {
          parts.push(key + '=[File]');
        } else {
          parts.push(key + '=' + value);
        }
      });
      return parts.join('&');
    }
    if (body instanceof ArrayBuffer || ArrayBuffer.isView(body)) {
      return '[Binary data]';
    }
    if (body instanceof Document) {
      return body.documentElement?.outerHTML ?? '';
    }
    try {
      return JSON.stringify(body);
    } catch {
      return String(body);
    }
  }

  // fetch 래핑
  window.fetch = function(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
    const url = typeof input === 'string' ? input :
                (input instanceof URL ? input.toString() :
                (input instanceof Request ? input.url : String(input)));
    const method = (init?.method ?? 'GET').toUpperCase();
    const body = init?.body;

    if (body && method !== 'GET') {
      notifyContentScript('FETCH', url, method, bodyToString(body));
    }

    return originalFetch.apply(window, [input, init] as Parameters<typeof fetch>);
  };

  // XHR 메타데이터를 위한 타입 확장
  interface XMLHttpRequestWithMeta extends XMLHttpRequest {
    __fj_method?: string;
    __fj_url?: string;
  }

  // XHR 래핑
  XMLHttpRequest.prototype.open = function(
    this: XMLHttpRequestWithMeta,
    method: string,
    url: string | URL,
    async?: boolean,
    username?: string | null,
    password?: string | null
  ): void {
    this.__fj_method = method;
    this.__fj_url = url.toString();
    return originalXHROpen.call(this, method, url, async ?? true, username ?? null, password ?? null);
  };

  XMLHttpRequest.prototype.send = function(
    this: XMLHttpRequestWithMeta,
    body?: Document | XMLHttpRequestBodyInit | null
  ): void {
    const method = (this.__fj_method ?? 'GET').toUpperCase();
    const url = this.__fj_url ?? '';

    if (body && method !== 'GET') {
      notifyContentScript('XHR', url, method, bodyToString(body));
    }

    return originalXHRSend.call(this, body);
  };

  // sendBeacon 래핑
  navigator.sendBeacon = function(url: string | URL, data?: BodyInit | null): boolean {
    notifyContentScript('BEACON', url.toString(), 'POST', bodyToString(data));
    return originalSendBeacon(url, data);
  };

  console.log('[FormJacking Guard] Main world interceptors installed');
})();
