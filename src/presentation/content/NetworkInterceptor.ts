/**
 * ============================================================================
 * 파일: NetworkInterceptor.ts
 * ============================================================================
 *
 * [역할]
 * 콘텐츠 스크립트 월드에서 네트워크 요청을 가로채서 감시합니다.
 * fetch, XHR, sendBeacon, form submit 등 모든 데이터 전송을 인터셉트합니다.
 *
 * [비유]
 * "네트워크 감시 카메라"와 같습니다:
 * - 페이지에서 외부로 나가는 모든 데이터 전송을 기록
 * - 원래의 기능은 그대로 유지하면서 "몰래 관찰"
 * - 의심스러운 전송이 발견되면 콜백으로 알림
 *
 * [인터셉트 방식]
 * 브라우저의 원본 함수를 우리 함수로 교체(래핑)합니다:
 *
 * ```
 * 원래: fetch(url, options) → 서버
 * 교체: fetch(url, options) → [우리 기록] → 원본 fetch → 서버
 * ```
 *
 * [인터셉트 대상]
 * 1. fetch(): 모던 AJAX 요청
 * 2. XMLHttpRequest (XHR): 전통적인 AJAX 요청
 * 3. navigator.sendBeacon(): 페이지 종료 시 비동기 전송
 * 4. Form submit: 폼 제출 이벤트
 *
 * [주요 메서드]
 * - start(): 인터셉션 시작 (원본 함수 교체)
 * - stop(): 인터셉션 중지 (원본 함수 복원)
 * - onRequest(callback): 요청 감지 시 콜백 등록
 * - onFormSubmit(callback): 폼 제출 감지 시 콜백 등록
 *
 * [다른 파일과의 관계]
 * - content/index.ts: 이 인터셉터 사용
 * - PageInjector.ts: 메인 월드 인터셉션과 협력
 * - injected.ts: 메인 월드에서 실제 인터셉션 수행
 *
 * [주의사항]
 * - 콘텐츠 스크립트 월드와 메인 월드는 분리되어 있음
 * - 일부 사이트의 CSP(보안 정책) 때문에 직접 인터셉션이 불가할 수 있음
 * - 그래서 injected.ts를 메인 월드에 주입하여 보완
 * ============================================================================
 */

import { NetworkRequestType } from '@domain/entities/NetworkRequest';

/**
 * 인터셉트된 요청 정보 인터페이스
 */
export interface InterceptedRequest {
  type: NetworkRequestType;
  url: string;
  method: string;
  headers: Record<string, string>;
  body?: string;
  initiatorScript?: string;
  timestamp: number;
}

/**
 * 요청 콜백 타입
 */
export type RequestCallback = (request: InterceptedRequest) => void;

/**
 * 폼 제출 콜백 타입
 */
export type FormSubmitCallback = (
  form: HTMLFormElement,
  action: string,
  data: FormData
) => void;

/**
 * NetworkInterceptor 클래스
 * fetch, XHR, sendBeacon, form submit을 인터셉트합니다.
 */
export class NetworkInterceptor {
  private requestCallbacks: Set<RequestCallback> = new Set();
  private formSubmitCallbacks: Set<FormSubmitCallback> = new Set();
  private isRunning: boolean = false;

  private originalFetch: typeof globalThis.fetch | null = null;
  private originalXHROpen: typeof XMLHttpRequest.prototype.open | null = null;
  private originalXHRSend: typeof XMLHttpRequest.prototype.send | null = null;
  private originalXHRSetRequestHeader: typeof XMLHttpRequest.prototype.setRequestHeader | null = null;
  private originalSendBeacon: typeof navigator.sendBeacon | null = null;

  private boundHandleFormSubmit: (event: Event) => void;

  // Bound interceptor functions
  private boundFetchInterceptor: typeof globalThis.fetch;
  private boundSendBeacon: typeof navigator.sendBeacon;

  constructor() {
    this.boundHandleFormSubmit = this.handleFormSubmit.bind(this);
    this.boundFetchInterceptor = this.createFetchInterceptor();
    this.boundSendBeacon = this.createSendBeaconInterceptor();
  }

  /**
   * 인터셉션 시작
   */
  start(): void {
    if (this.isRunning) {
      return;
    }

    this.isRunning = true;

    // 원본 함수 저장 및 래핑
    this.interceptFetch();
    this.interceptXHR();
    this.interceptSendBeacon();

    // Form submit 이벤트 리스너
    document.addEventListener('submit', this.boundHandleFormSubmit, true);
  }

  /**
   * 인터셉션 중지
   */
  stop(): void {
    if (!this.isRunning) {
      return;
    }

    this.isRunning = false;

    // 원본 함수 복원
    this.restoreFetch();
    this.restoreXHR();
    this.restoreSendBeacon();

    // Form submit 이벤트 리스너 해제
    document.removeEventListener('submit', this.boundHandleFormSubmit, true);
  }

  /**
   * 요청 콜백 등록
   */
  onRequest(callback: RequestCallback): void {
    this.requestCallbacks.add(callback);
  }

  /**
   * 요청 콜백 해제
   */
  offRequest(callback: RequestCallback): void {
    this.requestCallbacks.delete(callback);
  }

  /**
   * 폼 제출 콜백 등록
   */
  onFormSubmit(callback: FormSubmitCallback): void {
    this.formSubmitCallbacks.add(callback);
  }

  /**
   * 폼 제출 콜백 해제
   */
  offFormSubmit(callback: FormSubmitCallback): void {
    this.formSubmitCallbacks.delete(callback);
  }

  /**
   * fetch 인터셉터 생성
   */
  private createFetchInterceptor(): typeof globalThis.fetch {
    return async (
      input: RequestInfo | URL,
      init?: RequestInit
    ): Promise<Response> => {
      // body가 있는 요청만 인터셉트 (POST, PUT 등)
      const method = this.extractMethod(input, init);
      const body = this.extractBody(input, init);

      if (body !== undefined && body !== null && this.isRunning) {
        const url = this.extractUrl(input);
        const headers = this.extractHeaders(input, init);
        const bodyString = await this.bodyToString(body);

        const interceptedRequest: InterceptedRequest = {
          type: NetworkRequestType.FETCH,
          url,
          method,
          headers,
          body: bodyString,
          timestamp: Date.now()
        };

        this.notifyRequestCallbacks(interceptedRequest);
      }

      if (this.originalFetch === null) {
        throw new Error('Original fetch not available');
      }

      return this.originalFetch.call(globalThis, input, init);
    };
  }

  /**
   * fetch 인터셉트
   */
  private interceptFetch(): void {
    this.originalFetch = globalThis.fetch;
    globalThis.fetch = this.boundFetchInterceptor;
  }

  /**
   * fetch 복원
   */
  private restoreFetch(): void {
    if (this.originalFetch !== null) {
      globalThis.fetch = this.originalFetch;
      this.originalFetch = null;
    }
  }

  /**
   * XHR 인터셉트
   */
  private interceptXHR(): void {
    // eslint-disable-next-line @typescript-eslint/unbound-method
    this.originalXHROpen = XMLHttpRequest.prototype.open;
    // eslint-disable-next-line @typescript-eslint/unbound-method
    this.originalXHRSend = XMLHttpRequest.prototype.send;
    // eslint-disable-next-line @typescript-eslint/unbound-method
    this.originalXHRSetRequestHeader = XMLHttpRequest.prototype.setRequestHeader;

    const originalOpen = this.originalXHROpen;
    const originalSend = this.originalXHRSend;
    const originalSetRequestHeader = this.originalXHRSetRequestHeader;
    // eslint-disable-next-line @typescript-eslint/no-this-alias
    const interceptor = this;

    // open 래핑
    XMLHttpRequest.prototype.open = function (
      this: XMLHttpRequestWithMeta,
      method: string,
      url: string | URL,
      async?: boolean,
      username?: string | null,
      password?: string | null
    ): void {
      this._fj_method = method;
      this._fj_url = url.toString();
      this._fj_headers = {};
      this._fj_originalOpen = originalOpen;
      this._fj_originalSend = originalSend;
      this._fj_originalSetRequestHeader = originalSetRequestHeader;

      originalOpen.call(
        this,
        method,
        url,
        async ?? true,
        username ?? null,
        password ?? null
      );
    };

    // setRequestHeader 래핑
    XMLHttpRequest.prototype.setRequestHeader = function (
      this: XMLHttpRequestWithMeta,
      name: string,
      value: string
    ): void {
      if (this._fj_headers !== undefined) {
        this._fj_headers[name] = value;
      }
      originalSetRequestHeader.call(this, name, value);
    };

    // send 래핑
    XMLHttpRequest.prototype.send = function (
      this: XMLHttpRequestWithMeta,
      body?: Document | XMLHttpRequestBodyInit | null
    ): void {
      const method = (this._fj_method ?? 'GET').toUpperCase();

      if (body !== undefined && body !== null && interceptor.isRunning && method !== 'GET') {
        const url = this._fj_url ?? '';
        const headers = this._fj_headers ?? {};
        const bodyString = interceptor.bodyToStringSync(body);

        const interceptedRequest: InterceptedRequest = {
          type: NetworkRequestType.XHR,
          url,
          method,
          headers,
          body: bodyString,
          timestamp: Date.now()
        };

        interceptor.notifyRequestCallbacks(interceptedRequest);
      }

      originalSend.call(this, body);
    };
  }

  /**
   * XHR 복원
   */
  private restoreXHR(): void {
    if (this.originalXHROpen !== null) {
      XMLHttpRequest.prototype.open = this.originalXHROpen;
      this.originalXHROpen = null;
    }
    if (this.originalXHRSend !== null) {
      XMLHttpRequest.prototype.send = this.originalXHRSend;
      this.originalXHRSend = null;
    }
    if (this.originalXHRSetRequestHeader !== null) {
      XMLHttpRequest.prototype.setRequestHeader = this.originalXHRSetRequestHeader;
      this.originalXHRSetRequestHeader = null;
    }
  }

  /**
   * sendBeacon 인터셉터 생성
   */
  private createSendBeaconInterceptor(): typeof navigator.sendBeacon {
    return (url: string | URL, data?: BodyInit | null): boolean => {
      if (this.isRunning) {
        const urlString = url.toString();
        const bodyString = data !== undefined && data !== null
          ? this.bodyToStringSync(data)
          : undefined;

        const interceptedRequest: InterceptedRequest = {
          type: NetworkRequestType.BEACON,
          url: urlString,
          method: 'POST',
          headers: {},
          ...(bodyString !== undefined ? { body: bodyString } : {}),
          timestamp: Date.now()
        };

        this.notifyRequestCallbacks(interceptedRequest);
      }

      if (this.originalSendBeacon === null) {
        return false;
      }

      return this.originalSendBeacon(url, data);
    };
  }

  /**
   * sendBeacon 인터셉트
   */
  private interceptSendBeacon(): void {
    this.originalSendBeacon = navigator.sendBeacon.bind(navigator);
    navigator.sendBeacon = this.boundSendBeacon;
  }

  /**
   * sendBeacon 복원
   */
  private restoreSendBeacon(): void {
    if (this.originalSendBeacon !== null) {
      navigator.sendBeacon = this.originalSendBeacon;
      this.originalSendBeacon = null;
    }
  }

  /**
   * 폼 제출 핸들러
   */
  private handleFormSubmit(event: Event): void {
    const form = event.target as HTMLFormElement;

    if (!(form instanceof HTMLFormElement)) {
      return;
    }

    const action = form.action !== '' ? form.action : window.location.href;
    const formData = new FormData(form);

    this.formSubmitCallbacks.forEach((callback) => {
      try {
        callback(form, action, formData);
      } catch (error) {
        console.error('[FormJacking Guard] Form submit callback error:', error);
      }
    });
  }

  /**
   * 요청 콜백 호출
   */
  private notifyRequestCallbacks(request: InterceptedRequest): void {
    this.requestCallbacks.forEach((callback) => {
      try {
        callback(request);
      } catch (error) {
        console.error('[FormJacking Guard] Request callback error:', error);
      }
    });
  }

  /**
   * Request/URL에서 URL 추출
   */
  private extractUrl(input: RequestInfo | URL): string {
    if (typeof input === 'string') {
      return input;
    }
    if (input instanceof URL) {
      return input.toString();
    }
    if (input instanceof Request) {
      return input.url;
    }
    return '';
  }

  /**
   * Request/init에서 method 추출
   */
  private extractMethod(input: RequestInfo | URL, init?: RequestInit): string {
    if (init?.method !== undefined) {
      return init.method.toUpperCase();
    }
    if (input instanceof Request) {
      return input.method.toUpperCase();
    }
    return 'GET';
  }

  /**
   * Request/init에서 headers 추출
   */
  private extractHeaders(
    input: RequestInfo | URL,
    init?: RequestInit
  ): Record<string, string> {
    const headers: Record<string, string> = {};

    const headersSource = init?.headers ?? (input instanceof Request ? input.headers : null);

    if (headersSource === null || headersSource === undefined) {
      return headers;
    }

    if (headersSource instanceof Headers) {
      headersSource.forEach((value, key) => {
        headers[key] = value;
      });
    } else if (Array.isArray(headersSource)) {
      headersSource.forEach(([key, value]) => {
        headers[key] = value;
      });
    } else {
      Object.assign(headers, headersSource);
    }

    return headers;
  }

  /**
   * Request/init에서 body 추출
   */
  private extractBody(
    input: RequestInfo | URL,
    init?: RequestInit
  ): BodyInit | null | undefined {
    // init.body가 있으면 우선 사용
    if (init?.body !== undefined) {
      return init.body;
    }
    // Request 객체인 경우 body 속성 사용
    if (input instanceof Request) {
      return input.body as BodyInit | null;
    }
    return undefined;
  }

  /**
   * body를 문자열로 변환 (비동기)
   */
  private async bodyToString(body: BodyInit): Promise<string> {
    if (typeof body === 'string') {
      return body;
    }
    if (body instanceof URLSearchParams) {
      return body.toString();
    }
    if (body instanceof FormData) {
      return this.formDataToString(body);
    }
    if (body instanceof Blob) {
      return await body.text();
    }
    if (body instanceof ArrayBuffer) {
      return new TextDecoder().decode(body);
    }
    if (ArrayBuffer.isView(body)) {
      return new TextDecoder().decode(body);
    }
    return String(body);
  }

  /**
   * body를 문자열로 변환 (동기)
   */
  private bodyToStringSync(body: BodyInit | Document): string {
    if (typeof body === 'string') {
      return body;
    }
    if (body instanceof URLSearchParams) {
      return body.toString();
    }
    if (body instanceof FormData) {
      return this.formDataToString(body);
    }
    if (body instanceof Blob) {
      return '[Blob data]';
    }
    if (body instanceof ArrayBuffer) {
      return new TextDecoder().decode(body);
    }
    if (ArrayBuffer.isView(body)) {
      return new TextDecoder().decode(body);
    }
    if (body instanceof Document) {
      return body.documentElement?.outerHTML ?? '';
    }
    return String(body);
  }

  /**
   * FormData를 문자열로 변환
   */
  private formDataToString(formData: FormData): string {
    const parts: string[] = [];
    formData.forEach((value, key) => {
      if (value instanceof File) {
        parts.push(`${key}=[File: ${value.name}]`);
      } else {
        parts.push(`${key}=${value}`);
      }
    });
    return parts.join('&');
  }
}

/**
 * XHR with FormJacking metadata
 */
interface XMLHttpRequestWithMeta extends XMLHttpRequest {
  _fj_method?: string;
  _fj_url?: string;
  _fj_headers?: Record<string, string>;
  _fj_originalOpen?: typeof XMLHttpRequest.prototype.open;
  _fj_originalSend?: typeof XMLHttpRequest.prototype.send;
  _fj_originalSetRequestHeader?: typeof XMLHttpRequest.prototype.setRequestHeader;
}
