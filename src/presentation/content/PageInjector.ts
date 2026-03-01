/**
 * ============================================================================
 * 파일: PageInjector.ts
 * ============================================================================
 *
 * [역할]
 * 메인 월드에서 인터셉트된 네트워크 요청 정보를 수신합니다.
 * injected.ts와 콘텐츠 스크립트 사이의 "다리" 역할을 합니다.
 *
 * [비유]
 * "무전기 수신자"와 같습니다:
 * - injected.ts(메인 월드)가 발신자
 * - PageInjector(콘텐츠 스크립트)가 수신자
 * - window.postMessage로 통신
 *
 * [왜 필요한가?]
 * Chrome 확장 프로그램의 콘텐츠 스크립트는 "격리된 세계(Isolated World)"에서 실행됩니다.
 * 웹페이지의 JavaScript와 완전히 분리되어 있어서:
 * - 웹페이지의 fetch, XHR을 직접 가로챌 수 없음
 * - 그래서 메인 월드에 injected.ts를 주입
 * - injected.ts가 요청을 가로채서 postMessage로 전송
 * - PageInjector가 이 메시지를 수신
 *
 * [통신 구조]
 * ```
 * [메인 월드]                    [콘텐츠 스크립트]
 * injected.ts                   PageInjector
 *     ↓                              ↑
 * window.postMessage  ────────→  onMessage
 * (__FJ_GUARD_REQUEST__)
 * ```
 *
 * [주요 메서드]
 * - inject(): 메시지 리스너 시작
 * - remove(): 메시지 리스너 중지
 * - onRequest(callback): 요청 수신 시 콜백 등록
 *
 * [다른 파일과의 관계]
 * - injected.ts: 메시지를 보내는 발신자
 * - content/index.ts: 이 수신자 사용
 * - NetworkInterceptor.ts: 함께 사용되어 모든 요청 포착
 *
 * [메시지 형식]
 * ```javascript
 * {
 *   type: '__FJ_GUARD_REQUEST__',
 *   payload: {
 *     type: 'FETCH' | 'XHR' | 'BEACON',
 *     url: string,
 *     method: string,
 *     body?: string,
 *     timestamp: number
 *   }
 * }
 * ```
 * ============================================================================
 */

/* eslint-disable no-console */

/**
 * 인터셉트된 요청 이벤트 타입
 */
export interface InterceptedRequestEvent {
  type: 'FETCH' | 'XHR' | 'BEACON';
  url: string;
  method: string;
  body?: string;
  initiatorScript?: string;
  timestamp: number;
}

/**
 * PageInjector 클래스
 * 메인 월드의 injected.ts로부터 메시지를 수신합니다.
 */
export class PageInjector {
  private isListening: boolean = false;
  private messageHandler: ((event: MessageEvent) => void) | null = null;
  private callbacks: Set<(request: InterceptedRequestEvent) => void> = new Set();

  /**
   * 메시지 리스너 시작
   */
  inject(): void {
    if (this.isListening) {
      return;
    }

    // 메시지 리스너 설정 (메인 월드 -> 콘텐츠 스크립트)
    this.messageHandler = (event: MessageEvent) => {
      if (event.source !== window) {
        return;
      }

      if (event.data?.type === '__FJ_GUARD_REQUEST__') {
        const request = event.data.payload as InterceptedRequestEvent;
        console.log('[FormJacking Guard] Intercepted from main world:', request.type, request.url);
        this.notifyCallbacks(request);
      }
    };

    window.addEventListener('message', this.messageHandler);

    this.isListening = true;
    console.log('[FormJacking Guard] Page injector message listener started');
  }

  /**
   * 메시지 리스너 중지
   */
  remove(): void {
    if (!this.isListening) {
      return;
    }

    if (this.messageHandler) {
      window.removeEventListener('message', this.messageHandler);
      this.messageHandler = null;
    }

    this.isListening = false;
  }

  /**
   * 요청 콜백 등록
   */
  onRequest(callback: (request: InterceptedRequestEvent) => void): void {
    this.callbacks.add(callback);
  }

  /**
   * 요청 콜백 해제
   */
  offRequest(callback: (request: InterceptedRequestEvent) => void): void {
    this.callbacks.delete(callback);
  }

  /**
   * 콜백 호출
   */
  private notifyCallbacks(request: InterceptedRequestEvent): void {
    this.callbacks.forEach((callback) => {
      try {
        callback(request);
      } catch (error) {
        console.error('[FormJacking Guard] Callback error:', error);
      }
    });
  }
}
