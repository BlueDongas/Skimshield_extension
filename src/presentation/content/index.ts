/**
 * ============================================================================
 * 파일: content/index.ts
 * ============================================================================
 *
 * [역할]
 * 콘텐츠 스크립트의 진입점(Entry Point)입니다.
 * 웹페이지에 주입되어 모든 보안 모니터링을 시작합니다.
 *
 * [비유]
 * "보안 관제 센터"와 같습니다:
 * - 여러 감시 시스템(InputMonitor, NetworkInterceptor 등)을 총괄
 * - 각 시스템에서 보고가 오면 백그라운드에 전달
 * - 위험 감지 시 사용자에게 경고(WarningModal) 표시
 *
 * [콘텐츠 스크립트란?]
 * Chrome 확장 프로그램이 웹페이지에 주입하는 JavaScript입니다.
 * - 웹페이지의 DOM에 접근 가능
 * - 확장 프로그램의 API(chrome.runtime)에도 접근 가능
 * - 웹페이지와 확장 프로그램 사이의 "다리" 역할
 *
 * [초기화 흐름]
 * ```
 * 페이지 로드
 *     ↓
 * ContentScript 인스턴스 생성
 *     ↓
 * initialize()
 *     ├→ DOMAnalyzer.analyze() - 페이지 구조 분석
 *     ├→ InputMonitor.start() - 민감 필드 모니터링
 *     ├→ NetworkInterceptor.start() - 네트워크 인터셉트
 *     ├→ PageInjector.inject() - 메인 월드 메시지 수신
 *     └→ setupMessageListener() - 백그라운드 통신
 * ```
 *
 * [메시지 통신]
 * - Content → Background: 민감 입력, 분석 요청, 상태 조회
 * - Background → Content: 경고 표시, 상태 업데이트
 *
 * [상태 관리]
 * - currentVerdict: 현재 페이지의 위험 등급
 * - sensitiveInputs: 최근 민감 입력 기록 (timestamp 포함)
 * - pendingRequests: 분석 대기 중인 요청
 *
 * [다른 파일과의 관계]
 * - DOMAnalyzer.ts: DOM 분석
 * - InputMonitor.ts: 입력 필드 감시
 * - NetworkInterceptor.ts: 네트워크 인터셉트
 * - PageInjector.ts: 메인 월드 통신
 * - WarningModal.ts: 경고 UI 표시
 * - background/index.ts: 백그라운드와 통신
 *
 * [내보내기]
 * 테스트용으로 주요 클래스들을 export합니다.
 * ============================================================================
 */

/* eslint-disable no-console */

import { NetworkRequestType } from '@domain/entities/NetworkRequest';
import { MessageType, Message, MessageResponse } from '@domain/ports/IMessenger';
import { SensitiveFieldType } from '@domain/value-objects/SensitiveFieldType';
import { Verdict, Recommendation } from '@domain/value-objects/Verdict';

import { detectPayloadFormat } from '@shared/utils/payloadFormatUtils';
import { DOMAnalyzer } from './DOMAnalyzer';
import { InputMonitor, SensitiveFieldInfo } from './InputMonitor';
import { NetworkInterceptor, InterceptedRequest } from './NetworkInterceptor';
import { PageInjector, InterceptedRequestEvent } from './PageInjector';
import { WarningModal, WarningInfo, UserAction } from './WarningModal';

/**
 * Content Script 상태
 */
interface ContentScriptState {
  isInitialized: boolean;
  currentVerdict: Verdict;
  sensitiveInputs: Map<string, { fieldType: SensitiveFieldType; inputLength: number; timestamp: number }>;
  pendingRequests: Map<string, InterceptedRequest>;
}

/**
 * Content Script 메인 클래스
 */
class ContentScript {
  private inputMonitor: InputMonitor;
  private networkInterceptor: NetworkInterceptor;
  private pageInjector: PageInjector;
  private domAnalyzer: DOMAnalyzer;
  private warningModal: WarningModal;
  private state: ContentScriptState;
  private lastClickTimestamp = 0;

  constructor() {
    this.inputMonitor = new InputMonitor();
    this.networkInterceptor = new NetworkInterceptor();
    this.pageInjector = new PageInjector();
    this.domAnalyzer = new DOMAnalyzer();
    this.warningModal = new WarningModal();

    this.state = {
      isInitialized: false,
      currentVerdict: Verdict.SAFE,
      sensitiveInputs: new Map(),
      pendingRequests: new Map()
    };
  }

  /**
   * Content Script 초기화
   */
  initialize(): void {
    if (this.state.isInitialized) {
      return;
    }

    console.log('[FormJacking Guard] Initializing content script...');

    // DOM 분석
    this.domAnalyzer.analyze();

    // 결제 페이지인 경우에만 본격적인 모니터링 시작
    if (this.domAnalyzer.isPaymentPage()) {
      console.log('[FormJacking Guard] Payment page detected, starting monitoring');
      this.startMonitoring();
    } else {
      console.log('[FormJacking Guard] Not a payment page, monitoring with reduced intensity');
      // 비결제 페이지에서도 기본 모니터링은 수행
      this.startMonitoring();
    }

    // 메시지 리스너 등록
    this.setupMessageListener();

    this.state.isInitialized = true;
    console.log('[FormJacking Guard] Content script initialized');
  }

  /**
   * 모니터링 시작
   */
  private startMonitoring(): void {
    // 클릭 이벤트 추적 (triggerEvent 추론용)
    document.addEventListener('click', () => {
      this.lastClickTimestamp = Date.now();
    }, true);

    // 입력 모니터 시작
    this.inputMonitor.onSensitiveInput(this.handleSensitiveInput.bind(this));
    this.inputMonitor.start();

    // 네트워크 인터셉터 시작 (콘텐츠 스크립트 월드)
    this.networkInterceptor.onRequest((request) => {
      void this.handleNetworkRequest(request);
    });
    this.networkInterceptor.onFormSubmit((form, action, data) => {
      void this.handleFormSubmit(form, action, data);
    });
    this.networkInterceptor.start();

    // 페이지 인젝터 시작 (메인 월드 인터셉션)
    this.pageInjector.onRequest((event: InterceptedRequestEvent) => {
      const requestType = event.type === 'FETCH' ? NetworkRequestType.FETCH :
                          event.type === 'XHR' ? NetworkRequestType.XHR :
                          NetworkRequestType.BEACON;
      const request: InterceptedRequest = {
        type: requestType,
        url: event.url,
        method: event.method,
        headers: {},
        timestamp: event.timestamp,
        ...(event.body !== undefined ? { body: event.body } : {}),
        ...(event.initiatorScript !== undefined ? { initiatorScript: event.initiatorScript } : {})
      };
      void this.handleNetworkRequest(request);
    });
    this.pageInjector.inject();
  }

  /**
   * 모니터링 중지
   */
  stop(): void {
    this.inputMonitor.stop();
    this.networkInterceptor.stop();
    this.pageInjector.remove();
    this.state.isInitialized = false;
  }

  /**
   * 민감 입력 핸들러
   */
  private handleSensitiveInput(info: SensitiveFieldInfo, value: string): void {
    console.log('[FormJacking Guard] Sensitive input detected:', {
      fieldType: info.fieldType,
      fieldId: info.fieldId,
      length: value.length
    });

    // 민감 입력 기록
    this.state.sensitiveInputs.set(info.fieldId, {
      fieldType: info.fieldType,
      inputLength: value.length,
      timestamp: Date.now()
    });

    // 백그라운드로 메시지 전송
    void this.sendToBackground({
      type: MessageType.SENSITIVE_INPUT,
      payload: {
        fieldId: info.fieldId,
        fieldType: info.fieldType,
        inputLength: value.length,
        domPath: info.domPath,
        timestamp: Date.now(),
        pageUrl: window.location.href
      },
      timestamp: Date.now()
    });
  }

  /**
   * verdict 심각도 반환
   */
  private getSeverity(verdict: Verdict): number {
    const severityOrder: Record<Verdict, number> = {
      [Verdict.SAFE]: 0,
      [Verdict.UNKNOWN]: 1,
      [Verdict.SUSPICIOUS]: 2,
      [Verdict.DANGEROUS]: 3
    };
    return severityOrder[verdict] ?? 0;
  }

  /**
   * 네트워크 요청 핸들러
   */
  private async handleNetworkRequest(request: InterceptedRequest): Promise<void> {
    const recentSensitiveInputs = this.getRecentSensitiveInputs(5000);

    // 최근 민감 입력이 없으면 무시
    if (recentSensitiveInputs.length === 0) {
      return;
    }

    console.log('[FormJacking Guard] Network request detected after sensitive input:', {
      url: request.url,
      method: request.method,
      type: request.type,
      recentInputs: recentSensitiveInputs.length
    });

    // 분석 요청
    const analysisResult = await this.requestAnalysis(request, recentSensitiveInputs);

    if (analysisResult !== null && analysisResult.verdict !== Verdict.SAFE) {
      // 현재 상태보다 덜 심각하면 무시
      if (this.getSeverity(analysisResult.verdict) < this.getSeverity(this.state.currentVerdict)) {
        console.log('[FormJacking Guard] Less severe verdict, skipping warning');
        return;
      }

      // UNKNOWN verdict인 경우 설정 확인
      if (analysisResult.verdict === Verdict.UNKNOWN) {
        const showUnknown = await this.getShowUnknownWarningsSetting();
        if (!showUnknown) {
          console.log('[FormJacking Guard] UNKNOWN warnings disabled, skipping');
          return;
        }
      }

      this.state.currentVerdict = analysisResult.verdict;
      await this.showWarning(analysisResult);
    }
  }

  /**
   * 확인 필요 경고 표시 설정 조회
   */
  private async getShowUnknownWarningsSetting(): Promise<boolean> {
    try {
      const response = await this.sendToBackground<
        Record<string, never>,
        { showUnknownWarnings?: boolean }
      >({
        type: MessageType.UPDATE_SETTINGS,
        payload: {},
        timestamp: Date.now()
      });

      if (response.success && response.data !== undefined) {
        return response.data.showUnknownWarnings ?? true;
      }
      return true;
    } catch {
      return true;
    }
  }

  /**
   * 폼 제출 핸들러
   */
  private async handleFormSubmit(
    form: HTMLFormElement,
    action: string,
    _data: FormData
  ): Promise<void> {
    const recentSensitiveInputs = this.getRecentSensitiveInputs(30000);

    // 폼 내에 민감 필드가 있는지 확인
    const formHasSensitiveFields = this.checkFormForSensitiveFields(form);

    if (!formHasSensitiveFields && recentSensitiveInputs.length === 0) {
      return;
    }

    console.log('[FormJacking Guard] Form submission detected:', {
      action,
      hasSensitiveFields: formHasSensitiveFields
    });

    // 폼 제출용 InterceptedRequest 생성
    const formMethod = form.method.toUpperCase();
    const request: InterceptedRequest = {
      type: NetworkRequestType.FORM,
      url: action,
      method: formMethod !== '' ? formMethod : 'POST',
      headers: {},
      timestamp: Date.now()
    };

    const analysisResult = await this.requestAnalysis(request, recentSensitiveInputs);

    if (analysisResult !== null && analysisResult.verdict !== Verdict.SAFE) {
      // 현재 상태보다 덜 심각하면 무시
      if (this.getSeverity(analysisResult.verdict) < this.getSeverity(this.state.currentVerdict)) {
        console.log('[FormJacking Guard] Less severe verdict, skipping warning');
        return;
      }

      // UNKNOWN verdict인 경우 설정 확인
      if (analysisResult.verdict === Verdict.UNKNOWN) {
        const showUnknown = await this.getShowUnknownWarningsSetting();
        if (!showUnknown) {
          console.log('[FormJacking Guard] UNKNOWN warnings disabled, skipping');
          return;
        }
      }

      this.state.currentVerdict = analysisResult.verdict;
      await this.showWarning(analysisResult);
    }
  }

  /**
   * 최근 민감 입력 목록 조회
   */
  private getRecentSensitiveInputs(
    withinMs: number
  ): Array<{ fieldType: SensitiveFieldType; inputLength: number; timestamp: number }> {
    const threshold = Date.now() - withinMs;
    const recent: Array<{ fieldType: SensitiveFieldType; inputLength: number; timestamp: number }> = [];

    this.state.sensitiveInputs.forEach((input) => {
      if (input.timestamp > threshold) {
        recent.push(input);
      }
    });

    return recent;
  }

  /**
   * 폼 내 민감 필드 확인
   */
  private checkFormForSensitiveFields(form: HTMLFormElement): boolean {
    const sensitiveFields = this.inputMonitor.getSensitiveFields();

    for (const [, fieldInfo] of sensitiveFields) {
      if (form.contains(fieldInfo.element)) {
        return true;
      }
    }

    return false;
  }

  /**
   * 백그라운드에 분석 요청
   */
  private async requestAnalysis(
    request: InterceptedRequest,
    sensitiveInputs: Array<{ fieldType: SensitiveFieldType; timestamp: number }>
  ): Promise<{
    verdict: Verdict;
    recommendation: Recommendation;
    message: string;
    details?: string[];
    targetUrl?: string;
  } | null> {
    try {
      const contentType = request.headers['content-type'] ?? request.headers['Content-Type'] ?? '';
      const detectedFormat = request.body !== undefined
        ? detectPayloadFormat(request.body, contentType)
        : undefined;

      const now = request.timestamp;
      const mostRecentInputTime = sensitiveInputs.length > 0
        ? Math.max(...sensitiveInputs.map(i => i.timestamp))
        : 0;
      const timeSinceClick = now - this.lastClickTimestamp;
      const timeSinceInput = mostRecentInputTime > 0 ? now - mostRecentInputTime : Infinity;

      let triggerEvent: 'click' | 'submit' | 'blur' | 'timer' | 'unknown';
      if (request.type === NetworkRequestType.FORM) {
        triggerEvent = 'submit';
      } else if (timeSinceClick < 500) {
        triggerEvent = 'click';
      } else if (timeSinceInput < 2000) {
        triggerEvent = 'blur';
      } else if (timeSinceInput > 10000) {
        triggerEvent = 'timer';
      } else {
        triggerEvent = 'unknown';
      }

      const requestPayload = {
        type: request.type,
        url: request.url,
        method: request.method,
        headers: request.headers ?? {},
        payloadSize: request.body?.length ?? 0,
        ...(detectedFormat !== undefined ? { payloadFormat: detectedFormat } : {}),
        ...(request.initiatorScript !== undefined ? { initiatorScript: request.initiatorScript } : {}),
        triggerEvent,
        timestamp: request.timestamp
      };

      const recentInputsPayload = sensitiveInputs.map((input) => ({
        fieldType: input.fieldType,
        inputLength: input.inputLength,
        timestamp: input.timestamp
      }));

      const response = await this.sendToBackground<
        {
          request: typeof requestPayload;
          recentInputs: typeof recentInputsPayload;
          currentDomain: string;
          externalScripts: string[];
        },
        {
          verdict: Verdict;
          recommendation: Recommendation;
          reason: string;
          details?: { suspiciousFactors: string[]; safeFactors: string[]; };
        }
      >({
        type: MessageType.ANALYZE_REQUEST,
        payload: {
          request: requestPayload,
          recentInputs: recentInputsPayload,
          currentDomain: this.domAnalyzer.getPageDomain(),
          externalScripts: this.domAnalyzer.getExternalScripts().map((s) => s.src)
        },
        timestamp: Date.now()
      });

      if (response.success && response.data !== undefined) {
        const data = response.data;
        const result: {
          verdict: Verdict;
          recommendation: Recommendation;
          message: string;
          details?: string[];
          targetUrl?: string;
        } = {
          verdict: data.verdict,
          recommendation: data.recommendation,
          message: data.reason,
          targetUrl: request.url
        };
        if (data.details !== undefined) {
          result.details = [...data.details.suspiciousFactors, ...data.details.safeFactors];
        }
        return result;
      }

      return null;
    } catch (error) {
      console.error('[FormJacking Guard] Analysis request failed:', error);
      return null;
    }
  }

  /**
   * URL에서 도메인 추출
   */
  private extractDomain(url: string): string {
    try {
      return new URL(url).hostname;
    } catch {
      return '';
    }
  }

  /**
   * 경고 표시
   */
  private async showWarning(result: {
    verdict: Verdict;
    recommendation: Recommendation;
    message: string;
    details?: string[];
    targetUrl?: string;
  }): Promise<UserAction> {
    const info: WarningInfo = {
      verdict: result.verdict,
      recommendation: result.recommendation,
      title: this.getWarningTitle(result.verdict),
      message: result.message,
      ...(result.details !== undefined ? { details: result.details } : {}),
      ...(result.targetUrl !== undefined ? { targetUrl: result.targetUrl } : {})
    };

    const userAction = await this.warningModal.show(info);

    // 대상 도메인 추출
    const targetDomain = result.targetUrl !== undefined
      ? this.extractDomain(result.targetUrl)
      : '';

    // 사용자 액션을 백그라운드에 전송
    void this.sendToBackground({
      type: MessageType.USER_ACTION,
      payload: {
        action: userAction,
        verdict: result.verdict,
        domain: targetDomain,
        targetUrl: result.targetUrl ?? '',
        timestamp: Date.now()
      },
      timestamp: Date.now()
    });

    return userAction;
  }

  /**
   * verdict에 따른 경고 제목 반환
   */
  private getWarningTitle(verdict: Verdict): string {
    switch (verdict) {
      case Verdict.DANGEROUS:
        return '위험 감지';
      case Verdict.SUSPICIOUS:
        return '의심스러운 활동';
      case Verdict.UNKNOWN:
        return '확인 필요';
      default:
        return '알림';
    }
  }

  /**
   * 메시지 리스너 설정
   */
  private setupMessageListener(): void {
    chrome.runtime.onMessage.addListener(
      (
        message: Message,
        _sender: chrome.runtime.MessageSender,
        sendResponse: (response: MessageResponse) => void
      ) => {
        this.handleMessage(message)
          .then(sendResponse)
          .catch((error: unknown) => {
            console.error('[FormJacking Guard] Message handler error:', error);
            sendResponse({ success: false, error: String(error) });
          });

        return true; // 비동기 응답
      }
    );
  }

  /**
   * 메시지 핸들러
   */
  private async handleMessage(message: Message): Promise<MessageResponse> {
    switch (message.type) {
      case MessageType.GET_STATE:
        return {
          success: true,
          data: {
            isPaymentPage: this.domAnalyzer.isPaymentPage(),
            sensitiveFieldCount: this.inputMonitor.getSensitiveFields().size,
            externalScriptCount: this.domAnalyzer.getExternalScripts().length,
            currentVerdict: this.state.currentVerdict
          }
        };

      case MessageType.SHOW_WARNING: {
        const warningPayload = message.payload as {
          verdict: Verdict;
          recommendation: Recommendation;
          message: string;
          details?: string[];
          targetUrl?: string;
        };
        await this.showWarning(warningPayload);
        return { success: true };
      }

      case MessageType.STATE_UPDATE: {
        const statePayload = message.payload as { verdict?: Verdict };
        if (statePayload.verdict !== undefined) {
          this.state.currentVerdict = statePayload.verdict;
          this.warningModal.updateVerdict(statePayload.verdict);
        }
        return { success: true };
      }

      default:
        return { success: false, error: 'Unknown message type' };
    }
  }

  /**
   * 백그라운드에 메시지 전송
   */
  private sendToBackground<T, R>(message: Message<T>): Promise<MessageResponse<R>> {
    return new Promise((resolve) => {
      chrome.runtime.sendMessage(message, (response: MessageResponse<R>) => {
        if (chrome.runtime.lastError !== undefined && chrome.runtime.lastError !== null) {
          const errorMessage = chrome.runtime.lastError.message ?? 'Unknown error';
          resolve({
            success: false,
            error: errorMessage
          });
        } else if (response !== undefined && response !== null) {
          resolve(response);
        } else {
          resolve({ success: false, error: 'No response' });
        }
      });
    });
  }
}

// Content Script 인스턴스 생성 및 초기화
const contentScript = new ContentScript();

// DOM 로드 완료 후 초기화
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => {
    contentScript.initialize();
  });
} else {
  contentScript.initialize();
}

// 모듈 내보내기 (테스트용)
export { ContentScript, InputMonitor, NetworkInterceptor, PageInjector, DOMAnalyzer, WarningModal };
export type { InterceptedRequest, InterceptedRequestEvent, SensitiveFieldInfo, WarningInfo };
export { UserAction };
