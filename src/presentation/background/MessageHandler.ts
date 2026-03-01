/**
 * ============================================================================
 * 파일: MessageHandler.ts
 * ============================================================================
 *
 * [역할]
 * 백그라운드에서 콘텐츠 스크립트, 팝업 등으로부터 오는
 * 모든 메시지를 처리하는 중앙 메시지 허브입니다.
 *
 * [비유]
 * "고객센터 상담원"과 같습니다:
 * - 여러 채널(콘텐츠, 팝업)에서 문의(메시지)가 들어옴
 * - 문의 유형에 따라 적절한 부서(UseCase)로 전달
 * - 처리 결과를 다시 고객에게 반환
 *
 * [메시지 유형과 처리]
 *
 * | 메시지 타입        | 처리 내용                        |
 * |-------------------|----------------------------------|
 * | SENSITIVE_INPUT   | 민감 입력 기록 (orchestrator)    |
 * | ANALYZE_REQUEST   | 네트워크 요청 분석               |
 * | GET_STATUS        | 보안 상태 조회                   |
 * | UPDATE_SETTINGS   | 설정 변경                        |
 * | GET_EVENTS        | 이벤트 목록 조회                 |
 * | CLEAR_DATA        | 데이터 삭제                      |
 * | USER_ACTION       | 사용자 액션(허용/차단) 처리      |
 *
 * [의존성 주입]
 * MessageHandlerDeps 인터페이스를 통해 의존성을 주입받습니다:
 * - orchestrator: 탐지 오케스트레이터
 * - getSecurityStatusUseCase: 상태 조회 유즈케이스
 * - manageSettingsUseCase: 설정 관리 유즈케이스
 * - manageBlockingUseCase: 차단 관리 유즈케이스
 * - eventRepository: 이벤트 저장소
 * - messenger: 메시지 통신
 *
 * [주요 메서드]
 * - handleMessage(type, payload, tabId): 메시지 처리
 * - start(): 메시지 리스너 등록
 * - stop(): 메시지 리스너 해제
 *
 * [다른 파일과의 관계]
 * - background/index.ts: 이 핸들러 생성 및 사용
 * - DetectionOrchestrator.ts: 탐지 로직 실행
 * - ManageSettingsUseCase.ts: 설정 관리
 * - ManageBlockingUseCase.ts: 차단 관리
 * - ChromeMessenger.ts: 실제 메시지 전송/수신
 *
 * [흐름]
 * 메시지 수신 → handleMessage() → switch(type)
 * → 적절한 핸들러 호출 → 결과 반환
 * ============================================================================
 */

import { MessageType, MessageHandler as IMessageHandlerFn } from '@domain/ports/IMessenger';
import { SensitiveFieldType } from '@domain/value-objects/SensitiveFieldType';
import { Verdict } from '@domain/value-objects/Verdict';

/**
 * ManageBlockingUseCase 인터페이스 (의존성 주입용)
 */
interface ManageBlockingUseCaseInterface {
  handleUserAction: (request: {
    action: 'allow' | 'block' | 'dismiss';
    domain: string;
    reason?: string;
  }) => Promise<{ success: boolean; action: string; error?: string }>;
}

/**
 * MessageHandler 의존성
 */
export interface MessageHandlerDeps {
  orchestrator: {
    handleSensitiveInput: (input: {
      fieldId: string;
      fieldType: SensitiveFieldType;
      inputLength: number;
      timestamp: number;
    }) => void;
    analyzeNetworkRequest: (payload: unknown, tabId?: number) => Promise<unknown>;
    clearInputBuffer: () => void;
  };
  getSecurityStatusUseCase: {
    execute: (currentDomain: string) => Promise<unknown>;
  };
  manageSettingsUseCase: {
    getSettings: () => Promise<unknown>;
    updateSettings: (update: unknown) => Promise<void>;
    resetSettings: () => Promise<void>;
    manageWhitelist: (action: 'add' | 'remove', domain: string) => Promise<void>;
    getWhitelistedDomains: () => Promise<string[]>;
  };
  manageBlockingUseCase: ManageBlockingUseCaseInterface;
  eventRepository: {
    findRecent: (limit: number) => Promise<unknown[]>;
    findByFilter: (filter: unknown) => Promise<unknown[]>;
    deleteAll: () => Promise<void>;
    deleteOlderThan: (timestamp: number) => Promise<number>;
  };
  messenger: {
    onMessage: <TPayload, TResponse>(
      type: MessageType,
      handler: IMessageHandlerFn<TPayload, TResponse>
    ) => void;
    offMessage: (type: MessageType) => void;
    sendToTab: (tabId: number, message: unknown) => Promise<unknown>;
  };
}

/**
 * 민감 입력 페이로드
 */
interface SensitiveInputPayload {
  fieldId: string;
  fieldType: SensitiveFieldType;
  inputLength: number;
  timestamp: number;
}

/**
 * 분석 요청 페이로드
 */
interface AnalyzeRequestPayload {
  request: {
    type: string;
    url: string;
    method: string;
    payloadSize: number;
    timestamp: number;
  };
  recentInputs: unknown[];
  currentDomain: string;
}

/**
 * 상태 조회 페이로드
 */
interface GetStatusPayload {
  currentDomain: string;
}

/**
 * 설정 업데이트 페이로드
 */
interface UpdateSettingsPayload {
  aiAnalysisEnabled?: boolean;
  notificationsEnabled?: boolean;
  autoBlockEnabled?: boolean;
  debugMode?: boolean;
  dataRetentionHours?: number;
  showUnknownWarnings?: boolean;
  whitelist?: {
    action: 'add' | 'remove';
    domain: string;
  };
}

/**
 * 이벤트 조회 페이로드
 */
interface GetEventsPayload {
  limit?: number;
  verdict?: Verdict;
  domain?: string;
}

/**
 * 데이터 삭제 페이로드
 */
interface ClearDataPayload {
  all?: boolean;
  olderThan?: number;
}

/**
 * 사용자 액션 페이로드
 */
interface UserActionPayload {
  action: 'allow' | 'block' | 'dismiss';
  domain: string;
  targetUrl?: string;
  remember?: boolean;
}

/**
 * MessageHandler 클래스
 */
export class MessageHandler {
  private readonly deps: MessageHandlerDeps;
  private isStarted: boolean = false;

  constructor(deps: MessageHandlerDeps) {
    this.deps = deps;
  }

  /**
   * 메시지 처리
   */
  async handleMessage(
    type: MessageType,
    payload: unknown,
    tabId?: number
  ): Promise<unknown> {
    try {
      switch (type) {
        case MessageType.SENSITIVE_INPUT:
          return this.handleSensitiveInput(payload as SensitiveInputPayload);

        case MessageType.ANALYZE_REQUEST:
          return await this.handleAnalyzeRequest(payload as AnalyzeRequestPayload, tabId);

        case MessageType.GET_STATUS:
          return await this.handleGetStatus(payload as GetStatusPayload);

        case MessageType.UPDATE_SETTINGS:
          return await this.handleUpdateSettings(payload as UpdateSettingsPayload);

        case MessageType.GET_EVENTS:
          return await this.handleGetEvents(payload as GetEventsPayload);

        case MessageType.CLEAR_DATA:
          return await this.handleClearData(payload as ClearDataPayload);

        case MessageType.USER_ACTION:
          return await this.handleUserAction(payload as UserActionPayload);

        default:
          return { error: `Unknown message type: ${String(type)}` };
      }
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      return { error: errorMessage };
    }
  }

  /**
   * 메시지 리스너 시작
   */
  start(): void {
    if (this.isStarted) {
      return;
    }

    this.isStarted = true;

    // 모든 메시지 타입에 대해 핸들러 등록
    const messageTypes = [
      MessageType.SENSITIVE_INPUT,
      MessageType.ANALYZE_REQUEST,
      MessageType.GET_STATUS,
      MessageType.UPDATE_SETTINGS,
      MessageType.GET_EVENTS,
      MessageType.CLEAR_DATA,
      MessageType.USER_ACTION
    ];

    for (const msgType of messageTypes) {
      this.deps.messenger.onMessage(msgType, (payload, tabId) =>
        this.handleMessage(msgType, payload, tabId)
      );
    }
  }

  /**
   * 메시지 리스너 중지
   */
  stop(): void {
    if (!this.isStarted) {
      return;
    }

    this.isStarted = false;

    // 모든 메시지 타입에 대해 핸들러 해제
    const messageTypes = [
      MessageType.SENSITIVE_INPUT,
      MessageType.ANALYZE_REQUEST,
      MessageType.GET_STATUS,
      MessageType.UPDATE_SETTINGS,
      MessageType.GET_EVENTS,
      MessageType.CLEAR_DATA,
      MessageType.USER_ACTION
    ];

    for (const msgType of messageTypes) {
      this.deps.messenger.offMessage(msgType);
    }
  }

  /**
   * 민감 입력 처리
   */
  private handleSensitiveInput(
    payload: SensitiveInputPayload
  ): { success: boolean } {
    this.deps.orchestrator.handleSensitiveInput({
      fieldId: payload.fieldId,
      fieldType: payload.fieldType,
      inputLength: payload.inputLength,
      timestamp: payload.timestamp
    });

    return { success: true };
  }

  /**
   * 분석 요청 처리
   */
  private async handleAnalyzeRequest(
    payload: AnalyzeRequestPayload,
    tabId?: number
  ): Promise<unknown> {
    return this.deps.orchestrator.analyzeNetworkRequest(payload, tabId);
  }

  /**
   * 상태 조회 처리
   */
  private async handleGetStatus(payload: GetStatusPayload): Promise<unknown> {
    return this.deps.getSecurityStatusUseCase.execute(payload.currentDomain);
  }

  /**
   * 설정 업데이트 처리
   */
  private async handleUpdateSettings(
    payload: UpdateSettingsPayload
  ): Promise<unknown> {
    // 화이트리스트 처리
    if (payload.whitelist !== undefined) {
      await this.deps.manageSettingsUseCase.manageWhitelist(
        payload.whitelist.action,
        payload.whitelist.domain
      );
    }

    // 일반 설정 업데이트 (whitelist 제외)
    const settingsUpdate: Partial<UpdateSettingsPayload> = {};
    if (payload.aiAnalysisEnabled !== undefined) {
      settingsUpdate.aiAnalysisEnabled = payload.aiAnalysisEnabled;
    }
    if (payload.notificationsEnabled !== undefined) {
      settingsUpdate.notificationsEnabled = payload.notificationsEnabled;
    }
    if (payload.autoBlockEnabled !== undefined) {
      settingsUpdate.autoBlockEnabled = payload.autoBlockEnabled;
    }
    if (payload.debugMode !== undefined) {
      settingsUpdate.debugMode = payload.debugMode;
    }
    if (payload.dataRetentionHours !== undefined) {
      settingsUpdate.dataRetentionHours = payload.dataRetentionHours;
    }
    if (payload.showUnknownWarnings !== undefined) {
      settingsUpdate.showUnknownWarnings = payload.showUnknownWarnings;
    }

    if (Object.keys(settingsUpdate).length > 0) {
      await this.deps.manageSettingsUseCase.updateSettings(settingsUpdate);
    }

    // 업데이트된 설정 반환
    return this.deps.manageSettingsUseCase.getSettings();
  }

  /**
   * 이벤트 조회 처리
   */
  private async handleGetEvents(payload: GetEventsPayload): Promise<unknown[]> {
    const limit = payload.limit ?? 50;

    // 필터가 있는 경우
    if (payload.verdict !== undefined || payload.domain !== undefined) {
      return this.deps.eventRepository.findByFilter({
        verdict: payload.verdict,
        domain: payload.domain,
        limit
      });
    }

    // 최근 이벤트 조회
    return this.deps.eventRepository.findRecent(limit);
  }

  /**
   * 데이터 삭제 처리
   */
  private async handleClearData(
    payload: ClearDataPayload
  ): Promise<{ deletedCount?: number; success?: boolean }> {
    if (payload.all === true) {
      await this.deps.eventRepository.deleteAll();
      this.deps.orchestrator.clearInputBuffer();
      return { success: true };
    }

    if (payload.olderThan !== undefined) {
      const deletedCount = await this.deps.eventRepository.deleteOlderThan(
        payload.olderThan
      );
      return { deletedCount };
    }

    return { success: true };
  }

  /**
   * 사용자 액션 처리
   */
  private async handleUserAction(
    payload: UserActionPayload
  ): Promise<{ success: boolean; action?: string; error?: string }> {
    // 도메인이 없으면 무시
    if (!payload.domain) {
      return { success: true };
    }

    // allow + remember 조합 시 화이트리스트에 영구 등록
    if (payload.action === 'allow' && payload.remember === true) {
      await this.deps.manageSettingsUseCase.manageWhitelist('add', payload.domain);
    }

    // ManageBlockingUseCase를 통해 액션 처리
    const result = await this.deps.manageBlockingUseCase.handleUserAction({
      action: payload.action,
      domain: payload.domain
    });

    return {
      success: result.success,
      action: result.action,
      ...(result.error !== undefined ? { error: result.error } : {})
    };
  }
}
