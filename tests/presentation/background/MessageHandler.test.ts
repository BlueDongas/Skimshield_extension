/**
 * MessageHandler 테스트
 * 백그라운드 메시지 처리 기능을 테스트합니다.
 */

import { NetworkRequestType } from '@domain/entities/NetworkRequest';
import { MessageType } from '@domain/ports/IMessenger';
import { SensitiveFieldType } from '@domain/value-objects/SensitiveFieldType';
import { Recommendation, Verdict } from '@domain/value-objects/Verdict';

/**
 * MessageHandler 인터페이스 정의 (테스트용)
 */
interface IMessageHandler {
  handleMessage(
    type: MessageType,
    payload: unknown,
    tabId?: number
  ): Promise<unknown>;
  start(): void;
  stop(): void;
}

/**
 * Mock 의존성 타입
 */
interface MockDeps {
  orchestrator: {
    handleSensitiveInput: jest.Mock;
    analyzeNetworkRequest: jest.Mock;
    clearInputBuffer: jest.Mock;
  };
  getSecurityStatusUseCase: {
    execute: jest.Mock;
  };
  manageSettingsUseCase: {
    getSettings: jest.Mock;
    updateSettings: jest.Mock;
    resetSettings: jest.Mock;
    manageWhitelist: jest.Mock;
    getWhitelistedDomains: jest.Mock;
  };
  manageBlockingUseCase: {
    handleUserAction: jest.Mock;
  };
  eventRepository: {
    findRecent: jest.Mock;
    findByFilter: jest.Mock;
    deleteAll: jest.Mock;
    deleteOlderThan: jest.Mock;
  };
  messenger: {
    onMessage: jest.Mock;
    offMessage: jest.Mock;
    sendToTab: jest.Mock;
  };
}

// Mock MessageHandler for RED phase
let MessageHandler: new (deps: MockDeps) => IMessageHandler;

describe('MessageHandler', () => {
  let handler: IMessageHandler;
  let mockDeps: MockDeps;

  beforeEach(() => {
    // Mock 의존성 설정
    mockDeps = {
      orchestrator: {
        handleSensitiveInput: jest.fn(),
        analyzeNetworkRequest: jest.fn().mockResolvedValue({
          verdict: Verdict.SAFE,
          confidence: 1.0,
          recommendation: Recommendation.PROCEED,
          reason: 'Safe',
          matchedRuleIds: [],
          usedAI: false,
          analysisTimeMs: 10
        }),
        clearInputBuffer: jest.fn()
      },
      getSecurityStatusUseCase: {
        execute: jest.fn().mockResolvedValue({
          overallStatus: 'safe',
          currentDomain: 'example.com',
          isWhitelisted: false,
          recentDangerCount: 0,
          recentSuspiciousCount: 0,
          totalEventCount: 0,
          aiEnabled: true
        })
      },
      manageSettingsUseCase: {
        getSettings: jest.fn().mockResolvedValue({
          aiAnalysisEnabled: true,
          notificationsEnabled: true,
          autoBlockEnabled: false,
          debugMode: false,
          dataRetentionHours: 24,
          whitelistedDomains: []
        }),
        updateSettings: jest.fn().mockResolvedValue(undefined),
        resetSettings: jest.fn().mockResolvedValue(undefined),
        manageWhitelist: jest.fn().mockResolvedValue(undefined),
        getWhitelistedDomains: jest.fn().mockResolvedValue([])
      },
      manageBlockingUseCase: {
        handleUserAction: jest.fn().mockResolvedValue({ success: true, action: 'allow' })
      },
      eventRepository: {
        findRecent: jest.fn().mockResolvedValue([]),
        findByFilter: jest.fn().mockResolvedValue([]),
        deleteAll: jest.fn().mockResolvedValue(undefined),
        deleteOlderThan: jest.fn().mockResolvedValue(0)
      },
      messenger: {
        onMessage: jest.fn(),
        offMessage: jest.fn(),
        sendToTab: jest.fn().mockResolvedValue({ success: true })
      }
    };

    // MessageHandler 동적 로드 시도
    try {
      // eslint-disable-next-line @typescript-eslint/no-require-imports, @typescript-eslint/no-var-requires
      const module = require('@presentation/background/MessageHandler');
      MessageHandler = module.MessageHandler;
      handler = new MessageHandler(mockDeps);
    } catch {
      // RED 단계: 모듈이 아직 없음
      handler = {
        handleMessage: jest.fn().mockResolvedValue(null),
        start: jest.fn(),
        stop: jest.fn()
      };
    }
  });

  afterEach(() => {
    handler.stop();
    jest.clearAllMocks();
  });

  describe('SENSITIVE_INPUT 메시지 처리', () => {
    it('민감 입력을 오케스트레이터에 전달해야 함', async () => {
      const payload = {
        fieldId: 'card-input',
        fieldType: SensitiveFieldType.CARD_NUMBER,
        inputLength: 16,
        timestamp: Date.now()
      };

      await handler.handleMessage(MessageType.SENSITIVE_INPUT, payload, 1);

      expect(mockDeps.orchestrator.handleSensitiveInput).toHaveBeenCalledWith(
        expect.objectContaining({
          fieldId: 'card-input',
          fieldType: SensitiveFieldType.CARD_NUMBER
        })
      );
    });

    it('성공 응답을 반환해야 함', async () => {
      const payload = {
        fieldId: 'password-input',
        fieldType: SensitiveFieldType.PASSWORD,
        inputLength: 8,
        timestamp: Date.now()
      };

      const result = await handler.handleMessage(
        MessageType.SENSITIVE_INPUT,
        payload,
        1
      );

      expect(result).toEqual({ success: true });
    });
  });

  describe('ANALYZE_REQUEST 메시지 처리', () => {
    it('네트워크 요청을 분석해야 함', async () => {
      const payload = {
        request: {
          type: NetworkRequestType.FETCH,
          url: 'https://api.example.com/submit',
          method: 'POST',
          payloadSize: 100,
          timestamp: Date.now()
        },
        recentInputs: [],
        currentDomain: 'example.com'
      };

      await handler.handleMessage(MessageType.ANALYZE_REQUEST, payload, 1);

      expect(mockDeps.orchestrator.analyzeNetworkRequest).toHaveBeenCalledWith(
        payload,
        1
      );
    });

    it('분석 결과를 반환해야 함', async () => {
      const analysisResult = {
        verdict: Verdict.DANGEROUS,
        confidence: 0.95,
        recommendation: Recommendation.BLOCK,
        reason: 'Suspicious external transfer',
        matchedRuleIds: ['D001'],
        usedAI: false,
        analysisTimeMs: 15
      };
      mockDeps.orchestrator.analyzeNetworkRequest.mockResolvedValue(
        analysisResult
      );

      const payload = {
        request: {
          type: NetworkRequestType.FETCH,
          url: 'https://evil.com/steal',
          method: 'POST',
          payloadSize: 500,
          timestamp: Date.now()
        },
        recentInputs: [
          {
            fieldType: SensitiveFieldType.CARD_NUMBER,
            inputLength: 16,
            timestamp: Date.now() - 100
          }
        ],
        currentDomain: 'shop.example.com'
      };

      const result = await handler.handleMessage(
        MessageType.ANALYZE_REQUEST,
        payload,
        1
      );

      expect(result).toEqual(analysisResult);
    });

    it('tabId가 없어도 분석해야 함', async () => {
      const payload = {
        request: {
          type: NetworkRequestType.XHR,
          url: 'https://api.example.com/data',
          method: 'POST',
          payloadSize: 50,
          timestamp: Date.now()
        },
        recentInputs: [],
        currentDomain: 'example.com'
      };

      await handler.handleMessage(MessageType.ANALYZE_REQUEST, payload);

      expect(mockDeps.orchestrator.analyzeNetworkRequest).toHaveBeenCalledWith(
        payload,
        undefined
      );
    });
  });

  describe('GET_STATUS 메시지 처리', () => {
    it('보안 상태를 조회해야 함', async () => {
      const payload = { currentDomain: 'example.com' };

      await handler.handleMessage(MessageType.GET_STATUS, payload);

      expect(mockDeps.getSecurityStatusUseCase.execute).toHaveBeenCalledWith(
        'example.com'
      );
    });

    it('보안 상태를 반환해야 함', async () => {
      const securityStatus = {
        overallStatus: 'warning' as const,
        currentDomain: 'suspicious.com',
        isWhitelisted: false,
        recentDangerCount: 0,
        recentSuspiciousCount: 2,
        totalEventCount: 5,
        aiEnabled: true
      };
      mockDeps.getSecurityStatusUseCase.execute.mockResolvedValue(
        securityStatus
      );

      const payload = { currentDomain: 'suspicious.com' };
      const result = await handler.handleMessage(
        MessageType.GET_STATUS,
        payload
      );

      expect(result).toEqual(securityStatus);
    });
  });

  describe('UPDATE_SETTINGS 메시지 처리', () => {
    it('설정을 업데이트해야 함', async () => {
      const payload = {
        aiAnalysisEnabled: false,
        notificationsEnabled: true
      };

      await handler.handleMessage(MessageType.UPDATE_SETTINGS, payload);

      expect(mockDeps.manageSettingsUseCase.updateSettings).toHaveBeenCalledWith(
        payload
      );
    });

    it('업데이트된 설정을 반환해야 함', async () => {
      const updatedSettings = {
        aiAnalysisEnabled: false,
        notificationsEnabled: true,
        autoBlockEnabled: false,
        debugMode: false,
        dataRetentionHours: 24,
        whitelistedDomains: []
      };
      mockDeps.manageSettingsUseCase.getSettings.mockResolvedValue(
        updatedSettings
      );

      const payload = { aiAnalysisEnabled: false };
      const result = await handler.handleMessage(
        MessageType.UPDATE_SETTINGS,
        payload
      );

      expect(result).toEqual(updatedSettings);
    });

    it('화이트리스트 추가를 처리해야 함', async () => {
      const payload = {
        whitelist: { action: 'add', domain: 'trusted.com' }
      };

      await handler.handleMessage(MessageType.UPDATE_SETTINGS, payload);

      expect(
        mockDeps.manageSettingsUseCase.manageWhitelist
      ).toHaveBeenCalledWith('add', 'trusted.com');
    });

    it('화이트리스트 제거를 처리해야 함', async () => {
      const payload = {
        whitelist: { action: 'remove', domain: 'untrusted.com' }
      };

      await handler.handleMessage(MessageType.UPDATE_SETTINGS, payload);

      expect(
        mockDeps.manageSettingsUseCase.manageWhitelist
      ).toHaveBeenCalledWith('remove', 'untrusted.com');
    });
  });

  describe('GET_EVENTS 메시지 처리', () => {
    it('최근 이벤트를 조회해야 함', async () => {
      const payload = { limit: 10 };

      await handler.handleMessage(MessageType.GET_EVENTS, payload);

      expect(mockDeps.eventRepository.findRecent).toHaveBeenCalledWith(10);
    });

    it('필터로 이벤트를 조회해야 함', async () => {
      const payload = {
        verdict: Verdict.DANGEROUS,
        domain: 'evil.com',
        limit: 50
      };

      await handler.handleMessage(MessageType.GET_EVENTS, payload);

      expect(mockDeps.eventRepository.findByFilter).toHaveBeenCalledWith(
        expect.objectContaining({
          verdict: Verdict.DANGEROUS,
          domain: 'evil.com',
          limit: 50
        })
      );
    });

    it('이벤트 목록을 반환해야 함', async () => {
      const events = [
        {
          id: 'event-1',
          verdict: Verdict.DANGEROUS,
          confidence: 0.95,
          targetDomain: 'evil.com',
          currentDomain: 'shop.com',
          reason: 'Suspicious',
          timestamp: Date.now()
        }
      ];
      mockDeps.eventRepository.findRecent.mockResolvedValue(events);

      const payload = { limit: 10 };
      const result = await handler.handleMessage(
        MessageType.GET_EVENTS,
        payload
      );

      expect(result).toEqual(events);
    });
  });

  describe('CLEAR_DATA 메시지 처리', () => {
    it('모든 데이터를 삭제해야 함', async () => {
      const payload = { all: true };

      await handler.handleMessage(MessageType.CLEAR_DATA, payload);

      expect(mockDeps.eventRepository.deleteAll).toHaveBeenCalled();
      expect(mockDeps.orchestrator.clearInputBuffer).toHaveBeenCalled();
    });

    it('특정 기간 이전 데이터만 삭제해야 함', async () => {
      const timestamp = Date.now() - 24 * 60 * 60 * 1000;
      const payload = { olderThan: timestamp };

      await handler.handleMessage(MessageType.CLEAR_DATA, payload);

      expect(mockDeps.eventRepository.deleteOlderThan).toHaveBeenCalledWith(
        timestamp
      );
    });

    it('삭제된 항목 수를 반환해야 함', async () => {
      mockDeps.eventRepository.deleteOlderThan.mockResolvedValue(5);

      const timestamp = Date.now() - 12 * 60 * 60 * 1000;
      const payload = { olderThan: timestamp };
      const result = await handler.handleMessage(
        MessageType.CLEAR_DATA,
        payload
      );

      expect(result).toEqual({ deletedCount: 5 });
    });
  });

  describe('에러 처리', () => {
    it('알 수 없는 메시지 타입에 대해 에러를 반환해야 함', async () => {
      const result = await handler.handleMessage(
        'UNKNOWN_TYPE' as MessageType,
        {}
      );

      expect(result).toEqual(
        expect.objectContaining({ error: expect.any(String) })
      );
    });

    it('분석 실패 시 에러를 반환해야 함', async () => {
      mockDeps.orchestrator.analyzeNetworkRequest.mockRejectedValue(
        new Error('Analysis failed')
      );

      const payload = {
        request: {
          type: NetworkRequestType.FETCH,
          url: 'https://api.example.com/submit',
          method: 'POST',
          payloadSize: 100,
          timestamp: Date.now()
        },
        recentInputs: [],
        currentDomain: 'example.com'
      };

      const result = await handler.handleMessage(
        MessageType.ANALYZE_REQUEST,
        payload,
        1
      );

      expect(result).toEqual(
        expect.objectContaining({ error: expect.any(String) })
      );
    });

    it('설정 업데이트 실패 시 에러를 반환해야 함', async () => {
      mockDeps.manageSettingsUseCase.updateSettings.mockRejectedValue(
        new Error('Update failed')
      );

      const payload = { aiAnalysisEnabled: false };
      const result = await handler.handleMessage(
        MessageType.UPDATE_SETTINGS,
        payload
      );

      expect(result).toEqual(
        expect.objectContaining({ error: expect.any(String) })
      );
    });
  });

  describe('라이프사이클', () => {
    it('start()로 메시지 리스너를 등록해야 함', () => {
      handler.start();

      // 모든 메시지 타입에 대해 핸들러 등록 확인
      expect(mockDeps.messenger.onMessage).toHaveBeenCalled();
    });

    it('stop()으로 메시지 리스너를 해제해야 함', () => {
      handler.start();
      handler.stop();

      expect(mockDeps.messenger.offMessage).toHaveBeenCalled();
    });

    it('여러 번 start() 호출해도 안전해야 함', () => {
      expect(() => {
        handler.start();
        handler.start();
        handler.start();
      }).not.toThrow();
    });

    it('여러 번 stop() 호출해도 안전해야 함', () => {
      handler.start();

      expect(() => {
        handler.stop();
        handler.stop();
        handler.stop();
      }).not.toThrow();
    });
  });

  describe('USER_ACTION 메시지 처리', () => {
    it('사용자 허용 액션을 처리해야 함', async () => {
      const payload = {
        action: 'allow',
        domain: 'allowed.com',
        remember: true
      };

      await handler.handleMessage(MessageType.USER_ACTION, payload, 1);

      // remember가 true면 화이트리스트에 추가
      expect(
        mockDeps.manageSettingsUseCase.manageWhitelist
      ).toHaveBeenCalledWith('add', 'allowed.com');
    });

    it('사용자 차단 액션을 처리해야 함', async () => {
      const payload = {
        action: 'block',
        domain: 'blocked.com',
        remember: false
      };

      const result = await handler.handleMessage(
        MessageType.USER_ACTION,
        payload,
        1
      );

      expect(result).toMatchObject({ success: true });
    });

    it('사용자 닫기 액션을 처리해야 함', async () => {
      const payload = {
        action: 'dismiss',
        domain: 'example.com'
      };

      const result = await handler.handleMessage(
        MessageType.USER_ACTION,
        payload,
        1
      );

      expect(result).toMatchObject({ success: true });
    });
  });
});
