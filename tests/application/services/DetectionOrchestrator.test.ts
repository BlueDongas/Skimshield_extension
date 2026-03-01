/**
 * DetectionOrchestrator 테스트
 */

import { AnalysisRequestDTO } from '@application/dto/AnalysisDTO';
import {
  DetectionOrchestrator,
  DetectionOrchestratorDeps
} from '@application/services/DetectionOrchestrator';
import { NetworkRequestType } from '@domain/entities/NetworkRequest';
import { IAIAnalyzer } from '@domain/ports/IAIAnalyzer';
import { IDetectionEngine } from '@domain/ports/IDetectionEngine';
import { IEventRepository } from '@domain/ports/IEventRepository';
import { IMessenger, MessageType } from '@domain/ports/IMessenger';
import { ISettingsRepository } from '@domain/ports/ISettingsRepository';
import { SensitiveFieldType } from '@domain/value-objects/SensitiveFieldType';
import { Verdict } from '@domain/value-objects/Verdict';

/**
 * Mock 의존성 생성 함수들
 */
function createMockHeuristicEngine(): IDetectionEngine {
  return {
    analyze: jest.fn().mockReturnValue({
      verdict: Verdict.SAFE,
      confidence: 0.8,
      matchedRules: [],
      reason: '안전'
    }),
    registerRule: jest.fn(),
    unregisterRule: jest.fn(),
    getRules: jest.fn().mockReturnValue([]),
    setRuleEnabled: jest.fn()
  };
}

function createMockAIAnalyzer(): IAIAnalyzer {
  return {
    analyze: jest.fn().mockResolvedValue({
      verdict: Verdict.SAFE,
      confidence: 0.85,
      reason: 'AI 분석 결과 안전'
    }),
    isAvailable: jest.fn().mockResolvedValue(true),
    isEnabled: jest.fn().mockReturnValue(true),
    setEnabled: jest.fn()
  };
}

function createMockSettingsRepository(): ISettingsRepository {
  return {
    getAll: jest.fn().mockResolvedValue({
      aiAnalysisEnabled: true,
      whitelistedDomains: [],
      notificationsEnabled: true,
      autoBlockEnabled: false,
      debugMode: false,
      dataRetentionHours: 24
    }),
    get: jest.fn().mockImplementation((key: string) => {
      if (key === 'aiAnalysisEnabled') return Promise.resolve(true);
      if (key === 'notificationsEnabled') return Promise.resolve(true);
      if (key === 'autoBlockEnabled') return Promise.resolve(false);
      return Promise.resolve(true);
    }),
    set: jest.fn().mockResolvedValue(undefined),
    setMultiple: jest.fn().mockResolvedValue(undefined),
    reset: jest.fn().mockResolvedValue(undefined),
    isWhitelisted: jest.fn().mockResolvedValue(false),
    addToWhitelist: jest.fn().mockResolvedValue(undefined),
    removeFromWhitelist: jest.fn().mockResolvedValue(undefined)
  };
}

function createMockEventRepository(): IEventRepository {
  return {
    save: jest.fn().mockResolvedValue(undefined),
    findById: jest.fn().mockResolvedValue(null),
    findByFilter: jest.fn().mockResolvedValue([]),
    findByDomain: jest.fn().mockResolvedValue([]),
    findRecent: jest.fn().mockResolvedValue([]),
    delete: jest.fn().mockResolvedValue(undefined),
    deleteOlderThan: jest.fn().mockResolvedValue(0),
    deleteAll: jest.fn().mockResolvedValue(undefined),
    count: jest.fn().mockResolvedValue(0),
    exportAll: jest.fn().mockResolvedValue([])
  };
}

function createMockMessenger(): IMessenger {
  return {
    sendToTab: jest.fn().mockResolvedValue({ success: true }),
    sendToBackground: jest.fn().mockResolvedValue({ success: true }),
    broadcast: jest.fn().mockResolvedValue(undefined),
    onMessage: jest.fn(),
    offMessage: jest.fn()
  };
}

/**
 * 테스트용 분석 요청 생성
 */
function createTestAnalysisRequest(
  overrides?: Partial<AnalysisRequestDTO>
): AnalysisRequestDTO {
  const now = Date.now();
  return {
    request: {
      type: NetworkRequestType.FETCH,
      url: 'https://api.example.com/data',
      method: 'POST',
      payloadSize: 256,
      timestamp: now
    },
    recentInputs: [],
    currentDomain: 'shop.example.com',
    ...overrides
  };
}

describe('DetectionOrchestrator', () => {
  let orchestrator: DetectionOrchestrator;
  let mockHeuristicEngine: IDetectionEngine;
  let mockAIAnalyzer: IAIAnalyzer;
  let mockSettingsRepo: ISettingsRepository;
  let mockEventRepo: IEventRepository;
  let mockMessenger: IMessenger;

  beforeEach(() => {
    mockHeuristicEngine = createMockHeuristicEngine();
    mockAIAnalyzer = createMockAIAnalyzer();
    mockSettingsRepo = createMockSettingsRepository();
    mockEventRepo = createMockEventRepository();
    mockMessenger = createMockMessenger();

    const deps: DetectionOrchestratorDeps = {
      heuristicEngine: mockHeuristicEngine,
      aiAnalyzer: mockAIAnalyzer,
      settingsRepository: mockSettingsRepo,
      eventRepository: mockEventRepo,
      messenger: mockMessenger
    };

    orchestrator = new DetectionOrchestrator(deps);
  });

  describe('handleSensitiveInput', () => {
    it('민감 입력을 버퍼에 저장해야 한다', () => {
      orchestrator.handleSensitiveInput({
        fieldId: 'test-field',
        fieldType: SensitiveFieldType.CARD_NUMBER,
        inputLength: 16,
        timestamp: Date.now()
      });

      const inputs = orchestrator.getRecentInputs(1000);
      expect(inputs).toHaveLength(1);
      expect(inputs[0].fieldType).toBe(SensitiveFieldType.CARD_NUMBER);
    });

    it('오래된 입력은 자동으로 정리해야 한다', () => {
      const oldTime = Date.now() - 60000; // 60초 전

      orchestrator.handleSensitiveInput({
        fieldId: 'old-field',
        fieldType: SensitiveFieldType.CARD_NUMBER,
        inputLength: 16,
        timestamp: oldTime
      });

      const inputs = orchestrator.getRecentInputs(5000);
      expect(inputs).toHaveLength(0);
    });

    it('여러 입력을 저장해야 한다', () => {
      const now = Date.now();

      orchestrator.handleSensitiveInput({
        fieldId: 'field-1',
        fieldType: SensitiveFieldType.CARD_NUMBER,
        inputLength: 16,
        timestamp: now - 100
      });

      orchestrator.handleSensitiveInput({
        fieldId: 'field-2',
        fieldType: SensitiveFieldType.CVV,
        inputLength: 3,
        timestamp: now
      });

      const inputs = orchestrator.getRecentInputs(1000);
      expect(inputs).toHaveLength(2);
    });
  });

  describe('analyzeNetworkRequest', () => {
    it('네트워크 요청을 분석해야 한다', async () => {
      const request = createTestAnalysisRequest();

      const result = await orchestrator.analyzeNetworkRequest(request);

      expect(result).toBeDefined();
      expect(result.verdict).toBeDefined();
    });

    it('최근 민감 입력을 분석에 포함해야 한다', async () => {
      const now = Date.now();

      orchestrator.handleSensitiveInput({
        fieldId: 'field-1',
        fieldType: SensitiveFieldType.CARD_NUMBER,
        inputLength: 16,
        timestamp: now - 100
      });

      const request = createTestAnalysisRequest({
        request: {
          type: NetworkRequestType.FETCH,
          url: 'https://api.example.com/data',
          method: 'POST',
          payloadSize: 256,
          timestamp: now
        }
      });

      await orchestrator.analyzeNetworkRequest(request);

      expect(mockHeuristicEngine.analyze).toHaveBeenCalledWith(
        expect.objectContaining({
          recentInputs: expect.arrayContaining([
            expect.objectContaining({
              fieldType: SensitiveFieldType.CARD_NUMBER
            })
          ])
        })
      );
    });

    it('위험한 결과는 이벤트로 저장해야 한다', async () => {
      (mockHeuristicEngine.analyze as jest.Mock).mockReturnValue({
        verdict: Verdict.DANGEROUS,
        confidence: 0.95,
        matchedRules: [{ ruleId: 'D001', ruleName: 'test', checkResult: { match: true, confidence: 0.95 } }],
        reason: '위험 감지'
      });

      const request = createTestAnalysisRequest();
      await orchestrator.analyzeNetworkRequest(request);

      expect(mockEventRepo.save).toHaveBeenCalled();
    });

    it('안전한 결과는 이벤트로 저장하지 않아야 한다', async () => {
      (mockHeuristicEngine.analyze as jest.Mock).mockReturnValue({
        verdict: Verdict.SAFE,
        confidence: 0.9,
        matchedRules: [],
        reason: '안전'
      });

      const request = createTestAnalysisRequest();
      await orchestrator.analyzeNetworkRequest(request);

      expect(mockEventRepo.save).not.toHaveBeenCalled();
    });

    it('의심스러운 결과도 이벤트로 저장해야 한다', async () => {
      (mockHeuristicEngine.analyze as jest.Mock).mockReturnValue({
        verdict: Verdict.SUSPICIOUS,
        confidence: 0.7,
        matchedRules: [],
        reason: '의심'
      });

      // AI가 없으면 휴리스틱 결과 그대로 사용
      (mockAIAnalyzer.isAvailable as jest.Mock).mockResolvedValue(false);

      const request = createTestAnalysisRequest();
      await orchestrator.analyzeNetworkRequest(request);

      expect(mockEventRepo.save).toHaveBeenCalled();
    });
  });

  describe('알림', () => {
    it('위험한 결과를 이벤트로 저장하고 반환해야 한다', async () => {
      (mockHeuristicEngine.analyze as jest.Mock).mockReturnValue({
        verdict: Verdict.DANGEROUS,
        confidence: 0.95,
        matchedRules: [],
        reason: '위험'
      });

      const request = createTestAnalysisRequest();
      const result = await orchestrator.analyzeNetworkRequest(request, 123);

      expect(result.verdict).toBe(Verdict.DANGEROUS);
      expect(mockEventRepo.save).toHaveBeenCalled();
      // 경고 표시는 content script가 분석 응답을 받아 직접 처리
      expect(mockMessenger.sendToTab).not.toHaveBeenCalled();
    });

    it('알림이 비활성화되면 알림을 보내지 않아야 한다', async () => {
      (mockSettingsRepo.get as jest.Mock).mockImplementation((key: string) => {
        if (key === 'notificationsEnabled') return Promise.resolve(false);
        return Promise.resolve(true);
      });

      (mockHeuristicEngine.analyze as jest.Mock).mockReturnValue({
        verdict: Verdict.DANGEROUS,
        confidence: 0.95,
        matchedRules: [],
        reason: '위험'
      });

      const request = createTestAnalysisRequest();
      await orchestrator.analyzeNetworkRequest(request, 123);

      expect(mockMessenger.sendToTab).not.toHaveBeenCalled();
    });

    it('의심스러운 결과도 이벤트로 저장하고 반환해야 한다', async () => {
      (mockHeuristicEngine.analyze as jest.Mock).mockReturnValue({
        verdict: Verdict.SUSPICIOUS,
        confidence: 0.7,
        matchedRules: [],
        reason: '의심'
      });

      // AI가 없으면 휴리스틱 결과 그대로 사용
      (mockAIAnalyzer.isAvailable as jest.Mock).mockResolvedValue(false);

      const request = createTestAnalysisRequest();
      const result = await orchestrator.analyzeNetworkRequest(request, 456);

      expect(result.verdict).toBe(Verdict.SUSPICIOUS);
      expect(mockEventRepo.save).toHaveBeenCalled();
      // 경고 표시는 content script가 분석 응답을 받아 직접 처리
      expect(mockMessenger.sendToTab).not.toHaveBeenCalled();
    });

    it('tabId가 없으면 알림을 보내지 않아야 한다', async () => {
      (mockHeuristicEngine.analyze as jest.Mock).mockReturnValue({
        verdict: Verdict.DANGEROUS,
        confidence: 0.95,
        matchedRules: [],
        reason: '위험'
      });

      const request = createTestAnalysisRequest();
      await orchestrator.analyzeNetworkRequest(request);

      expect(mockMessenger.sendToTab).not.toHaveBeenCalled();
    });
  });

  describe('clearInputBuffer', () => {
    it('입력 버퍼를 비워야 한다', () => {
      orchestrator.handleSensitiveInput({
        fieldId: 'field-1',
        fieldType: SensitiveFieldType.CARD_NUMBER,
        inputLength: 16,
        timestamp: Date.now()
      });

      orchestrator.clearInputBuffer();

      const inputs = orchestrator.getRecentInputs(10000);
      expect(inputs).toHaveLength(0);
    });
  });

  describe('getRecentInputs', () => {
    it('지정된 시간 내의 입력만 반환해야 한다', () => {
      const now = Date.now();

      orchestrator.handleSensitiveInput({
        fieldId: 'old',
        fieldType: SensitiveFieldType.CARD_NUMBER,
        inputLength: 16,
        timestamp: now - 2000
      });

      orchestrator.handleSensitiveInput({
        fieldId: 'recent',
        fieldType: SensitiveFieldType.CVV,
        inputLength: 3,
        timestamp: now - 100
      });

      const inputs = orchestrator.getRecentInputs(1000);
      expect(inputs).toHaveLength(1);
      expect(inputs[0].fieldId).toBe('recent');
    });
  });
});
