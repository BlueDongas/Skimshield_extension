/**
 * HeuristicEngine 도메인 서비스 테스트
 */

import {
  createDetectionRule,
  RuleCategory,
  RuleCheckResult
} from '@domain/entities/DetectionRule';
import {
  createNetworkRequest,
  NetworkRequestType
} from '@domain/entities/NetworkRequest';
import { createSensitiveInput } from '@domain/entities/SensitiveInput';
import { DetectionContext } from '@domain/ports/IDetectionEngine';
import {
  HeuristicEngine,
  createHeuristicEngine
} from '@domain/services/HeuristicEngine';
import { SensitiveFieldType } from '@domain/value-objects/SensitiveFieldType';
import { Verdict } from '@domain/value-objects/Verdict';

describe('HeuristicEngine', () => {
  let engine: HeuristicEngine;

  beforeEach(() => {
    engine = createHeuristicEngine();
    // createHeuristicEngine()은 기본 규칙을 자동 등록하므로
    // 단위 테스트용으로 모두 초기화한다
    [...engine.getRules()].forEach((rule) => engine.unregisterRule(rule.id));
  });

  describe('createHeuristicEngine', () => {
    it('새로운 휴리스틱 엔진을 생성해야 한다', () => {
      expect(engine).toBeDefined();
      expect(typeof engine.analyze).toBe('function');
      expect(typeof engine.registerRule).toBe('function');
    });

    it('초기 상태에서 규칙이 없어야 한다', () => {
      expect(engine.getRules()).toHaveLength(0);
    });
  });

  describe('registerRule', () => {
    it('규칙을 등록할 수 있어야 한다', () => {
      const rule = createDetectionRule({
        id: 'TEST001',
        name: 'test_rule',
        description: '테스트 규칙',
        category: RuleCategory.DANGER,
        priority: 50,
        enabled: true,
        check: (): RuleCheckResult => ({ match: false, confidence: 0 })
      });

      engine.registerRule(rule);
      expect(engine.getRules()).toHaveLength(1);
    });

    it('동일 ID 규칙을 중복 등록하면 덮어쓰기해야 한다', () => {
      const rule1 = createDetectionRule({
        id: 'TEST001',
        name: 'test_rule_1',
        description: '테스트 규칙 1',
        category: RuleCategory.DANGER,
        priority: 50,
        enabled: true,
        check: (): RuleCheckResult => ({ match: false, confidence: 0 })
      });

      const rule2 = createDetectionRule({
        id: 'TEST001',
        name: 'test_rule_2',
        description: '테스트 규칙 2',
        category: RuleCategory.DANGER,
        priority: 60,
        enabled: true,
        check: (): RuleCheckResult => ({ match: false, confidence: 0 })
      });

      engine.registerRule(rule1);
      engine.registerRule(rule2);

      expect(engine.getRules()).toHaveLength(1);
      expect(engine.getRules()[0]?.name).toBe('test_rule_2');
    });
  });

  describe('unregisterRule', () => {
    it('규칙을 등록 해제할 수 있어야 한다', () => {
      const rule = createDetectionRule({
        id: 'TEST001',
        name: 'test_rule',
        description: '테스트 규칙',
        category: RuleCategory.DANGER,
        priority: 50,
        enabled: true,
        check: (): RuleCheckResult => ({ match: false, confidence: 0 })
      });

      engine.registerRule(rule);
      engine.unregisterRule('TEST001');

      expect(engine.getRules()).toHaveLength(0);
    });
  });

  describe('setRuleEnabled', () => {
    it('규칙을 활성화/비활성화할 수 있어야 한다', () => {
      const rule = createDetectionRule({
        id: 'TEST001',
        name: 'test_rule',
        description: '테스트 규칙',
        category: RuleCategory.DANGER,
        priority: 50,
        enabled: true,
        check: (): RuleCheckResult => ({ match: false, confidence: 0 })
      });

      engine.registerRule(rule);
      engine.setRuleEnabled('TEST001', false);

      const rules = engine.getRules();
      expect(rules[0]?.enabled).toBe(false);
    });
  });

  describe('analyze', () => {
    const createTestContext = (
      overrides?: Partial<{
        domain: string;
        currentDomain: string;
        timestamp: number;
        recentInputTimestamp: number;
        requestType: NetworkRequestType;
      }>
    ): DetectionContext => {
      const now = Date.now();
      const config = {
        domain: 'api.example.com',
        currentDomain: 'shop.example.com',
        timestamp: now,
        recentInputTimestamp: now - 200,
        requestType: NetworkRequestType.FETCH,
        ...overrides
      };

      return {
        request: createNetworkRequest({
          type: config.requestType,
          url: `https://${config.domain}/api/data`,
          method: 'POST',
          payloadSize: 256,
          timestamp: config.timestamp
        }),
        recentInputs: [
          createSensitiveInput({
            fieldId: 'card-number',
            fieldType: SensitiveFieldType.CARD_NUMBER,
            inputLength: 16,
            timestamp: config.recentInputTimestamp,
            domPath: 'form > input'
          })
        ],
        currentDomain: config.currentDomain
      };
    };

    it('규칙이 없으면 UNKNOWN을 반환해야 한다', () => {
      const context = createTestContext();
      const result = engine.analyze(context);

      expect(result.verdict).toBe(Verdict.UNKNOWN);
      expect(result.matchedRules).toHaveLength(0);
    });

    it('위험 규칙이 매칭되면 DANGEROUS를 반환해야 한다', () => {
      const dangerRule = createDetectionRule({
        id: 'D001',
        name: 'danger_rule',
        description: '위험 규칙',
        category: RuleCategory.DANGER,
        priority: 100,
        enabled: true,
        check: (): RuleCheckResult => ({
          match: true,
          confidence: 0.95,
          details: { reason: 'test' }
        })
      });

      engine.registerRule(dangerRule);

      const context = createTestContext();
      const result = engine.analyze(context);

      expect(result.verdict).toBe(Verdict.DANGEROUS);
      expect(result.confidence).toBe(0.95);
      expect(result.matchedRules).toHaveLength(1);
      expect(result.matchedRules[0]?.ruleId).toBe('D001');
    });

    it('안전 규칙이 매칭되면 SAFE를 반환해야 한다', () => {
      const safeRule = createDetectionRule({
        id: 'S001',
        name: 'safe_rule',
        description: '안전 규칙',
        category: RuleCategory.SAFE,
        priority: 100,
        enabled: true,
        check: (): RuleCheckResult => ({
          match: true,
          confidence: 0.95,
          details: { reason: 'test' }
        })
      });

      engine.registerRule(safeRule);

      const context = createTestContext();
      const result = engine.analyze(context);

      expect(result.verdict).toBe(Verdict.SAFE);
      expect(result.confidence).toBe(0.95);
    });

    it('비활성화된 규칙은 실행하지 않아야 한다', () => {
      const disabledRule = createDetectionRule({
        id: 'D001',
        name: 'disabled_rule',
        description: '비활성화 규칙',
        category: RuleCategory.DANGER,
        priority: 100,
        enabled: false,
        check: (): RuleCheckResult => ({
          match: true,
          confidence: 0.95
        })
      });

      engine.registerRule(disabledRule);

      const context = createTestContext();
      const result = engine.analyze(context);

      expect(result.verdict).toBe(Verdict.UNKNOWN);
      expect(result.matchedRules).toHaveLength(0);
    });

    it('우선순위가 높은 규칙이 먼저 실행되어야 한다', () => {
      const executionOrder: string[] = [];

      const lowPriorityRule = createDetectionRule({
        id: 'LOW',
        name: 'low_priority',
        description: '낮은 우선순위',
        category: RuleCategory.DANGER,
        priority: 10,
        enabled: true,
        check: (): RuleCheckResult => {
          executionOrder.push('LOW');
          return { match: false, confidence: 0 };
        }
      });

      const highPriorityRule = createDetectionRule({
        id: 'HIGH',
        name: 'high_priority',
        description: '높은 우선순위',
        category: RuleCategory.DANGER,
        priority: 100,
        enabled: true,
        check: (): RuleCheckResult => {
          executionOrder.push('HIGH');
          return { match: false, confidence: 0 };
        }
      });

      // 낮은 우선순위를 먼저 등록
      engine.registerRule(lowPriorityRule);
      engine.registerRule(highPriorityRule);

      const context = createTestContext();
      engine.analyze(context);

      expect(executionOrder[0]).toBe('HIGH');
      expect(executionOrder[1]).toBe('LOW');
    });

    it('위험 규칙 매칭 시 안전 규칙은 실행하지 않아야 한다', () => {
      let safeRuleExecuted = false;

      const dangerRule = createDetectionRule({
        id: 'D001',
        name: 'danger_rule',
        description: '위험 규칙',
        category: RuleCategory.DANGER,
        priority: 100,
        enabled: true,
        check: (): RuleCheckResult => ({
          match: true,
          confidence: 0.95
        })
      });

      const safeRule = createDetectionRule({
        id: 'S001',
        name: 'safe_rule',
        description: '안전 규칙',
        category: RuleCategory.SAFE,
        priority: 100,
        enabled: true,
        check: (): RuleCheckResult => {
          safeRuleExecuted = true;
          return { match: true, confidence: 0.95 };
        }
      });

      engine.registerRule(dangerRule);
      engine.registerRule(safeRule);

      const context = createTestContext();
      engine.analyze(context);

      expect(safeRuleExecuted).toBe(false);
    });

    it('여러 위험 규칙이 매칭되면 가장 높은 신뢰도를 사용해야 한다', () => {
      const rule1 = createDetectionRule({
        id: 'D001',
        name: 'rule_1',
        description: '규칙 1',
        category: RuleCategory.DANGER,
        priority: 100,
        enabled: true,
        check: (): RuleCheckResult => ({
          match: true,
          confidence: 0.85
        })
      });

      const rule2 = createDetectionRule({
        id: 'D002',
        name: 'rule_2',
        description: '규칙 2',
        category: RuleCategory.DANGER,
        priority: 90,
        enabled: true,
        check: (): RuleCheckResult => ({
          match: true,
          confidence: 0.95
        })
      });

      engine.registerRule(rule1);
      engine.registerRule(rule2);

      const context = createTestContext();
      const result = engine.analyze(context);

      expect(result.confidence).toBe(0.95);
      expect(result.matchedRules).toHaveLength(2);
    });

    it('위험/안전 모두 매칭되지 않으면 UNKNOWN을 반환해야 한다', () => {
      const dangerRule = createDetectionRule({
        id: 'D001',
        name: 'danger_rule',
        description: '위험 규칙',
        category: RuleCategory.DANGER,
        priority: 100,
        enabled: true,
        check: (): RuleCheckResult => ({
          match: false,
          confidence: 0
        })
      });

      const safeRule = createDetectionRule({
        id: 'S001',
        name: 'safe_rule',
        description: '안전 규칙',
        category: RuleCategory.SAFE,
        priority: 100,
        enabled: true,
        check: (): RuleCheckResult => ({
          match: false,
          confidence: 0
        })
      });

      engine.registerRule(dangerRule);
      engine.registerRule(safeRule);

      const context = createTestContext();
      const result = engine.analyze(context);

      expect(result.verdict).toBe(Verdict.UNKNOWN);
    });
  });
});
