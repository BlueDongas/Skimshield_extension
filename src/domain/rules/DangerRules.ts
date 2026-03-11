/**
 * ============================================================================
 * 파일: DangerRules.ts
 * ============================================================================
 *
 * [역할]
 * 폼재킹 공격을 탐지하는 "위험" 휴리스틱 규칙들을 정의합니다.
 * 이 규칙에 매칭되면 해당 요청은 DANGEROUS로 판정됩니다.
 *
 * [비유]
 * "수상한 행동 패턴 목록"과 같습니다:
 * - 이런 패턴이 감지되면 공격일 가능성이 높다고 판단
 *
 * [정의된 규칙들]
 *
 * D001: immediate_external_transfer (우선순위 100) ⭐ 가장 중요
 * - 민감 정보 입력 후 500ms 이내에 외부 도메인으로 전송
 * - 폼재킹의 전형적인 패턴 (입력 직후 빠르게 탈취)
 * - 시간이 짧을수록 더 의심 (100ms 이내 = 0.98 신뢰도)
 *
 * D002: known_malicious_domain (우선순위 99)
 * - 알려진 악성 도메인 패턴으로의 전송
 * - 예: analytics-track.info, g00gle-analytics.com (타이포스쿼팅)
 * - 의심스러운 TLD (.tk, .ml 등) 포함
 *
 * D003: suspicious_cdn_pattern (우선순위 95)
 * - CDN이나 분석 서비스를 위장한 도메인
 * - 예: cdn123.something.xyz, analytics-01.fake.net
 * - 최근 5초 이내 민감 입력이 있어야 매칭
 *
 * D004: card_data_to_analytics (우선순위 94)
 * - 카드 정보 입력 후 분석 서비스(GA 등)로 전송
 * - 정상적인 분석 서비스가 카드 정보를 수집할 이유 없음
 * - 1초 이내 카드 입력 + 분석 서비스 요청 = 위험
 *
 * D005: beacon_with_sensitive (우선순위 93)
 * - Beacon API를 통한 외부 전송 + 최근 민감 입력
 * - Beacon API: 페이지 종료 시에도 데이터 전송 가능
 * - 폼재킹에서 탐지 회피용으로 자주 사용
 *
 * [왜 이런 패턴이 위험한가?]
 * 폼재킹 공격은:
 * 1. 웹페이지에 악성 스크립트를 삽입
 * 2. 사용자 입력을 가로채서
 * 3. 공격자 서버로 빠르게 전송
 * → 이 규칙들이 그 행동 패턴을 탐지
 *
 * [다른 파일과의 관계]
 * - HeuristicEngine.ts: 이 규칙들을 등록하고 실행
 * - SafeRules.ts: 반대로 안전 패턴 정의
 * - DetectionOrchestrator.ts: 규칙 실행 결과 처리
 *
 * [흐름]
 * HeuristicEngine.analyze() → 위험 규칙 먼저 체크
 * → D001~D005 중 하나라도 매칭 → DANGEROUS 반환 + 경고
 * ============================================================================
 */

import {
  createDetectionRule,
  DetectionRule,
  RuleCategory
} from '@domain/entities/DetectionRule';
import { NetworkRequestType } from '@domain/entities/NetworkRequest';
import { DetectionContext } from '@domain/ports/IDetectionEngine';
import {
  isCardRelatedField,
  SensitiveFieldType
} from '@domain/value-objects/SensitiveFieldType';

/**
 * 동일 도메인 확인 헬퍼
 */
function isSameDomain(domain1: string, domain2: string): boolean {
  return (
    domain1 === domain2 ||
    domain1.endsWith(`.${domain2}`) ||
    domain2.endsWith(`.${domain1}`)
  );
}

/**
 * 민감 필드 타입 목록
 */
const SENSITIVE_FIELD_TYPES: readonly SensitiveFieldType[] = [
  SensitiveFieldType.CARD_NUMBER,
  SensitiveFieldType.CVV,
  SensitiveFieldType.EXPIRY_DATE,
  SensitiveFieldType.PASSWORD
];

/**
 * 카드 관련 필드 타입 목록
 */
const CARD_FIELD_TYPES: readonly SensitiveFieldType[] = [
  SensitiveFieldType.CARD_NUMBER,
  SensitiveFieldType.CVV,
  SensitiveFieldType.EXPIRY_DATE
];

/**
 * D001: 즉시 외부 전송
 * 민감 입력 후 500ms 이내 외부 도메인으로 전송 감지
 */
export function createD001Rule(): DetectionRule {
  return createDetectionRule({
    id: 'D001',
    name: 'immediate_external_transfer',
    description: '민감 정보 입력 후 500ms 이내 외부 도메인으로 전송 감지',
    category: RuleCategory.DANGER,
    priority: 100,
    enabled: true,
    tags: ['timing', 'external', 'critical'],

    check: (contextUnknown) => {
      const context = contextUnknown as DetectionContext;
      const { request, recentInputs, currentDomain } = context;

      // 민감 입력 중 요청과 가장 가까운 것 선택 (postMessage 비동기 지연 고려)
      const sensitiveInputs = recentInputs.filter((input) =>
        SENSITIVE_FIELD_TYPES.includes(input.fieldType)
      );

      if (sensitiveInputs.length === 0) {
        return { match: false, confidence: 0 };
      }

      const sensitiveInput = sensitiveInputs.reduce((closest, current) =>
        Math.abs(current.timestamp - request.timestamp) <
        Math.abs(closest.timestamp - request.timestamp)
          ? current
          : closest
      );

      // 시간 차이 계산 (절대값: postMessage 비동기 전달로 순서가 뒤바뀔 수 있음)
      const timeDiff = Math.abs(request.timestamp - sensitiveInput.timestamp);

      // 외부 도메인 확인
      const isExternal = !isSameDomain(request.domain, currentDomain);

      // 조건: 500ms 이내 + 외부 도메인
      const isMatch = timeDiff < 500 && isExternal;

      if (!isMatch) {
        return { match: false, confidence: 0 };
      }

      // 시간이 짧을수록 더 의심스러움
      let confidence: number;
      if (timeDiff < 100) {
        confidence = 0.98;
      } else if (timeDiff < 250) {
        confidence = 0.95;
      } else {
        confidence = 0.9;
      }

      return {
        match: true,
        confidence,
        details: {
          timeDiff,
          targetDomain: request.domain,
          inputType: sensitiveInput.fieldType,
          threshold: 500
        }
      };
    }
  });
}

/**
 * 악성 도메인 패턴 정의
 */
interface MaliciousPattern {
  pattern: RegExp;
  type: string;
  severity: number;
}

const MALICIOUS_PATTERNS: readonly MaliciousPattern[] = [
  // 알려진 스키머 도메인
  { pattern: /analytics-track\.info$/i, type: 'skimmer', severity: 1.0 },
  { pattern: /cdn-analytics\.net$/i, type: 'skimmer', severity: 1.0 },
  { pattern: /track-data\.com$/i, type: 'skimmer', severity: 0.95 },

  // 타이포스쿼팅 패턴
  { pattern: /g00gle-analytics\.com$/i, type: 'typosquat', severity: 0.98 },
  { pattern: /googl3\.com$/i, type: 'typosquat', severity: 0.98 },
  { pattern: /stripe-api\.net$/i, type: 'typosquat', severity: 0.97 },

  // 의심스러운 TLD + 패턴 조합
  { pattern: /^[a-z]{2,4}\.(tk|ml|ga|cf|gq)$/i, type: 'suspicious_tld', severity: 0.8 },

  // 인코딩된/난독화된 도메인
  { pattern: /^[a-z0-9]{32,}\./i, type: 'obfuscated', severity: 0.85 }
];

/**
 * D002: 알려진 악성 도메인
 * 알려진 악성 도메인으로의 데이터 전송 감지
 */
export function createD002Rule(): DetectionRule {
  return createDetectionRule({
    id: 'D002',
    name: 'known_malicious_domain',
    description: '알려진 악성 도메인으로의 데이터 전송 감지',
    category: RuleCategory.DANGER,
    priority: 99,
    enabled: true,
    tags: ['blacklist', 'critical'],

    check: (contextUnknown) => {
      const context = contextUnknown as DetectionContext;
      const { request } = context;

      for (const { pattern, type, severity } of MALICIOUS_PATTERNS) {
        if (pattern.test(request.domain)) {
          return {
            match: true,
            confidence: severity,
            details: {
              matchedPattern: pattern.toString(),
              patternType: type,
              domain: request.domain
            }
          };
        }
      }

      return { match: false, confidence: 0 };
    }
  });
}

/**
 * 의심스러운 CDN 패턴 정의
 */
interface SuspiciousCDNPattern {
  pattern: RegExp;
  type: string;
}

const SUSPICIOUS_CDN_PATTERNS: readonly SuspiciousCDNPattern[] = [
  // CDN 위장
  { pattern: /cdn[0-9]*\.[a-z]{2,10}\.(info|net|xyz|top)$/i, type: 'fake_cdn' },
  { pattern: /static[0-9]*\.[a-z]+\.(info|top|xyz)$/i, type: 'fake_static' },
  { pattern: /assets?\.[a-z]+\.(tk|ml|ga)$/i, type: 'fake_assets' },

  // 분석 서비스 위장
  { pattern: /analytics[0-9-]*\.[a-z]+\.(net|info|xyz)$/i, type: 'fake_analytics' },
  { pattern: /tracker?[0-9]*\.[a-z]+/i, type: 'fake_tracker' },
  { pattern: /stats?[0-9]*\.[a-z]+\.(info|net)$/i, type: 'fake_stats' },

  // 결제 서비스 위장
  { pattern: /pay(ment)?[0-9-]*\.[a-z]+\.(net|info)$/i, type: 'fake_payment' },
  { pattern: /checkout[0-9]*\.[a-z]+/i, type: 'fake_checkout' }
];

/**
 * 정상 CDN 화이트리스트
 */
const LEGITIMATE_CDNS: readonly string[] = [
  'cloudflare.com',
  'cloudfront.net',
  'akamaized.net',
  'fastly.net',
  'jsdelivr.net',
  'unpkg.com',
  'cdnjs.cloudflare.com'
];

/**
 * D003: 의심스러운 CDN 위장 패턴
 * CDN이나 분석 서비스를 위장한 의심스러운 도메인 감지
 */
export function createD003Rule(): DetectionRule {
  return createDetectionRule({
    id: 'D003',
    name: 'suspicious_cdn_pattern',
    description: 'CDN이나 분석 서비스를 위장한 의심스러운 도메인 감지',
    category: RuleCategory.DANGER,
    priority: 95,
    enabled: true,
    tags: ['pattern', 'cdn', 'impersonation'],

    check: (contextUnknown) => {
      const context = contextUnknown as DetectionContext;
      const { request, recentInputs } = context;

      // 최근 민감 입력이 없으면 스킵 (5초 이내)
      const hasSensitiveInput = recentInputs.some(
        (input) => request.timestamp - input.timestamp < 5000
      );

      if (!hasSensitiveInput) {
        return { match: false, confidence: 0 };
      }

      // 정상 CDN이면 스킵
      if (LEGITIMATE_CDNS.some((cdn) => request.domain.includes(cdn))) {
        return { match: false, confidence: 0 };
      }

      for (const { pattern, type } of SUSPICIOUS_CDN_PATTERNS) {
        if (pattern.test(request.domain)) {
          return {
            match: true,
            confidence: 0.85,
            details: {
              matchedPattern: pattern.toString(),
              patternType: type,
              domain: request.domain
            }
          };
        }
      }

      return { match: false, confidence: 0 };
    }
  });
}

/**
 * 분석 서비스 도메인 목록
 */
const ANALYTICS_SERVICES: readonly string[] = [
  'google-analytics.com',
  'googletagmanager.com',
  'analytics.google.com',
  'hotjar.com',
  'mixpanel.com',
  'segment.com',
  'amplitude.com',
  'heap.io',
  'fullstory.com'
];

/**
 * D004: 카드 정보를 분석 서비스로 전송
 * 카드 정보 입력 후 분석 서비스로의 의심스러운 전송 감지
 */
export function createD004Rule(): DetectionRule {
  return createDetectionRule({
    id: 'D004',
    name: 'card_data_to_analytics',
    description: '카드 정보 입력 후 분석 서비스로의 의심스러운 전송',
    category: RuleCategory.DANGER,
    priority: 94,
    enabled: true,
    tags: ['card', 'analytics', 'data-leak'],

    check: (contextUnknown) => {
      const context = contextUnknown as DetectionContext;
      const { request, recentInputs } = context;

      // 분석 서비스로의 요청인지 확인
      const isAnalyticsRequest = ANALYTICS_SERVICES.some((service) =>
        request.domain.includes(service)
      );

      if (!isAnalyticsRequest) {
        return { match: false, confidence: 0 };
      }

      // 카드 관련 민감 입력 확인 (1초 이내)
      const cardInput = recentInputs.find(
        (input) =>
          CARD_FIELD_TYPES.includes(input.fieldType) &&
          request.timestamp - input.timestamp < 1000
      );

      if (cardInput !== undefined) {
        return {
          match: true,
          confidence: 0.9,
          details: {
            analyticsService: request.domain,
            cardInputType: cardInput.fieldType,
            timeDiff: request.timestamp - cardInput.timestamp
          }
        };
      }

      return { match: false, confidence: 0 };
    }
  });
}

/**
 * D005: Beacon API로 민감 정보 전송
 * Beacon API를 통한 민감 정보 전송 감지
 */
export function createD005Rule(): DetectionRule {
  return createDetectionRule({
    id: 'D005',
    name: 'beacon_with_sensitive',
    description: 'Beacon API를 통한 민감 정보 전송 감지',
    category: RuleCategory.DANGER,
    priority: 93,
    enabled: true,
    tags: ['beacon', 'exfiltration'],

    check: (contextUnknown) => {
      const context = contextUnknown as DetectionContext;
      const { request, recentInputs, currentDomain } = context;

      // Beacon 요청인지 확인
      if (request.type !== NetworkRequestType.BEACON) {
        return { match: false, confidence: 0 };
      }

      // 외부 도메인인지 확인
      const isExternal = !isSameDomain(request.domain, currentDomain);

      if (!isExternal) {
        return { match: false, confidence: 0 };
      }

      // 최근 민감 입력 확인 (3초 이내)
      const recentSensitive = recentInputs.filter(
        (input) =>
          request.timestamp - input.timestamp < 3000 &&
          SENSITIVE_FIELD_TYPES.includes(input.fieldType)
      );

      if (recentSensitive.length > 0) {
        // 카드 정보가 포함된 경우 더 높은 신뢰도
        const hasCardData = recentSensitive.some((input) =>
          isCardRelatedField(input.fieldType)
        );

        return {
          match: true,
          confidence: hasCardData ? 0.92 : 0.85,
          details: {
            requestType: 'beacon',
            targetDomain: request.domain,
            sensitiveInputs: recentSensitive.map((i) => i.fieldType),
            payloadSize: request.payloadSize
          }
        };
      }

      return { match: false, confidence: 0 };
    }
  });
}

/**
 * 모든 위험 규칙 생성
 */
export function createAllDangerRules(): DetectionRule[] {
  return [
    createD001Rule(),
    createD002Rule(),
    createD003Rule(),
    createD004Rule(),
    createD005Rule()
  ];
}
