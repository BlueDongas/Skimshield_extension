/**
 * ============================================================================
 * 파일: IAIAnalyzer.ts (포트/인터페이스)
 * ============================================================================
 *
 * [역할]
 * AI 분석기의 "인터페이스(계약)"를 정의합니다.
 * 실제 구현은 infrastructure 레이어의 BedrockAIAdapter.ts에 있습니다.
 *
 * [비유]
 * "전문 감정사에게 의뢰하는 양식"과 같습니다:
 * - 어떤 정보를 제공해야 하는지 (AIAnalysisRequest)
 * - 어떤 결과를 받을 수 있는지 (AIAnalysisResponse)
 * - 어떤 기능을 요청할 수 있는지 (analyze, isAvailable 등)
 *
 * [왜 인터페이스로 분리했나?]
 * 클린 아키텍처 원칙:
 * - domain 레이어는 외부 기술(AWS Bedrock)에 의존하면 안 됨
 * - 인터페이스만 정의하고, 구현은 infrastructure에서
 * - 나중에 다른 AI(OpenAI 등)로 교체 가능
 *
 * [AIAnalysisRequest - AI에게 보내는 정보]
 * - request: 분석할 네트워크 요청
 * - recentInputs: 최근 민감 입력 정보
 * - currentDomain: 현재 페이지 도메인
 * - heuristicVerdict: 휴리스틱 분석 결과 (AI 참고용)
 *
 * [AIAnalysisResponse - AI가 반환하는 정보]
 * - verdict: 판정 결과
 * - confidence: 신뢰도
 * - reason: 판정 이유
 * - recommendation: 권장 조치
 *
 * [다른 파일과의 관계]
 * - BedrockAIAdapter.ts: 실제 AI API 호출 구현
 * - StubAIAdapter.ts: 테스트용 더미 구현
 * - DetectionOrchestrator.ts: 휴리스틱 후 AI 분석 요청
 * - Container.ts: 구현체 주입
 *
 * [흐름]
 * DetectionOrchestrator → IAIAnalyzer.analyze() 호출
 * → (실제로는 BedrockAIAdapter 실행) → AI 응답 반환
 * ============================================================================
 */

import { NetworkRequest } from '@domain/entities/NetworkRequest';
import { SensitiveInput } from '@domain/entities/SensitiveInput';
import { Verdict, Recommendation } from '@domain/value-objects/Verdict';

/**
 * AI 분석 요청
 */
export interface AIAnalysisRequest {
  request: NetworkRequest;
  recentInputs: readonly SensitiveInput[];
  currentDomain: string;
  externalScripts?: readonly string[];
  heuristicVerdict?: Verdict;
  heuristicConfidence?: number;
  heuristicReason?: string;
}

/**
 * AI 분석 응답
 */
export interface AIAnalysisResponse {
  verdict: Verdict;
  confidence: number;
  reason: string;
  recommendation: Recommendation;
  details?: { suspiciousFactors: string[]; safeFactors: string[]; };
}

/**
 * AI 분석기 인터페이스
 */
export interface IAIAnalyzer {
  /**
   * AI를 사용하여 네트워크 요청 분석
   */
  analyze(request: AIAnalysisRequest): Promise<AIAnalysisResponse>;

  /**
   * AI 분석 가능 여부 확인
   */
  isAvailable(): Promise<boolean>;

  /**
   * AI 분석기 활성화 여부
   */
  isEnabled(): boolean;

  /**
   * AI 분석기 활성화/비활성화
   */
  setEnabled(enabled: boolean): void;
}
