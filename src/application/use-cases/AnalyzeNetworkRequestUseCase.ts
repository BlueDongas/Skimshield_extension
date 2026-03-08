/**
 * ============================================================================
 * 파일: AnalyzeNetworkRequestUseCase.ts
 * ============================================================================
 *
 * [역할]
 * 네트워크 요청을 분석하여 폼재킹 공격 여부를 판단하는 "핵심 유즈케이스"입니다.
 * 휴리스틱 엔진과 AI 분석기를 조합하여 최종 판정을 내립니다.
 *
 * [비유]
 * "2단계 보안 검사"와 같습니다:
 * 1단계: 휴리스틱 검사 (빠르고 규칙 기반)
 * 2단계: AI 검사 (정교하지만 느림, 필요시에만)
 *
 * [분석 흐름]
 * 1. 화이트리스트 확인 → 있으면 SAFE 즉시 반환
 * 2. 휴리스틱 엔진 분석
 *    - DANGEROUS/SAFE → 즉시 반환
 *    - UNKNOWN → AI 분석으로 진행
 * 3. AI 분석 (설정 활성화 + 가용 시)
 *    - 성공 → AI 결과 반환
 *    - 실패 → 휴리스틱 결과로 폴백
 *
 * [입력: AnalysisRequestDTO]
 * - request: 네트워크 요청 정보 (URL, method, timestamp 등)
 * - recentInputs: 최근 민감 입력 목록
 * - currentDomain: 현재 페이지 도메인
 *
 * [출력: AnalysisResponseDTO]
 * - verdict: 판정 결과 (SAFE, DANGEROUS, UNKNOWN 등)
 * - confidence: 신뢰도
 * - recommendation: 권장 조치
 * - reason: 판정 이유
 * - usedAI: AI 분석 사용 여부
 * - analysisTimeMs: 분석 소요 시간
 *
 * [의존성]
 * - IDetectionEngine: 휴리스틱 엔진 (HeuristicEngine)
 * - IAIAnalyzer: AI 분석기 (BedrockAIAdapter)
 * - ISettingsRepository: 설정 저장소 (AI 활성화 여부 확인)
 *
 * [다른 파일과의 관계]
 * - DetectionOrchestrator.ts: 이 유즈케이스를 더 상위 레벨에서 조율
 * - MessageHandler.ts: ANALYZE_REQUEST 메시지 처리 시 호출
 *
 * [참고]
 * 이 유즈케이스는 독립적으로도 사용 가능하지만,
 * 실제로는 DetectionOrchestrator가 더 많은 기능을 포함하여 사용됩니다.
 * ============================================================================
 */

import {
  AnalysisRequestDTO,
  AnalysisResponseDTO
} from '@application/dto/AnalysisDTO';
import {
  createNetworkRequest,
  NetworkRequest
} from '@domain/entities/NetworkRequest';
import {
  createSensitiveInput,
  SensitiveInput
} from '@domain/entities/SensitiveInput';
import { IAIAnalyzer } from '@domain/ports/IAIAnalyzer';
import {
  DetectionContext,
  IDetectionEngine
} from '@domain/ports/IDetectionEngine';
import { ISettingsRepository } from '@domain/ports/ISettingsRepository';
import {
  getRecommendationForVerdict,
  Verdict
} from '@domain/value-objects/Verdict';

/**
 * 유즈케이스 의존성
 */
export interface AnalyzeNetworkRequestUseCaseDeps {
  heuristicEngine: IDetectionEngine;
  aiAnalyzer: IAIAnalyzer;
  settingsRepository: ISettingsRepository;
}

/**
 * AnalyzeNetworkRequestUseCase 클래스
 */
export class AnalyzeNetworkRequestUseCase {
  private readonly heuristicEngine: IDetectionEngine;
  private readonly aiAnalyzer: IAIAnalyzer;
  private readonly settingsRepository: ISettingsRepository;

  constructor(deps: AnalyzeNetworkRequestUseCaseDeps) {
    this.heuristicEngine = deps.heuristicEngine;
    this.aiAnalyzer = deps.aiAnalyzer;
    this.settingsRepository = deps.settingsRepository;
  }

  /**
   * 네트워크 요청 분석 실행
   */
  async execute(requestDTO: AnalysisRequestDTO): Promise<AnalysisResponseDTO> {
    const startTime = performance.now();

    // URL에서 대상 도메인 추출
    const targetDomain = this.extractDomain(requestDTO.request.url);

    // 1. 화이트리스트 확인
    const isWhitelisted = await this.settingsRepository.isWhitelisted(
      targetDomain
    );

    if (isWhitelisted) {
      return this.createResponse({
        verdict: Verdict.SAFE,
        confidence: 1.0,
        reason: `화이트리스트 도메인: ${targetDomain}`,
        matchedRuleIds: [],
        usedAI: false,
        analysisTimeMs: performance.now() - startTime
      });
    }

    // 2. DTO를 DetectionContext로 변환
    const context = this.toDetectionContext(requestDTO);

    // 3. 휴리스틱 엔진으로 분석
    const heuristicResult = this.heuristicEngine.analyze(context);

    // 4. 휴리스틱 결과가 확정적이면 바로 반환
    if (
      heuristicResult.verdict === Verdict.DANGEROUS ||
      heuristicResult.verdict === Verdict.SAFE
    ) {
      return this.createResponse({
        verdict: heuristicResult.verdict,
        confidence: heuristicResult.confidence,
        reason: heuristicResult.reason,
        matchedRuleIds: heuristicResult.matchedRules.map((r) => r.ruleId),
        usedAI: false,
        analysisTimeMs: performance.now() - startTime
      });
    }

    // 5. UNKNOWN인 경우 AI 분석 시도
    const aiEnabled = await this.settingsRepository.get('aiAnalysisEnabled');

    if (aiEnabled) {
      const aiAvailable = await this.aiAnalyzer.isAvailable();

      if (aiAvailable) {
        this.aiAnalyzer.setEnabled(true);
        try {
          const aiRequest: Parameters<typeof this.aiAnalyzer.analyze>[0] = {
            request: context.request,
            recentInputs: context.recentInputs,
            currentDomain: context.currentDomain,
            heuristicVerdict: heuristicResult.verdict,
            heuristicConfidence: heuristicResult.confidence
          };

          if (context.externalScripts !== undefined) {
            aiRequest.externalScripts = context.externalScripts;
          }

          const aiResult = await this.aiAnalyzer.analyze(aiRequest);

          const responseParams: {
            verdict: Verdict;
            confidence: number;
            reason: string;
            matchedRuleIds: readonly string[];
            usedAI: boolean;
            analysisTimeMs: number;
            details?: { suspiciousFactors: string[]; safeFactors: string[]; };
          } = {
            verdict: aiResult.verdict,
            confidence: aiResult.confidence,
            reason: aiResult.reason,
            matchedRuleIds: heuristicResult.matchedRules.map((r) => r.ruleId),
            usedAI: true,
            analysisTimeMs: performance.now() - startTime
          };

          if (aiResult.details !== undefined) {
            responseParams.details = aiResult.details;
          }

          return this.createResponse(responseParams);
        } catch {
          // AI 분석 실패 시 휴리스틱 결과로 폴백
        }
      }
    }

    // 6. AI 미사용 또는 실패 시 휴리스틱 결과 반환
    return this.createResponse({
      verdict: heuristicResult.verdict,
      confidence: heuristicResult.confidence,
      reason: heuristicResult.reason,
      matchedRuleIds: heuristicResult.matchedRules.map((r) => r.ruleId),
      usedAI: false,
      analysisTimeMs: performance.now() - startTime
    });
  }

  /**
   * AnalysisRequestDTO를 DetectionContext로 변환
   */
  private toDetectionContext(dto: AnalysisRequestDTO): DetectionContext {
    const requestProps: {
      type: typeof dto.request.type;
      url: string;
      method: string;
      payloadSize: number;
      timestamp: number;
      headers?: Record<string, string>;
    } = {
      type: dto.request.type,
      url: dto.request.url,
      method: dto.request.method,
      payloadSize: dto.request.payloadSize,
      timestamp: dto.request.timestamp
    };

    if (dto.request.headers !== undefined) {
      requestProps.headers = dto.request.headers;
    }

    const request: NetworkRequest = createNetworkRequest(requestProps);

    const recentInputs: SensitiveInput[] = dto.recentInputs.map(
      (input, index) =>
        createSensitiveInput({
          fieldId: `input-${index}`,
          fieldType: input.fieldType,
          inputLength: input.inputLength,
          timestamp: input.timestamp,
          domPath: 'unknown'
        })
    );

    const context: DetectionContext = {
      request,
      recentInputs,
      currentDomain: dto.currentDomain,
      externalScripts: dto.externalScripts ?? []
    };

    return context;
  }

  /**
   * 응답 DTO 생성
   */
  private createResponse(params: {
    verdict: Verdict;
    confidence: number;
    reason: string;
    matchedRuleIds: readonly string[];
    usedAI: boolean;
    analysisTimeMs: number;
    details?: { suspiciousFactors: string[]; safeFactors: string[]; };
  }): AnalysisResponseDTO {
    const response: AnalysisResponseDTO = {
      verdict: params.verdict,
      confidence: params.confidence,
      recommendation: getRecommendationForVerdict(params.verdict),
      reason: params.reason,
      matchedRuleIds: params.matchedRuleIds,
      usedAI: params.usedAI,
      analysisTimeMs: params.analysisTimeMs
    };

    if (params.details !== undefined) {
      response.details = params.details;
    }

    return response;
  }

  /**
   * URL에서 도메인 추출
   */
  private extractDomain(url: string): string {
    try {
      return new URL(url).hostname;
    } catch {
      return url;
    }
  }
}
