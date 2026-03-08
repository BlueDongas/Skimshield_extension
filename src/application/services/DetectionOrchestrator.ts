/**
 * ============================================================================
 * 파일: DetectionOrchestrator.ts
 * ============================================================================
 *
 * [역할]
 * 탐지의 전체 프로세스를 조율하는 "오케스트레이터(지휘자)"입니다.
 * 민감 입력 버퍼링, 네트워크 분석, 이벤트 저장을 통합 관리합니다.
 *
 * [비유]
 * "교통 관제 센터"와 같습니다:
 * - 각종 정보(입력, 네트워크 요청)를 수집
 * - 분석 엔진들(휴리스틱, AI)을 조율
 * - 결과에 따라 적절한 조치(저장, 알림)
 *
 * [핵심 기능]
 *
 * 1. 민감 입력 버퍼링:
 *    - handleSensitiveInput(): 민감 입력을 메모리에 임시 저장
 *    - getRecentInputs(): 최근 N밀리초 이내 입력 조회
 *    - 네트워크 요청 분석 시 "최근에 민감 입력이 있었나?" 확인용
 *
 * 2. 네트워크 요청 분석:
 *    - analyzeNetworkRequest(): 전체 분석 프로세스 실행
 *    - 화이트리스트 확인 → 휴리스틱 분석 → (필요시) AI 분석
 *    - 최근 민감 입력 정보를 분석 컨텍스트에 추가
 *
 * 3. 결과 처리:
 *    - SAFE가 아닌 결과는 이벤트로 저장
 *    - (참고: 경고창 표시는 Content Script에서 직접 처리)
 *
 * [분석 흐름 상세]
 * 1. 화이트리스트 확인 → 있으면 SAFE 즉시 반환
 * 2. 최근 500ms 이내 민감 입력 가져오기
 * 3. DetectionContext 구성 (요청 + 입력 + 도메인)
 * 4. 휴리스틱 엔진 분석
 *    - DANGEROUS/SAFE → 결과 확정
 *    - UNKNOWN → AI 분석 시도
 * 5. (필요시) AI 분석
 * 6. 결과가 SAFE가 아니면 이벤트 저장
 *
 * [의존성]
 * - IDetectionEngine: 휴리스틱 엔진
 * - IAIAnalyzer: AI 분석기
 * - ISettingsRepository: 설정 저장소
 * - IEventRepository: 이벤트 저장소
 * - IMessenger: 메시지 통신 (향후 확장용)
 *
 * [다른 파일과의 관계]
 * - MessageHandler.ts: ANALYZE_REQUEST, SENSITIVE_INPUT 메시지 처리
 * - background/index.ts: 오케스트레이터 인스턴스 생성 및 초기화
 * - content/index.ts: 분석 요청 전송
 *
 * [흐름]
 * Content Script에서 네트워크 요청 감지
 * → ANALYZE_REQUEST 메시지 → MessageHandler
 * → DetectionOrchestrator.analyzeNetworkRequest()
 * → 분석 결과 반환 → Content Script에서 경고 표시
 * ============================================================================
 */

import {
  AnalysisRequestDTO,
  AnalysisResponseDTO
} from '@application/dto/AnalysisDTO';
import { createDetectionEvent } from '@domain/entities/DetectionEvent';
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
import { IEventRepository } from '@domain/ports/IEventRepository';
import { IMessenger } from '@domain/ports/IMessenger';
import { ISettingsRepository } from '@domain/ports/ISettingsRepository';
import { SensitiveFieldType } from '@domain/value-objects/SensitiveFieldType';
import {
  getRecommendationForVerdict,
  Verdict
} from '@domain/value-objects/Verdict';
import { PayloadFormat } from '@shared/utils/payloadFormatUtils';

/**
 * 입력 버퍼 아이템
 */
interface InputBufferItem {
  fieldId: string;
  fieldType: SensitiveFieldType;
  inputLength: number;
  timestamp: number;
}

/**
 * 오케스트레이터 의존성
 */
export interface DetectionOrchestratorDeps {
  heuristicEngine: IDetectionEngine;
  aiAnalyzer: IAIAnalyzer;
  settingsRepository: ISettingsRepository;
  eventRepository: IEventRepository;
  messenger: IMessenger;
}

/**
 * DetectionOrchestrator 클래스
 */
export class DetectionOrchestrator {
  private readonly heuristicEngine: IDetectionEngine;
  private readonly aiAnalyzer: IAIAnalyzer;
  private readonly settingsRepository: ISettingsRepository;
  private readonly eventRepository: IEventRepository;
  private readonly messenger: IMessenger;

  private inputBuffer: InputBufferItem[] = [];

  constructor(deps: DetectionOrchestratorDeps) {
    this.heuristicEngine = deps.heuristicEngine;
    this.aiAnalyzer = deps.aiAnalyzer;
    this.settingsRepository = deps.settingsRepository;
    this.eventRepository = deps.eventRepository;
    this.messenger = deps.messenger;
    // messenger는 향후 기능 확장을 위해 유지
    void this.messenger;
  }

  /**
   * 민감 입력 처리
   */
  handleSensitiveInput(input: InputBufferItem): void {
    this.inputBuffer.push(input);
    this.cleanupOldInputs();
  }

  /**
   * 네트워크 요청 분석
   */
  async analyzeNetworkRequest(
    requestDTO: AnalysisRequestDTO,
    tabId?: number
  ): Promise<AnalysisResponseDTO> {
    const startTime = performance.now();

    // 1. URL에서 대상 도메인 추출
    const targetDomain = this.extractDomain(requestDTO.request.url);

    // 2. 화이트리스트 확인
    const isWhitelisted =
      await this.settingsRepository.isWhitelisted(targetDomain);

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

    // 3. 최근 민감 입력 가져오기 (500ms 이내)
    const recentInputs = this.getRecentInputs(500);
    const enrichedDTO = {
      ...requestDTO,
      recentInputs: [
        ...requestDTO.recentInputs,
        ...recentInputs.map((i) => ({
          fieldType: i.fieldType,
          inputLength: i.inputLength,
          timestamp: i.timestamp
        }))
      ]
    };

    // 4. DetectionContext 변환
    const context = this.toDetectionContext(enrichedDTO);

    // 5. 휴리스틱 엔진 분석
    const heuristicResult = this.heuristicEngine.analyze(context);

    // 6. 결과에 따른 처리
    let finalResult: AnalysisResponseDTO;

    if (
      heuristicResult.verdict === Verdict.DANGEROUS ||
      heuristicResult.verdict === Verdict.SAFE
    ) {
      finalResult = this.createResponse({
        verdict: heuristicResult.verdict,
        confidence: heuristicResult.confidence,
        reason: heuristicResult.reason,
        matchedRuleIds: heuristicResult.matchedRules.map((r) => r.ruleId),
        usedAI: false,
        analysisTimeMs: performance.now() - startTime
      });
    } else {
      // UNKNOWN인 경우 AI 분석 시도
      const aiEnabled = await this.settingsRepository.get('aiAnalysisEnabled');
      const aiAvailable = await this.aiAnalyzer.isAvailable();

      if (aiEnabled && aiAvailable) {
        this.aiAnalyzer.setEnabled(true);
        try {
          const aiRequest: Parameters<typeof this.aiAnalyzer.analyze>[0] = {
            request: context.request,
            recentInputs: context.recentInputs,
            currentDomain: context.currentDomain,
            heuristicVerdict: heuristicResult.verdict,
            heuristicConfidence: heuristicResult.confidence,
            heuristicReason: heuristicResult.reason
          };

          if (context.externalScripts !== undefined) {
            aiRequest.externalScripts = context.externalScripts;
          }

          const aiResult = await this.aiAnalyzer.analyze(aiRequest);

          const responseParams: Parameters<typeof this.createResponse>[0] = {
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

          finalResult = this.createResponse(responseParams);
        } catch {
          finalResult = this.createResponse({
            verdict: heuristicResult.verdict,
            confidence: heuristicResult.confidence,
            reason: heuristicResult.reason,
            matchedRuleIds: heuristicResult.matchedRules.map((r) => r.ruleId),
            usedAI: false,
            analysisTimeMs: performance.now() - startTime
          });
        }
      } else {
        finalResult = this.createResponse({
          verdict: heuristicResult.verdict,
          confidence: heuristicResult.confidence,
          reason: heuristicResult.reason,
          matchedRuleIds: heuristicResult.matchedRules.map((r) => r.ruleId),
          usedAI: false,
          analysisTimeMs: performance.now() - startTime
        });
      }
    }

    // 7. 이벤트 저장 (SAFE가 아닌 모든 verdict)
    if (finalResult.verdict !== Verdict.SAFE) {
      await this.handleNonSafeResult(
        requestDTO,
        finalResult,
        targetDomain,
        tabId
      );
    }

    return finalResult;
  }

  /**
   * 최근 입력 조회
   */
  getRecentInputs(withinMs: number): InputBufferItem[] {
    const threshold = Date.now() - withinMs;
    return this.inputBuffer.filter((i) => i.timestamp > threshold);
  }

  /**
   * 입력 버퍼 초기화
   */
  clearInputBuffer(): void {
    this.inputBuffer = [];
  }

  /**
   * 오래된 입력 정리
   */
  private cleanupOldInputs(): void {
    const threshold = Date.now() - 10000; // 10초 이상 된 입력 정리
    this.inputBuffer = this.inputBuffer.filter((i) => i.timestamp > threshold);
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

  /**
   * DTO를 DetectionContext로 변환
   */
  private toDetectionContext(dto: AnalysisRequestDTO): DetectionContext {
    const requestProps: {
      type: typeof dto.request.type;
      url: string;
      method: string;
      payloadSize: number;
      payloadFormat?: PayloadFormat;
      initiatorScript?: string;
      triggerEvent?: 'click' | 'submit' | 'blur' | 'timer' | 'unknown';
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

    if (dto.request.payloadFormat !== undefined) {
      requestProps.payloadFormat = dto.request.payloadFormat;
    }

    if (dto.request.initiatorScript !== undefined) {
      requestProps.initiatorScript = dto.request.initiatorScript;
    }

    if (dto.request.triggerEvent !== undefined) {
      requestProps.triggerEvent = dto.request.triggerEvent;
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
   * 응답 생성
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
   * SAFE가 아닌 결과 처리 (이벤트 저장)
   */
  private async handleNonSafeResult(
    requestDTO: AnalysisRequestDTO,
    result: AnalysisResponseDTO,
    targetDomain: string,
    tabId?: number
  ): Promise<void> {
    // 이벤트 생성 props 준비
    type EventProps = {
      verdict: Verdict;
      confidence: number;
      reason: string;
      recommendation: typeof result.recommendation;
      requestId: string;
      requestType: typeof requestDTO.request.type;
      targetDomain: string;
      currentDomain: string;
      timestamp: number;
      matchedRuleId?: string;
    };

    const eventProps: EventProps = {
      verdict: result.verdict,
      confidence: result.confidence,
      reason: result.reason,
      recommendation: result.recommendation,
      requestId: `req-${requestDTO.request.timestamp}`,
      requestType: requestDTO.request.type,
      targetDomain,
      currentDomain: requestDTO.currentDomain,
      timestamp: requestDTO.request.timestamp
    };

    const firstRuleId = result.matchedRuleIds[0];
    if (firstRuleId !== undefined) {
      eventProps.matchedRuleId = firstRuleId;
    }

    const event = createDetectionEvent(eventProps);

    await this.eventRepository.save(event);

    // 참고: 알림은 content script에서 분석 응답을 받아 직접 표시하므로
    // 백그라운드에서 SHOW_WARNING 메시지를 중복 전송하지 않음
    void tabId; // lint 경고 방지
  }
}
