/**
 * ============================================================================
 * 파일: BedrockAIAdapter.ts
 * ============================================================================
 *
 * [역할]
 * IAIAnalyzer 인터페이스의 AWS Bedrock 구현체입니다.
 * Claude AI를 사용하여 네트워크 요청을 분석합니다.
 *
 * [비유]
 * "AI 보안 전문가에게 자문 구하기"와 같습니다:
 * - 요청 정보를 설명하고
 * - AI가 폼재킹 공격 여부를 판단
 * - 판정 결과와 이유를 반환
 *
 * [AWS Bedrock이란?]
 * AWS에서 제공하는 AI 모델 서비스
 * - Claude, Titan 등 다양한 모델 사용 가능
 * - API 호출로 AI 분석 수행
 * - 사용량 기반 과금
 *
 * [주의사항]
 * 현재 Chrome 확장 프로그램에서는 AWS SDK가
 * 제대로 동작하지 않아 StubAIAdapter 사용 중
 * (향후 서버 프록시 구현 시 활성화 예정)
 *
 * [분석 흐름]
 * 1. buildPrompt(): 분석 요청을 프롬프트로 변환
 * 2. Claude API 호출
 * 3. parseResponse(): AI 응답 JSON 파싱
 *
 * [프롬프트 구조]
 * - 요청 정보 (URL, method, payloadSize 등)
 * - 최근 민감 입력 정보
 * - 외부 스크립트 목록
 * - 휴리스틱 분석 결과
 * - 응답 형식 지정 (JSON)
 *
 * [AI 응답 형식]
 * ```json
 * {
 *   "verdict": "DANGEROUS",
 *   "confidence": 0.95,
 *   "reason": "판단 이유",
 *   "recommendation": "BLOCK"
 * }
 * ```
 *
 * [다른 파일과의 관계]
 * - IAIAnalyzer.ts: 구현하는 인터페이스
 * - StubAIAdapter.ts: 대체 구현 (현재 사용 중)
 * - DetectionOrchestrator.ts: AI 분석 호출
 * - Container.ts: 의존성 주입
 * ============================================================================
 */

import { AnthropicBedrock } from '@anthropic-ai/bedrock-sdk';

import {
  AIAnalysisRequest,
  AIAnalysisResponse,
  IAIAnalyzer
} from '@domain/ports/IAIAnalyzer';
import { Recommendation, Verdict } from '@domain/value-objects/Verdict';

/**
 * Bedrock 설정
 */
export interface BedrockConfig {
  region: string;
  modelId: string;
  accessKeyId?: string;
  secretAccessKey?: string;
}

/**
 * AI 응답 파싱 결과
 */
interface ParsedAIResponse {
  verdict: string;
  confidence: number;
  reason: string;
  recommendation: string;
  details?: { suspiciousFactors: string[]; safeFactors: string[]; };
}

/**
 * Bedrock AI 어댑터 구현체
 */
export class BedrockAIAdapter implements IAIAnalyzer {
  private readonly client: AnthropicBedrock;
  private readonly modelId: string;
  private enabled: boolean = true;

  constructor(config: BedrockConfig) {
    this.modelId = config.modelId;
    this.client = new AnthropicBedrock({
      awsRegion: config.region
    });
  }

  /**
   * AI 분석기 활성화 여부
   */
  isEnabled(): boolean {
    return this.enabled;
  }

  /**
   * AI 분석기 활성화/비활성화
   */
  setEnabled(enabled: boolean): void {
    this.enabled = enabled;
  }

  /**
   * AI 분석 가능 여부 확인
   */
  async isAvailable(): Promise<boolean> {
    if (!this.enabled) {
      return false;
    }

    try {
      // 간단한 테스트 호출로 가용성 확인
      await this.client.messages.create({
        model: this.modelId,
        max_tokens: 10,
        messages: [{ role: 'user', content: 'ping' }]
      });
      return true;
    } catch {
      return false;
    }
  }

  /**
   * AI를 사용하여 네트워크 요청 분석
   */
  async analyze(request: AIAnalysisRequest): Promise<AIAnalysisResponse> {
    if (!this.enabled) {
      return {
        verdict: Verdict.UNKNOWN,
        confidence: 0,
        reason: 'AI 분석기가 비활성화되어 있습니다',
        recommendation: Recommendation.WARN
      };
    }

    const prompt = this.buildPrompt(request);

    const response = await this.client.messages.create({
      model: this.modelId,
      max_tokens: 1024,
      messages: [{ role: 'user', content: prompt }]
    });

    return this.parseResponse(response);
  }

  /**
   * 분석 프롬프트 생성
   */
  private buildPrompt(request: AIAnalysisRequest): string {
    const parts: string[] = [
      '당신은 웹 보안 전문가입니다. 다음 네트워크 요청을 분석하여 폼재킹(formjacking) 공격 여부를 판단해주세요.',
      '',
      '## 요청 정보',
      `- URL: ${request.request.url}`,
      `- HTTP 메서드: ${request.request.method}`,
      `- 요청 타입: ${request.request.type}`,
      `- 페이로드 크기: ${request.request.payloadSize} bytes`,
      `- 현재 도메인: ${request.currentDomain}`,
      ''
    ];

    // 최근 입력 정보
    if (request.recentInputs.length > 0) {
      parts.push('## 최근 민감 입력');
      for (const input of request.recentInputs) {
        parts.push(`- 필드 타입: ${input.fieldType}, 길이: ${input.inputLength}`);
      }
      parts.push('');
    }

    // 외부 스크립트 정보
    if (request.externalScripts !== undefined && request.externalScripts.length > 0) {
      parts.push('## 외부 스크립트');
      for (const script of request.externalScripts) {
        parts.push(`- ${script}`);
      }
      parts.push('');
    }

    // 휴리스틱 분석 결과
    if (request.heuristicVerdict !== undefined) {
      parts.push('## 휴리스틱 분석 결과');
      parts.push(`- 판정: ${request.heuristicVerdict}`);
      if (request.heuristicConfidence !== undefined) {
        parts.push(`- 신뢰도: ${(request.heuristicConfidence * 100).toFixed(1)}%`);
      }
      parts.push('');
    }

    parts.push('## 응답 형식');
    parts.push('다음 JSON 형식으로 응답해주세요:');
    parts.push('```json');
    parts.push('{');
    parts.push('  "verdict": "DANGEROUS" | "SUSPICIOUS" | "SAFE" | "UNKNOWN",');
    parts.push('  "confidence": 0.0 ~ 1.0,');
    parts.push('  "reason": "판단 이유",');
    parts.push('  "recommendation": "BLOCK" | "WARN" | "PROCEED"');
    parts.push('}');
    parts.push('```');

    return parts.join('\n');
  }

  /**
   * AI 응답 파싱
   */
  private parseResponse(response: {
    content: Array<{ type: string; text?: string }>;
  }): AIAnalysisResponse {
    const content = response.content[0];
    if (content === undefined || content.type !== 'text' || content.text === undefined) {
      throw new Error('AI 응답이 비어있습니다');
    }

    const text = content.text;

    // JSON 추출 (```json ... ``` 형식 또는 순수 JSON)
    let jsonStr = text;
    const jsonMatch = text.match(/```json\s*([\s\S]*?)\s*```/);
    if (jsonMatch?.[1] !== undefined) {
      jsonStr = jsonMatch[1];
    }

    const parsed = JSON.parse(jsonStr) as ParsedAIResponse;

    const result: AIAnalysisResponse = {
      verdict: this.parseVerdict(parsed.verdict),
      confidence: parsed.confidence,
      reason: parsed.reason,
      recommendation: this.parseRecommendation(parsed.recommendation)
    };

    if (parsed.details !== undefined) {
      result.details = parsed.details;
    }

    return result;
  }

  /**
   * Verdict 문자열 파싱
   */
  private parseVerdict(verdict: string): Verdict {
    const map: Record<string, Verdict> = {
      DANGEROUS: Verdict.DANGEROUS,
      SUSPICIOUS: Verdict.SUSPICIOUS,
      SAFE: Verdict.SAFE,
      UNKNOWN: Verdict.UNKNOWN
    };
    return map[verdict] ?? Verdict.UNKNOWN;
  }

  /**
   * Recommendation 문자열 파싱
   */
  private parseRecommendation(recommendation: string): Recommendation {
    const map: Record<string, Recommendation> = {
      BLOCK: Recommendation.BLOCK,
      WARN: Recommendation.WARN,
      PROCEED: Recommendation.PROCEED,
      // 호환성을 위한 추가 매핑
      ALLOW: Recommendation.PROCEED,
      ANALYZE: Recommendation.WARN
    };
    return map[recommendation] ?? Recommendation.WARN;
  }
}
