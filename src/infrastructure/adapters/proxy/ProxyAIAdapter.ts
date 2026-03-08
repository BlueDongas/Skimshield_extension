import {
  AIAnalysisRequest,
  AIAnalysisResponse,
  IAIAnalyzer
} from '@domain/ports/IAIAnalyzer';
import { findMostRecentInput } from '@domain/entities/SensitiveInput';
import { Recommendation, Verdict } from '@domain/value-objects/Verdict';
import { maskUrlQueryParams } from '@shared/utils/maskingUtils';
import { PROXY_CONFIG } from './proxyConstants';
import {
  ProxyAdapterConfig,
  ProxyAnalysisRequest,
  ProxyAnalysisResponse
} from './ProxyApiTypes';

const VERDICT_FROM_PROXY: Record<string, Verdict> = {
  SAFE: Verdict.SAFE,
  SUSPICIOUS: Verdict.SUSPICIOUS,
  DANGEROUS: Verdict.DANGEROUS,
  UNKNOWN: Verdict.UNKNOWN,
};

const RECOMMENDATION_FROM_PROXY: Record<string, Recommendation> = {
  PROCEED: Recommendation.PROCEED,
  WARN: Recommendation.WARN,
  BLOCK: Recommendation.BLOCK,
};

const RETRYABLE_STATUS_CODES = new Set([429, 500, 501, 502, 503, 504]);

export class ProxyAIAdapter implements IAIAnalyzer {
  private enabled = false;
  private readonly baseUrl: string;
  private readonly timeoutMs: number;
  private readonly maxRetries: number;
  private readonly retryBaseDelayMs: number;

  constructor(config?: ProxyAdapterConfig) {
    this.baseUrl = config?.baseUrl ?? PROXY_CONFIG.BASE_URL;
    this.timeoutMs = config?.timeoutMs ?? PROXY_CONFIG.TIMEOUT_MS;
    this.maxRetries = config?.maxRetries ?? PROXY_CONFIG.MAX_RETRIES;
    this.retryBaseDelayMs = config?.retryBaseDelayMs ?? PROXY_CONFIG.RETRY_BASE_DELAY_MS;
  }

  isEnabled(): boolean {
    return this.enabled;
  }

  setEnabled(enabled: boolean): void {
    this.enabled = enabled;
  }

  async isAvailable(): Promise<boolean> {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(
        () => controller.abort(),
        PROXY_CONFIG.HEALTH_CHECK_TIMEOUT_MS
      );

      const response = await fetch(
        `${this.baseUrl}${PROXY_CONFIG.HEALTH_ENDPOINT}`,
        { method: 'GET', signal: controller.signal }
      );

      clearTimeout(timeoutId);
      return true; // 어떤 HTTP 응답이든 오면 서버가 살아있음
    } catch {
      return false;
    }
  }

  async analyze(request: AIAnalysisRequest): Promise<AIAnalysisResponse> {
    if (!this.enabled) {
      return {
        verdict: Verdict.UNKNOWN,
        confidence: 0,
        reason: 'AI 분석기가 비활성화 상태입니다.',
        recommendation: Recommendation.WARN,
      };
    }

    const proxyRequest = this.toProxyRequest(request);
    const proxyResponse = await this.sendRequest(proxyRequest);
    return this.fromProxyResponse(proxyResponse);
  }

  private toProxyRequest(request: AIAnalysisRequest): ProxyAnalysisRequest {
    const { request: req, recentInputs, currentDomain, externalScripts } = request;

    let payloadFormat: 'JSON' | 'FORM_DATA' | 'BASE64' | 'UNKNOWN';
    if (req.payloadFormat !== undefined) {
      // content layer에서 body를 직접 분석해 감지한 값을 우선 사용
      payloadFormat = req.payloadFormat;
    } else {
      // body가 없는 경우(form submit 등) Content-Type 헤더로 추론
      const contentType = req.headers['content-type'] ?? req.headers['Content-Type'] ?? '';
      if (contentType.includes('application/json')) {
        payloadFormat = 'JSON';
      } else if (
        contentType.includes('application/x-www-form-urlencoded') ||
        contentType.includes('multipart/form-data')
      ) {
        payloadFormat = 'FORM_DATA';
      } else {
        payloadFormat = 'UNKNOWN';
      }
    }

    const triggerEvent: 'click' | 'submit' | 'blur' | 'timer' | 'unknown' =
      req.triggerEvent ?? 'unknown';

    const mostRecent = findMostRecentInput(recentInputs);
    const timeSinceLastInputMs = mostRecent
      ? req.timestamp - mostRecent.timestamp
      : -1;

    return {
      networkEvent: {
        destinationUrl: maskUrlQueryParams(req.url),
        method: req.method,
        type: req.type,
        payloadSize: req.payloadSize,
        payloadFormat,
        initiatorScript: req.initiatorScript ?? '',
      },
      behaviorContext: {
        triggerEvent,
        timeSinceLastInputMs,
      },
      recentInputs: recentInputs.map((input) => ({
        fieldType: input.fieldType,
        length: input.inputLength,
      })),
      environment: {
        currentDomain,
        externalScripts: (externalScripts ?? []).map(maskUrlQueryParams),
      },
      heuristicContext: {
        verdict: (request.heuristicVerdict ?? Verdict.UNKNOWN).toUpperCase(),
        confidence: request.heuristicConfidence ?? 0,
        reason: request.heuristicReason ?? '',
      },
    };
  }

  private fromProxyResponse(response: ProxyAnalysisResponse): AIAnalysisResponse {
    const verdict = VERDICT_FROM_PROXY[response.verdict] ?? Verdict.UNKNOWN;
    const recommendation = RECOMMENDATION_FROM_PROXY[response.recommendation] ?? Recommendation.WARN;
    const confidence = Math.max(0, Math.min(1, response.confidence));

    const result: AIAnalysisResponse = {
      verdict,
      confidence,
      reason: response.reasonMessage,
      recommendation,
    };

    if (response.analysisDetails !== undefined) {
      result.details = response.analysisDetails;
    }

    return result;
  }

  private async sendRequest(body: ProxyAnalysisRequest): Promise<ProxyAnalysisResponse> {
    let lastError: Error | undefined;

    for (let attempt = 0; attempt <= this.maxRetries; attempt++) {
      if (attempt > 0) {
        const delay = this.retryBaseDelayMs * Math.pow(2, attempt - 1);
        await this.sleep(delay);
      }

      let response: Response;
      try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), this.timeoutMs);

        response = await fetch(
          `${this.baseUrl}${PROXY_CONFIG.ANALYZE_ENDPOINT}`,
          {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
            signal: controller.signal,
          }
        );

        clearTimeout(timeoutId);
      } catch (error) {
        if (error instanceof Error && error.name === 'AbortError') {
          lastError = new Error('Proxy API request timed out');
        } else {
          lastError = error instanceof Error ? error : new Error(String(error));
        }
        continue;
      }

      if (response.ok) {
        return (await response.json()) as ProxyAnalysisResponse;
      }

      if (!RETRYABLE_STATUS_CODES.has(response.status)) {
        throw new Error(`Proxy API error: ${response.status} ${response.statusText}`);
      }

      lastError = new Error(`Proxy API error: ${response.status} ${response.statusText}`);
    }

    throw lastError ?? new Error('Proxy API request failed');
  }

  private sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
}
