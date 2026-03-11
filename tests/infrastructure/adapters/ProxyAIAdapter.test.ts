/**
 * ProxyAIAdapter 단위 테스트
 * fetch를 mock하여 프록시 서버와의 통신 로직을 검증합니다.
 */

import { createNetworkRequest } from '@domain/entities/NetworkRequest';
import { createSensitiveInput } from '@domain/entities/SensitiveInput';
import { AIAnalysisRequest } from '@domain/ports/IAIAnalyzer';
import { SensitiveFieldType } from '@domain/value-objects/SensitiveFieldType';
import { Recommendation, Verdict } from '@domain/value-objects/Verdict';
import { ProxyAIAdapter } from '@infrastructure/adapters/proxy/ProxyAIAdapter';
import { ProxyAdapterConfig } from '@infrastructure/adapters/proxy/ProxyApiTypes';

// fetch 전역 mock
const mockFetch = jest.fn();
global.fetch = mockFetch;

const TEST_BASE_URL = 'http://3.34.210.236:3000';

const TEST_CONFIG: ProxyAdapterConfig = {
  baseUrl: TEST_BASE_URL,
  timeoutMs: 5000,
  maxRetries: 0,         // 테스트에서 재시도 없이 즉시 실패
  retryBaseDelayMs: 100,
};

/**
 * 서버가 반환하는 성공 응답 생성
 */
function makeServerResponse(overrides: object = {}) {
  return {
    verdict: 'DANGEROUS',
    confidence: 0.95,
    recommendation: 'BLOCK',
    reasonMessage: '카드 정보가 외부 도메인으로 즉시 전송됨',
    analysisDetails: {
      suspiciousFactors: ['즉각적 외부 전송', '알 수 없는 도메인'],
      safeFactors: []
    },
    ...overrides
  };
}

/**
 * fetch 성공 응답 mock
 */
function mockFetchSuccess(body: object, status = 200) {
  mockFetch.mockResolvedValueOnce({
    ok: status >= 200 && status < 300,
    status,
    statusText: status === 200 ? 'OK' : 'Error',
    json: async () => body
  });
}

/**
 * fetch 실패 응답 mock
 */
function mockFetchError(status: number, body: object = { error: '서버 내부 에러' }) {
  mockFetch.mockResolvedValueOnce({
    ok: false,
    status,
    statusText: 'Internal Server Error',
    json: async () => body
  });
}

/**
 * 테스트용 AIAnalysisRequest 생성
 */
function createTestRequest(overrides: Partial<AIAnalysisRequest> = {}): AIAnalysisRequest {
  const now = Date.now();
  return {
    request: createNetworkRequest({
      type: 'fetch',
      url: 'https://evil-skimmer.xyz/collect',
      method: 'POST',
      payloadSize: 256,
      timestamp: now
    }),
    recentInputs: [
      createSensitiveInput({
        fieldId: 'card-number',
        fieldType: SensitiveFieldType.CARD_NUMBER,
        inputLength: 16,
        timestamp: now - 100,
        domPath: 'form > input#cardNumber'
      }),
      createSensitiveInput({
        fieldId: 'cvv',
        fieldType: SensitiveFieldType.CVV,
        inputLength: 3,
        timestamp: now - 80,
        domPath: 'form > input#cvv'
      })
    ],
    currentDomain: 'shop.example.com',
    externalScripts: ['https://cdn.thirdparty.com/analytics.js'],
    heuristicVerdict: Verdict.SUSPICIOUS,
    heuristicConfidence: 0.8,
    heuristicReason: '짧은 시간 내 외부 도메인으로 전송',
    ...overrides
  };
}

describe('ProxyAIAdapter', () => {
  let adapter: ProxyAIAdapter;

  beforeEach(() => {
    jest.clearAllMocks();
    adapter = new ProxyAIAdapter(TEST_CONFIG);
  });

  // ─────────────────────────────────────────────
  // isEnabled / setEnabled
  // ─────────────────────────────────────────────
  describe('isEnabled / setEnabled', () => {
    it('기본적으로 비활성화 상태여야 함', () => {
      expect(adapter.isEnabled()).toBe(false);
    });

    it('setEnabled(true)로 활성화할 수 있어야 함', () => {
      adapter.setEnabled(true);
      expect(adapter.isEnabled()).toBe(true);
    });

    it('setEnabled(false)로 비활성화할 수 있어야 함', () => {
      adapter.setEnabled(true);
      adapter.setEnabled(false);
      expect(adapter.isEnabled()).toBe(false);
    });
  });

  // ─────────────────────────────────────────────
  // isAvailable
  // ─────────────────────────────────────────────
  describe('isAvailable', () => {
    it('서버가 응답하면 true를 반환해야 함', async () => {
      mockFetch.mockResolvedValueOnce({ ok: true, status: 200 });
      const result = await adapter.isAvailable();
      expect(result).toBe(true);
    });

    it('서버가 404를 반환해도 살아있으면 true를 반환해야 함', async () => {
      mockFetch.mockResolvedValueOnce({ ok: false, status: 404 });
      const result = await adapter.isAvailable();
      expect(result).toBe(true);
    });

    it('네트워크 에러 시 false를 반환해야 함', async () => {
      mockFetch.mockRejectedValueOnce(new Error('ECONNREFUSED'));
      const result = await adapter.isAvailable();
      expect(result).toBe(false);
    });

    it('타임아웃 시 false를 반환해야 함', async () => {
      const abortError = new DOMException('The user aborted a request.', 'AbortError');
      mockFetch.mockRejectedValueOnce(abortError);
      const result = await adapter.isAvailable();
      expect(result).toBe(false);
    });

    it('/health 엔드포인트로 요청을 보내야 함', async () => {
      mockFetch.mockResolvedValueOnce({ ok: true, status: 200 });
      await adapter.isAvailable();
      expect(mockFetch).toHaveBeenCalledWith(
        expect.stringContaining('/health'),
        expect.objectContaining({ method: 'GET' })
      );
    });
  });

  // ─────────────────────────────────────────────
  // analyze - 비활성화 상태
  // ─────────────────────────────────────────────
  describe('analyze (비활성화 상태)', () => {
    it('비활성화 상태에서는 UNKNOWN을 반환하고 fetch 호출 없어야 함', async () => {
      // adapter.setEnabled(false) 가 기본값
      const result = await adapter.analyze(createTestRequest());
      expect(result.verdict).toBe(Verdict.UNKNOWN);
      expect(mockFetch).not.toHaveBeenCalled();
    });
  });

  // ─────────────────────────────────────────────
  // analyze - 요청 포맷 검증
  // ─────────────────────────────────────────────
  describe('analyze - 요청 포맷', () => {
    beforeEach(() => {
      adapter.setEnabled(true);
    });

    it('/analyze 엔드포인트로 POST 요청을 보내야 함', async () => {
      mockFetchSuccess(makeServerResponse());
      await adapter.analyze(createTestRequest());

      expect(mockFetch).toHaveBeenCalledWith(
        `${TEST_BASE_URL}/analyze`,
        expect.objectContaining({ method: 'POST' })
      );
    });

    it('Content-Type: application/json 헤더를 포함해야 함', async () => {
      mockFetchSuccess(makeServerResponse());
      await adapter.analyze(createTestRequest());

      expect(mockFetch).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          headers: expect.objectContaining({
            'Content-Type': 'application/json'
          })
        })
      );
    });

    it('서버 API 스펙에 맞는 request body를 전송해야 함', async () => {
      mockFetchSuccess(makeServerResponse());
      await adapter.analyze(createTestRequest());

      const call = mockFetch.mock.calls[0];
      const body = JSON.parse(call[1].body as string);

      // 최상위 필드 확인
      expect(body).toHaveProperty('networkEvent');
      expect(body).toHaveProperty('behaviorContext');
      expect(body).toHaveProperty('recentInputs');
      expect(body).toHaveProperty('environment');
      expect(body).toHaveProperty('heuristicContext');
    });

    it('networkEvent 필드가 올바르게 매핑되어야 함', async () => {
      mockFetchSuccess(makeServerResponse());
      await adapter.analyze(createTestRequest());

      const body = JSON.parse(mockFetch.mock.calls[0][1].body as string);
      const ne = body.networkEvent;

      expect(ne.destinationUrl).toBeDefined();
      expect(ne.method).toBe('POST');
      expect(ne.type).toBeDefined();
      expect(typeof ne.payloadSize).toBe('number');
      expect(ne.payloadFormat).toBeDefined();
      expect(ne.initiatorScript).toBeDefined();
    });

    it('recentInputs 배열이 fieldType과 length를 포함해야 함', async () => {
      mockFetchSuccess(makeServerResponse());
      await adapter.analyze(createTestRequest());

      const body = JSON.parse(mockFetch.mock.calls[0][1].body as string);
      expect(Array.isArray(body.recentInputs)).toBe(true);
      expect(body.recentInputs.length).toBeGreaterThan(0);

      const firstInput = body.recentInputs[0];
      expect(firstInput).toHaveProperty('fieldType');
      expect(firstInput).toHaveProperty('length');
    });

    it('heuristicContext에 휴리스틱 결과가 포함되어야 함', async () => {
      mockFetchSuccess(makeServerResponse());
      await adapter.analyze(createTestRequest({
        heuristicVerdict: Verdict.SUSPICIOUS,
        heuristicConfidence: 0.8,
        heuristicReason: '외부 도메인 즉시 전송'
      }));

      const body = JSON.parse(mockFetch.mock.calls[0][1].body as string);
      expect(body.heuristicContext.verdict).toBe('SUSPICIOUS');
      expect(body.heuristicContext.confidence).toBe(0.8);
      expect(body.heuristicContext.reason).toBe('외부 도메인 즉시 전송');
    });

    it('recentInputs가 없을 때 behaviorContext.timeSinceLastInputMs가 -1이어야 함', async () => {
      mockFetchSuccess(makeServerResponse());
      await adapter.analyze(createTestRequest({ recentInputs: [] }));

      const body = JSON.parse(mockFetch.mock.calls[0][1].body as string);
      expect(body.behaviorContext.timeSinceLastInputMs).toBe(-1);
    });

    it('externalScripts URL의 쿼리 파라미터를 마스킹해야 함', async () => {
      mockFetchSuccess(makeServerResponse());
      await adapter.analyze(createTestRequest({
        externalScripts: ['https://cdn.example.com/script.js?token=SECRET&id=123']
      }));

      const body = JSON.parse(mockFetch.mock.calls[0][1].body as string);
      const scripts: string[] = body.environment.externalScripts;
      expect(scripts[0]).not.toContain('SECRET');
    });

    it('URL 쿼리 파라미터를 마스킹해야 함', async () => {
      mockFetchSuccess(makeServerResponse());
      const request = createTestRequest({
        request: createNetworkRequest({
          type: 'fetch',
          url: 'https://evil.com/collect?card=4111111111111111&cvv=123',
          method: 'POST',
          payloadSize: 100,
          timestamp: Date.now()
        })
      });

      await adapter.analyze(request);

      const body = JSON.parse(mockFetch.mock.calls[0][1].body as string);
      // 쿼리 파라미터 값이 마스킹되어야 함
      expect(body.networkEvent.destinationUrl).not.toContain('4111111111111111');
    });
  });

  // ─────────────────────────────────────────────
  // analyze - 응답 파싱
  // ─────────────────────────────────────────────
  describe('analyze - 응답 파싱', () => {
    beforeEach(() => {
      adapter.setEnabled(true);
    });

    it('DANGEROUS 응답을 올바르게 파싱해야 함', async () => {
      mockFetchSuccess(makeServerResponse({
        verdict: 'DANGEROUS',
        confidence: 0.95,
        recommendation: 'BLOCK',
        reasonMessage: '카드 정보 탈취 시도'
      }));

      const result = await adapter.analyze(createTestRequest());
      expect(result.verdict).toBe(Verdict.DANGEROUS);
      expect(result.confidence).toBe(0.95);
      expect(result.recommendation).toBe(Recommendation.BLOCK);
      expect(result.reason).toBe('카드 정보 탈취 시도');
    });

    it('SUSPICIOUS 응답을 올바르게 파싱해야 함', async () => {
      mockFetchSuccess(makeServerResponse({
        verdict: 'SUSPICIOUS',
        confidence: 0.7,
        recommendation: 'WARN',
        reasonMessage: '의심스러운 패턴'
      }));

      const result = await adapter.analyze(createTestRequest());
      expect(result.verdict).toBe(Verdict.SUSPICIOUS);
      expect(result.recommendation).toBe(Recommendation.WARN);
    });

    it('SAFE 응답을 올바르게 파싱해야 함', async () => {
      mockFetchSuccess(makeServerResponse({
        verdict: 'SAFE',
        confidence: 0.9,
        recommendation: 'PROCEED',
        reasonMessage: '정상 결제 요청'
      }));

      const result = await adapter.analyze(createTestRequest());
      expect(result.verdict).toBe(Verdict.SAFE);
      expect(result.recommendation).toBe(Recommendation.PROCEED);
    });

    it('analysisDetails가 있으면 result.details에 포함해야 함', async () => {
      mockFetchSuccess(makeServerResponse({
        analysisDetails: {
          suspiciousFactors: ['외부 도메인', '즉각 전송'],
          safeFactors: []
        }
      }));

      const result = await adapter.analyze(createTestRequest());
      expect(result.details).toBeDefined();
      expect(result.details?.suspiciousFactors).toContain('외부 도메인');
    });

    it('confidence를 0~1 사이로 클램핑해야 함', async () => {
      mockFetchSuccess(makeServerResponse({ confidence: 1.5 }));
      const result = await adapter.analyze(createTestRequest());
      expect(result.confidence).toBeLessThanOrEqual(1);

      mockFetch.mockClear();
      mockFetchSuccess(makeServerResponse({ confidence: -0.3 }));
      const result2 = await adapter.analyze(createTestRequest());
      expect(result2.confidence).toBeGreaterThanOrEqual(0);
    });

    it('알 수 없는 verdict 문자열은 Verdict.UNKNOWN으로 폴백해야 함', async () => {
      mockFetchSuccess(makeServerResponse({ verdict: 'MALICIOUS' }));
      const result = await adapter.analyze(createTestRequest());
      expect(result.verdict).toBe(Verdict.UNKNOWN);
    });

    it('알 수 없는 recommendation 문자열은 Recommendation.WARN으로 폴백해야 함', async () => {
      mockFetchSuccess(makeServerResponse({ recommendation: 'REVIEW' }));
      const result = await adapter.analyze(createTestRequest());
      expect(result.recommendation).toBe(Recommendation.WARN);
    });

    it('analysisDetails가 없는 응답에서 result.details가 undefined여야 함', async () => {
      const responseWithoutDetails = {
        verdict: 'SUSPICIOUS',
        confidence: 0.7,
        recommendation: 'WARN',
        reasonMessage: '의심스러운 패턴'
      };
      mockFetchSuccess(responseWithoutDetails);
      const result = await adapter.analyze(createTestRequest());
      expect(result.details).toBeUndefined();
    });
  });

  // ─────────────────────────────────────────────
  // analyze - 에러 처리
  // ─────────────────────────────────────────────
  describe('analyze - 에러 처리', () => {
    beforeEach(() => {
      adapter.setEnabled(true);
    });

    it('서버 500 에러 시 throw해야 함 (재시도 없을 때)', async () => {
      mockFetchError(500);
      await expect(adapter.analyze(createTestRequest())).rejects.toThrow();
    });

    it('서버 400 에러는 재시도 없이 즉시 throw해야 함', async () => {
      mockFetchError(400, { error: 'Bad Request' });
      await expect(adapter.analyze(createTestRequest())).rejects.toThrow(/400/);
      // 400은 재시도 불가 코드 → fetch는 정확히 1번만 호출
      expect(mockFetch).toHaveBeenCalledTimes(1);
    });

    it('네트워크 에러 시 throw해야 함', async () => {
      mockFetch.mockRejectedValueOnce(new Error('ECONNREFUSED'));
      await expect(adapter.analyze(createTestRequest())).rejects.toThrow();
    });

    it('타임아웃 에러를 명확한 메시지로 throw해야 함', async () => {
      const abortError = new DOMException('The user aborted a request.', 'AbortError');
      mockFetch.mockRejectedValueOnce(abortError);
      await expect(adapter.analyze(createTestRequest())).rejects.toThrow(/timed out/i);
    });
  });

  // ─────────────────────────────────────────────
  // analyze - 재시도 로직
  // ─────────────────────────────────────────────
  describe('analyze - 재시도 로직', () => {
    it('500 에러는 재시도 후 성공하면 결과를 반환해야 함', async () => {
      const adapterWithRetry = new ProxyAIAdapter({
        ...TEST_CONFIG,
        maxRetries: 2,
        retryBaseDelayMs: 1  // 테스트 속도를 위해 최소 딜레이
      });
      adapterWithRetry.setEnabled(true);

      // 첫 번째 요청 500, 두 번째 성공
      mockFetchError(500);
      mockFetchSuccess(makeServerResponse({ verdict: 'DANGEROUS' }));

      const result = await adapterWithRetry.analyze(createTestRequest());
      expect(result.verdict).toBe(Verdict.DANGEROUS);
      expect(mockFetch).toHaveBeenCalledTimes(2);
    });

    it('maxRetries 횟수 초과 시 마지막 에러를 throw해야 함', async () => {
      const adapterWithRetry = new ProxyAIAdapter({
        ...TEST_CONFIG,
        maxRetries: 2,
        retryBaseDelayMs: 1
      });
      adapterWithRetry.setEnabled(true);

      // 모든 시도 실패 (1 + maxRetries = 3번)
      mockFetchError(500);
      mockFetchError(500);
      mockFetchError(500);

      await expect(adapterWithRetry.analyze(createTestRequest())).rejects.toThrow();
      expect(mockFetch).toHaveBeenCalledTimes(3);
    });
  });
});
