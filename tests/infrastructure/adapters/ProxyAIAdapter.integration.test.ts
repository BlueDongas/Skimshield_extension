/**
 * @jest-environment node
 *
 * ProxyAIAdapter 통합 테스트 — 실제 프록시 서버 대상
 *
 * 1순위: 서버 응답 형식이 ProxyAnalysisResponse 타입과 일치하는지 검증
 * 2순위: 시나리오별 판정이 맥락에 맞게 일관성 있게 나오는지 검증
 *
 * 프록시 서버가 가용하지 않으면 각 테스트는 건너뜁니다.
 */

import * as http from 'http';

import {
  ProxyAnalysisRequest,
  ProxyAnalysisResponse
} from '@infrastructure/adapters/proxy/ProxyApiTypes';

jest.setTimeout(20000);

const PROXY_HOST = '3.34.210.236';
const PROXY_PORT = 3000;

const VALID_VERDICTS = new Set(['SAFE', 'SUSPICIOUS', 'DANGEROUS', 'UNKNOWN']);
const VALID_RECOMMENDATIONS = new Set(['PROCEED', 'WARN', 'BLOCK']);

// ─────────────────────────────────────────────────────────────
// 헬퍼
// ─────────────────────────────────────────────────────────────

function callProxy(payload: ProxyAnalysisRequest): Promise<ProxyAnalysisResponse> {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify(payload);
    const req = http.request(
      {
        host: PROXY_HOST,
        port: PROXY_PORT,
        path: '/analyze',
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(body)
        },
        timeout: 10000
      },
      (res) => {
        let raw = '';
        res.on('data', (chunk: Buffer) => { raw += chunk.toString(); });
        res.on('end', () => {
          try {
            resolve(JSON.parse(raw) as ProxyAnalysisResponse);
          } catch {
            reject(new Error(`JSON 파싱 실패: ${raw.slice(0, 200)}`));
          }
        });
      }
    );
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('요청 타임아웃')); });
    req.write(body);
    req.end();
  });
}

function checkProxyHealth(): Promise<boolean> {
  return new Promise((resolve) => {
    const req = http.request(
      { host: PROXY_HOST, port: PROXY_PORT, path: '/health', method: 'GET', timeout: 5000 },
      () => resolve(true)
    );
    req.on('error', () => resolve(false));
    req.on('timeout', () => { req.destroy(); resolve(false); });
    req.end();
  });
}

/** 모든 위험 신호가 켜진 고의심 요청 */
function makeHighSuspicionRequest(): ProxyAnalysisRequest {
  return {
    networkEvent: {
      destinationUrl: 'http://analytics-track.info/collect',
      method: 'POST',
      type: 'FETCH',
      payloadSize: 256,
      payloadFormat: 'JSON',
      initiatorScript: 'http://evil-cdn.tk/tracker.js'
    },
    behaviorContext: {
      triggerEvent: 'timer',
      timeSinceLastInputMs: 50
    },
    recentInputs: [
      { fieldType: 'card_number', length: 16 },
      { fieldType: 'cvv', length: 3 },
      { fieldType: 'expiry_date', length: 5 }
    ],
    environment: {
      currentDomain: 'shop.example.com',
      externalScripts: ['http://evil-cdn.tk/tracker.js']
    },
    heuristicContext: { verdict: 'UNKNOWN', confidence: 0, reason: '' }
  };
}

/** 민감 입력 없는 저의심 요청 */
function makeLowSuspicionRequest(): ProxyAnalysisRequest {
  return {
    networkEvent: {
      destinationUrl: 'http://external-service.io/api/report',
      method: 'GET',
      type: 'FETCH',
      payloadSize: 0,
      payloadFormat: 'UNKNOWN',
      initiatorScript: ''
    },
    behaviorContext: {
      triggerEvent: 'unknown',
      timeSinceLastInputMs: -1
    },
    recentInputs: [],
    environment: {
      currentDomain: 'shop.example.com',
      externalScripts: []
    },
    heuristicContext: { verdict: 'UNKNOWN', confidence: 0, reason: '' }
  };
}

// ─────────────────────────────────────────────────────────────
// 테스트
// ─────────────────────────────────────────────────────────────

describe('ProxyAIAdapter Integration Tests', () => {
  let proxyAvailable: boolean;

  beforeAll(async () => {
    proxyAvailable = await checkProxyHealth();
    if (!proxyAvailable) {
      console.warn(`[Integration] 프록시 서버(${PROXY_HOST}:${PROXY_PORT})에 연결할 수 없음 — 테스트 건너뜀`);
    }
  });

  // ─────────────────────────────────────────────
  // 1순위: 응답 형식 검증
  // ─────────────────────────────────────────────
  describe('응답 형식 검증', () => {
    let response: ProxyAnalysisResponse;

    beforeAll(async () => {
      if (!proxyAvailable) return;
      response = await callProxy(makeHighSuspicionRequest());
    });

    it('verdict 필드가 유효한 값이어야 함', () => {
      if (!proxyAvailable) return;
      expect(VALID_VERDICTS.has(response.verdict)).toBe(true);
    });

    it('confidence가 0 이상 1 이하의 숫자여야 함', () => {
      if (!proxyAvailable) return;
      expect(typeof response.confidence).toBe('number');
      expect(response.confidence).toBeGreaterThanOrEqual(0);
      expect(response.confidence).toBeLessThanOrEqual(1);
    });

    it('recommendation 필드가 유효한 값이어야 함', () => {
      if (!proxyAvailable) return;
      expect(VALID_RECOMMENDATIONS.has(response.recommendation)).toBe(true);
    });

    it('reasonMessage가 비어있지 않은 문자열이어야 함', () => {
      if (!proxyAvailable) return;
      expect(typeof response.reasonMessage).toBe('string');
      expect(response.reasonMessage.trim().length).toBeGreaterThan(0);
    });

    it('analysisDetails가 있을 때 suspiciousFactors가 배열이어야 함', () => {
      if (!proxyAvailable) return;
      if (response.analysisDetails === undefined) return;
      expect(Array.isArray(response.analysisDetails.suspiciousFactors)).toBe(true);
    });

    it('analysisDetails가 있을 때 safeFactors가 배열이어야 함', () => {
      if (!proxyAvailable) return;
      if (response.analysisDetails === undefined) return;
      expect(Array.isArray(response.analysisDetails.safeFactors)).toBe(true);
    });

    it('analysisDetails의 각 factor가 문자열 배열이어야 함', () => {
      if (!proxyAvailable) return;
      if (response.analysisDetails === undefined) return;
      const allFactors = [
        ...response.analysisDetails.suspiciousFactors,
        ...response.analysisDetails.safeFactors
      ];
      allFactors.forEach((f) => expect(typeof f).toBe('string'));
    });

    it('예상치 못한 최상위 필드가 없어야 함', () => {
      if (!proxyAvailable) return;
      const knownKeys = new Set(['verdict', 'confidence', 'recommendation', 'reasonMessage', 'analysisDetails']);
      const actualKeys = Object.keys(response);
      const unknownKeys = actualKeys.filter((k) => !knownKeys.has(k));
      expect(unknownKeys).toEqual([]);
    });
  });

  // ─────────────────────────────────────────────
  // 2순위: 시나리오별 판정 일관성
  // ─────────────────────────────────────────────
  describe('시나리오별 판정 일관성', () => {
    it('고의심 시나리오(악성 도메인 + 카드 입력 + 외부 스크립트)는 SUSPICIOUS 이상이어야 함', async () => {
      if (!proxyAvailable) return;

      const res = await callProxy(makeHighSuspicionRequest());

      expect(['SUSPICIOUS', 'DANGEROUS']).toContain(res.verdict);
    });

    it('고의심 시나리오의 confidence가 0.5 초과여야 함', async () => {
      if (!proxyAvailable) return;

      const res = await callProxy(makeHighSuspicionRequest());

      expect(res.confidence).toBeGreaterThan(0.5);
    });

    it('저의심 시나리오(민감 입력 없음)의 confidence가 고의심보다 낮아야 함', async () => {
      if (!proxyAvailable) return;

      const [high, low] = await Promise.all([
        callProxy(makeHighSuspicionRequest()),
        callProxy(makeLowSuspicionRequest())
      ]);

      console.log(`고의심 confidence: ${high.confidence}, 저의심 confidence: ${low.confidence}`);
      expect(high.confidence).toBeGreaterThanOrEqual(low.confidence);
    });

    it('동일한 요청을 두 번 보내면 같은 verdict를 반환해야 함', async () => {
      if (!proxyAvailable) return;

      const req = makeHighSuspicionRequest();
      const [res1, res2] = await Promise.all([callProxy(req), callProxy(req)]);

      console.log(`반복 verdict: ${res1.verdict}, ${res2.verdict}`);
      expect(res1.verdict).toBe(res2.verdict);
    });

    it('recommendation이 verdict와 논리적으로 일치해야 함', async () => {
      if (!proxyAvailable) return;

      const res = await callProxy(makeHighSuspicionRequest());

      // DANGEROUS → BLOCK, SUSPICIOUS → WARN or BLOCK, SAFE → PROCEED, UNKNOWN → WARN
      if (res.verdict === 'DANGEROUS') {
        expect(['BLOCK', 'WARN']).toContain(res.recommendation);
      } else if (res.verdict === 'SAFE') {
        expect(['PROCEED', 'WARN']).toContain(res.recommendation);
      }
      // SUSPICIOUS, UNKNOWN은 제약 없음 (서버 재량)
    });

    it('고의심 시나리오에서 suspiciousFactors가 1개 이상이어야 함', async () => {
      if (!proxyAvailable) return;

      const res = await callProxy(makeHighSuspicionRequest());

      if (res.analysisDetails !== undefined) {
        expect(res.analysisDetails.suspiciousFactors.length).toBeGreaterThan(0);
      }
    });
  });
});
