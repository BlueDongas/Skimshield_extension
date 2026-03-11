/**
 * AI 프록시 서버 통신 E2E 테스트
 *
 * 목적: 휴리스틱이 UNKNOWN을 반환하는 시나리오에서
 *       실제로 AI 프록시 서버에 요청이 전송되고
 *       그 결과가 경고 모달에 반영되는지 검증
 *
 * UNKNOWN 유도 조건:
 *   - 민감 입력 후 800ms 뒤 외부 도메인으로 fetch (D001 500ms 기준 초과)
 *   - external-data-collector.io: 어떤 규칙 목록에도 없는 도메인
 *   → 모든 위험/안전 규칙 불발 → 휴리스틱 UNKNOWN → AI 호출
 *
 * 검증 방법:
 *   - 모달 제목이 "의심스러운 활동"이면 AI가 SUSPICIOUS 반환 (서버 통신 성공)
 *   - 모달 제목이 "확인 필요"이면 AI 미사용 (UNKNOWN 폴백)
 */

import * as http from 'http';

import { Page } from 'puppeteer';

import {
  createPage,
  getTestPageUrl,
  fillSensitiveForm,
  waitForWarningModal,
  closeBrowser
} from './setup';

const PROXY_HOST = '3.34.210.236';
const PROXY_PORT = 3000;

/**
 * 프록시 서버 도달 가능 여부 확인 (Node.js HTTP 클라이언트)
 */
function checkProxyAvailable(): Promise<boolean> {
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

/**
 * 모달이 열린 뒤 제목 텍스트 추출
 */
async function getModalTitle(page: Page): Promise<string> {
  return page.$eval(
    '[data-formjacking-modal] #fj-modal-title, [data-formjacking-modal] h2',
    (el) => el.textContent?.trim() ?? ''
  );
}

describe('AI Proxy Server Communication E2E Tests', () => {
  let page: Page;
  let proxyAvailable: boolean;

  beforeAll(async () => {
    proxyAvailable = await checkProxyAvailable();
    console.log(`Proxy server (${PROXY_HOST}:${PROXY_PORT}) available: ${proxyAvailable}`);
  });

  beforeEach(async () => {
    page = await createPage();
  });

  afterEach(async () => {
    if (page !== undefined) {
      await page.close();
    }
  });

  afterAll(async () => {
    await closeBrowser();
  });

  describe('Proxy Server Reachability', () => {
    it('should be reachable from test environment', () => {
      // 이 테스트가 실패하면 이하 테스트들은 AI 폴백(UNKNOWN) 경로로 동작함을 의미
      expect(proxyAvailable).toBe(true);
    });
  });

  /**
   * UNKNOWN 시나리오 페이지 이동 + 폼 입력 후 모달 대기 공통 헬퍼
   */
  async function loadAndTrigger(): Promise<boolean> {
    await page.goto(getTestPageUrl('ambiguous-external.html'), {
      waitUntil: 'networkidle0'
    });
    await fillSensitiveForm(page, {
      name: 'Test User',
      cardNumber: '4111 1111 1111 1111',
      expiryDate: '12/26',
      cvv: '123'
    });
    await new Promise(resolve => setTimeout(resolve, 2000));
    return waitForWarningModal(page, 15000);
  }

  describe('UNKNOWN Heuristic Scenario → AI Proxy Call', () => {
    it('should trigger AI analysis when heuristic returns UNKNOWN', async () => {
      const modalAppeared = await loadAndTrigger();
      expect(modalAppeared).toBe(true);
    });

    it('should show AI-enhanced result (SUSPICIOUS) not just UNKNOWN fallback', async () => {
      if (!proxyAvailable) {
        console.warn('Proxy server not reachable — skipping AI result verification');
        return;
      }

      const modalAppeared = await loadAndTrigger();
      expect(modalAppeared).toBe(true);

      const title = await getModalTitle(page);
      console.log(`Warning modal title: "${title}"`);
      expect(title).toBe('의심스러운 활동');
    });

    it('should include AI analysis details in the modal', async () => {
      if (!proxyAvailable) {
        console.warn('Proxy server not reachable — skipping AI details verification');
        return;
      }

      const modalAppeared = await loadAndTrigger();
      expect(modalAppeared).toBe(true);

      const modalContent = await page.$eval(
        '[data-formjacking-modal]',
        (el) => el.textContent ?? ''
      );
      console.log(`Modal content length: ${modalContent.length} chars`);
      expect(modalContent.length).toBeGreaterThan(20);
    });
  });

  // ─────────────────────────────────────────────
  // 3순위: AI 분석 결과 모달 UI 반영 검증
  // ─────────────────────────────────────────────
  describe('AI 분석 결과 모달 UI 반영', () => {
    it('SUSPICIOUS 판정 시 노란 신호등이 표시되어야 함', async () => {
      if (!proxyAvailable) {
        console.warn('Proxy server not reachable — skipping traffic light verification');
        return;
      }

      const modalAppeared = await loadAndTrigger();
      expect(modalAppeared).toBe(true);

      const trafficLightColor = await page.$eval(
        '[data-formjacking-modal] .traffic-light',
        (el) => {
          if (el.classList.contains('yellow')) return 'yellow';
          if (el.classList.contains('red')) return 'red';
          return 'green';
        }
      );
      console.log(`Traffic light color: ${trafficLightColor}`);

      // SUSPICIOUS → yellow
      expect(trafficLightColor).toBe('yellow');
    });

    it('AI analysisDetails의 suspiciousFactors가 모달 세부내용에 표시되어야 함', async () => {
      if (!proxyAvailable) {
        console.warn('Proxy server not reachable — skipping details verification');
        return;
      }

      const modalAppeared = await loadAndTrigger();
      expect(modalAppeared).toBe(true);

      // .details ul li 항목들이 존재해야 함
      const detailItems = await page.$$eval(
        '[data-formjacking-modal] .details li',
        (items) => items.map((li) => li.textContent?.trim() ?? '')
      );
      console.log(`Detail items (${detailItems.length}):`, detailItems);

      expect(detailItems.length).toBeGreaterThan(0);
      // 각 항목이 빈 문자열이 아닌지 확인
      detailItems.forEach((text) => expect(text.length).toBeGreaterThan(0));
    });

    it('대상 URL이 모달에 표시되어야 함', async () => {
      if (!proxyAvailable) {
        console.warn('Proxy server not reachable — skipping target URL verification');
        return;
      }

      const modalAppeared = await loadAndTrigger();
      expect(modalAppeared).toBe(true);

      const targetUrlText = await page.$eval(
        '[data-formjacking-modal] .target-url',
        (el) => el.textContent ?? ''
      );
      console.log(`Target URL display: "${targetUrlText}"`);

      // 외부 도메인이 표시되어야 함
      expect(targetUrlText).toContain('external-data-collector.io');
    });
  });
});
