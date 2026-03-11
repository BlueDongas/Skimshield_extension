/**
 * E2E 테스트 환경 설정
 * Puppeteer를 사용한 Chrome 확장 프로그램 테스트 환경 구성
 */

/* eslint-disable no-console, import/no-named-as-default-member */

import * as fs from 'fs';
import * as http from 'http';
import * as path from 'path';

import puppeteer, { Browser, Page } from 'puppeteer';

// 확장 프로그램 빌드 경로
export const EXTENSION_PATH = path.resolve(__dirname, '../../dist');

// 테스트 페이지 경로
export const TEST_PAGES_PATH = path.resolve(__dirname, 'pages');

// 테스트 서버 포트
export const TEST_SERVER_PORT = 3333;

// 브라우저 인스턴스
let browser: Browser | null = null;

// 테스트 서버 인스턴스
let testServer: http.Server | null = null;

/**
 * 확장 프로그램이 로드된 브라우저 시작
 */
export async function launchBrowserWithExtension(): Promise<Browser> {
  if (browser !== null) {
    return browser;
  }

  // 확장 프로그램 빌드 확인
  if (!fs.existsSync(EXTENSION_PATH)) {
    throw new Error(
      `Extension not built. Run 'npm run build' first. Expected path: ${EXTENSION_PATH}`
    );
  }

  browser = await puppeteer.launch({
    headless: false, // 확장 프로그램은 headless: false 필요
    args: [
      `--disable-extensions-except=${EXTENSION_PATH}`,
      `--load-extension=${EXTENSION_PATH}`,
      '--no-sandbox',
      '--disable-setuid-sandbox',
      '--disable-dev-shm-usage',
      '--disable-gpu',
      '--window-size=1280,800'
    ],
    defaultViewport: {
      width: 1280,
      height: 800
    }
  });

  // 확장 프로그램 로드 대기 (IndexedDB 초기화 포함)
  await new Promise(resolve => setTimeout(resolve, 5000));

  return browser;
}

/**
 * 새 페이지 생성
 */
export async function createPage(): Promise<Page> {
  const b = await launchBrowserWithExtension();
  const page = await b.newPage();

  // 콘솔 로그 출력 (디버깅용)
  page.on('console', msg => {
    if (process.env.DEBUG_E2E === 'true') {
      console.log('[PAGE]', msg.type(), msg.text());
    }
  });

  // 페이지 에러 출력
  page.on('pageerror', error => {
    console.error('[PAGE ERROR]', error.message);
  });

  return page;
}

/**
 * 테스트 서버 시작
 */
export async function startTestServer(): Promise<void> {
  if (testServer !== null) {
    return;
  }

  return new Promise((resolve, reject) => {
    testServer = http.createServer((req, res) => {
      const url = req.url ?? '/';
      const filePath = path.join(TEST_PAGES_PATH, url === '/' ? 'index.html' : url);

      // 파일 존재 확인
      if (!fs.existsSync(filePath)) {
        res.writeHead(404);
        res.end('Not Found');
        return;
      }

      // MIME 타입 결정
      const ext = path.extname(filePath);
      const mimeTypes: Record<string, string> = {
        '.html': 'text/html',
        '.js': 'application/javascript',
        '.css': 'text/css',
        '.json': 'application/json'
      };

      const contentType = mimeTypes[ext] ?? 'text/plain';

      // 파일 읽기 및 전송
      fs.readFile(filePath, (err, data) => {
        if (err !== null) {
          res.writeHead(500);
          res.end('Server Error');
          return;
        }

        res.writeHead(200, { 'Content-Type': contentType });
        res.end(data);
      });
    });

    testServer.listen(TEST_SERVER_PORT, () => {
      console.log(`Test server running at http://localhost:${TEST_SERVER_PORT}`);
      resolve();
    });

    testServer.on('error', reject);
  });
}

/**
 * 테스트 서버 종료
 */
export async function stopTestServer(): Promise<void> {
  if (testServer === null) {
    return;
  }

  const server = testServer;
  return new Promise(resolve => {
    server.close(() => {
      testServer = null;
      resolve();
    });
  });
}

/**
 * 브라우저 종료
 */
export async function closeBrowser(): Promise<void> {
  if (browser !== null) {
    await browser.close();
    browser = null;
  }
}

/**
 * 전체 정리
 */
export async function cleanup(): Promise<void> {
  await closeBrowser();
  await stopTestServer();
}

/**
 * 확장 프로그램 ID 가져오기
 */
export async function getExtensionId(): Promise<string> {
  const b = await launchBrowserWithExtension();
  const targets = b.targets();

  for (const target of targets) {
    const url = target.url();
    // chrome-extension://[extension-id]/ 형식에서 ID 추출
    const match = url.match(/chrome-extension:\/\/([a-z]+)\//);
    if (match !== null) {
      return match[1];
    }
  }

  throw new Error('Extension ID not found');
}

/**
 * 확장 프로그램 팝업 페이지 열기
 */
export async function openPopup(): Promise<Page> {
  const extensionId = await getExtensionId();
  const b = await launchBrowserWithExtension();
  const page = await b.newPage();

  await page.goto(`chrome-extension://${extensionId}/popup/popup.html`);
  await page.waitForSelector('#app', { timeout: 5000 });

  return page;
}

/**
 * 테스트 페이지 URL 생성
 */
export function getTestPageUrl(pageName: string): string {
  return `http://localhost:${TEST_SERVER_PORT}/${pageName}`;
}

/**
 * 민감 정보 입력 헬퍼
 */
export async function fillSensitiveForm(
  page: Page,
  data: {
    cardNumber?: string;
    cvv?: string;
    expiryDate?: string;
    name?: string;
  }
): Promise<void> {
  if (data.cardNumber !== undefined) {
    await page.type('[data-testid="card-number"], [name="cardNumber"], #cardNumber', data.cardNumber);
  }
  if (data.cvv !== undefined) {
    await page.type('[data-testid="cvv"], [name="cvv"], #cvv', data.cvv);
  }
  if (data.expiryDate !== undefined) {
    await page.type('[data-testid="expiry"], [name="expiryDate"], #expiryDate', data.expiryDate);
  }
  if (data.name !== undefined) {
    await page.type('[data-testid="name"], [name="cardholderName"], #cardholderName', data.name);
  }
}

/**
 * 경고 모달 대기 및 확인
 */
export async function waitForWarningModal(page: Page, timeout = 10000): Promise<boolean> {
  try {
    await page.waitForSelector('[data-formjacking-modal], [data-testid="warning-modal"], .formjacking-guard-modal', {
      timeout
    });
    return true;
  } catch {
    return false;
  }
}

/**
 * 네트워크 요청 가로채기 설정
 */
export async function setupRequestInterception(
  page: Page,
  handler: (url: string, method: string) => void
): Promise<void> {
  await page.setRequestInterception(true);

  page.on('request', request => {
    handler(request.url(), request.method());
    void request.continue();
  });
}

// Jest 글로벌 설정
beforeAll(async () => {
  await startTestServer();
});

afterAll(async () => {
  await cleanup();
});
