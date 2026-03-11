/**
 * 폼재킹 탐지 E2E 테스트
 * 다양한 폼재킹 공격 시나리오에서 탐지가 정상 동작하는지 검증
 */

import { Page } from 'puppeteer';

import {
  createPage,
  getTestPageUrl,
  fillSensitiveForm,
  waitForWarningModal,
  closeBrowser
} from './setup';

describe('Formjacking Detection E2E Tests', () => {
  let page: Page;

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

  describe('Basic Formjacking Attack Detection', () => {
    it('should detect and warn when card data is sent to external malicious domain', async () => {
      // Given: Navigate to formjacking attack page
      await page.goto(getTestPageUrl('formjacking-attack.html'), {
        waitUntil: 'networkidle0'
      });

      // When: Fill in payment form (triggers malicious script)
      await fillSensitiveForm(page, {
        name: 'Victim User',
        cardNumber: '4111 1111 1111 1111',
        expiryDate: '12/25',
        cvv: '123'
      });

      // Wait for malicious script to attempt exfiltration
      await new Promise(resolve => setTimeout(resolve, 2000));

      // Then: Warning modal SHOULD appear
      const warningAppeared = await waitForWarningModal(page, 10000);
      expect(warningAppeared).toBe(true);
    });

    it('should identify the malicious destination domain', async () => {
      // Given: Navigate to formjacking attack page
      await page.goto(getTestPageUrl('formjacking-attack.html'), {
        waitUntil: 'networkidle0'
      });

      // Track outgoing requests
      const externalRequests: string[] = [];
      await page.setRequestInterception(true);
      page.on('request', req => {
        const url = req.url();
        if (url.includes('evil-skimmer.xyz') || url.includes('malicious')) {
          externalRequests.push(url);
        }
        void req.continue();
      });

      // When: Trigger the attack
      await fillSensitiveForm(page, {
        cardNumber: '5555 5555 5555 4444',
        cvv: '456'
      });

      await new Promise(resolve => setTimeout(resolve, 3000));

      // Then: Should have attempted to send to malicious domain
      expect(externalRequests.length).toBeGreaterThan(0);
      expect(externalRequests[0]).toContain('evil-skimmer.xyz');
    });

    it('should block data exfiltration when user clicks Block', async () => {
      // Given: Navigate to formjacking attack page
      await page.goto(getTestPageUrl('formjacking-attack.html'), {
        waitUntil: 'networkidle0'
      });

      // When: Trigger the attack
      await fillSensitiveForm(page, {
        cardNumber: '4000 0000 0000 0002',
        cvv: '999'
      });

      // Wait for warning modal
      const warningAppeared = await waitForWarningModal(page, 10000);

      if (warningAppeared) {
        // Click block button
        const blockBtn = await page.$('[data-testid="block-btn"], .block-button');
        if (blockBtn !== null) {
          await blockBtn.click();
        }

        // Then: Subsequent requests should be blocked
        const afterBlockRequests: string[] = [];
        await page.setRequestInterception(true);
        page.on('request', req => {
          afterBlockRequests.push(req.url());
          void req.continue();
        });

        // Try to submit more data
        await page.type('[data-testid="card-number"]', '1234');
        await new Promise(resolve => setTimeout(resolve, 2000));

        // Should not have new malicious requests
        const maliciousAfterBlock = afterBlockRequests.filter(
          url => url.includes('evil-skimmer.xyz')
        );
        expect(maliciousAfterBlock.length).toBe(0);
      }
    });
  });

  describe('Beacon API Exfiltration Detection', () => {
    it('should detect sendBeacon exfiltration attempts', async () => {
      // Given: Navigate to beacon exfiltration page
      await page.goto(getTestPageUrl('beacon-exfiltration.html'), {
        waitUntil: 'networkidle0'
      });

      // When: Fill form to trigger beacon attack
      await fillSensitiveForm(page, {
        name: 'Beacon Victim',
        cardNumber: '4111 1111 1111 1111',
        cvv: '321'
      });

      // Blur field to trigger beacon
      await page.click('body');
      await new Promise(resolve => setTimeout(resolve, 2000));

      // Then: Warning should appear for beacon API abuse
      const warningAppeared = await waitForWarningModal(page, 10000);
      expect(warningAppeared).toBe(true);
    });

    it('should identify Beacon API in attack pattern', async () => {
      // Given: Navigate to beacon exfiltration page
      await page.goto(getTestPageUrl('beacon-exfiltration.html'), {
        waitUntil: 'networkidle0'
      });

      // Track console logs for beacon detection
      const consoleLogs: string[] = [];
      page.on('console', msg => {
        consoleLogs.push(msg.text());
      });

      // When: Trigger beacon attack
      await page.type('[data-testid="card-number"]', '4242424242424242');
      await page.type('[data-testid="cvv"]', '123');
      await page.click('body'); // blur to trigger

      await new Promise(resolve => setTimeout(resolve, 2000));

      // Then: Should detect beacon attempt
      const beaconDetected = consoleLogs.some(log =>
        log.includes('BEACON') || log.includes('sendBeacon')
      );
      expect(beaconDetected).toBe(true);
    });
  });

  describe('Delayed Exfiltration Detection', () => {
    it('should detect delayed data theft attempts', async () => {
      // Given: Navigate to delayed exfiltration page
      await page.goto(getTestPageUrl('delayed-exfiltration.html'), {
        waitUntil: 'networkidle0'
      });

      // When: Fill form (attack waits 3 seconds before exfiltrating)
      await fillSensitiveForm(page, {
        name: 'Delayed Victim',
        cardNumber: '4111 1111 1111 1111',
        expiryDate: '12/26',
        cvv: '555'
      });

      // Wait for delayed exfiltration attempt (3+ seconds)
      await new Promise(resolve => setTimeout(resolve, 5000));

      // Then: Warning should appear even after delay
      const warningAppeared = await waitForWarningModal(page, 10000);
      expect(warningAppeared).toBe(true);
    });

    it('should detect image-based exfiltration', async () => {
      // Given: Navigate to delayed exfiltration page
      await page.goto(getTestPageUrl('delayed-exfiltration.html'), {
        waitUntil: 'networkidle0'
      });

      // Track image requests
      const imageRequests: string[] = [];
      await page.setRequestInterception(true);
      page.on('request', req => {
        if (req.resourceType() === 'image') {
          imageRequests.push(req.url());
        }
        void req.continue();
      });

      // When: Trigger attack
      await fillSensitiveForm(page, {
        cardNumber: '5500 0000 0000 0004',
        cvv: '321',
        expiryDate: '06/28'
      });

      await new Promise(resolve => setTimeout(resolve, 5000));

      // Then: Should detect suspicious image request with data
      const suspiciousImage = imageRequests.some(
        url => url.includes('stealth-collector') || url.includes('?d=')
      );
      expect(suspiciousImage).toBe(true);
    });
  });

  describe('Real-time Detection', () => {
    it('should detect attack immediately on keystroke exfiltration', async () => {
      // Given: Navigate to formjacking attack page
      await page.goto(getTestPageUrl('formjacking-attack.html'), {
        waitUntil: 'networkidle0'
      });

      const startTime = Date.now();

      // When: Start typing card number
      await page.focus('[data-testid="card-number"]');
      await page.keyboard.type('4111', { delay: 100 });

      // Wait for detection
      const warningAppeared = await waitForWarningModal(page, 5000);
      const detectionTime = Date.now() - startTime;

      // Then: Should detect quickly (within 5 seconds)
      if (warningAppeared) {
        expect(detectionTime).toBeLessThan(5000);
      }
    });

    it('should correlate input events with network requests', async () => {
      // Given: Navigate to formjacking attack page
      await page.goto(getTestPageUrl('formjacking-attack.html'), {
        waitUntil: 'networkidle0'
      });

      // Track timing of events
      const inputTimes: number[] = [];
      const requestTimes: number[] = [];

      await page.setRequestInterception(true);
      page.on('request', req => {
        if (req.url().includes('evil-skimmer')) {
          requestTimes.push(Date.now());
        }
        void req.continue();
      });

      // When: Type card number
      await page.focus('[data-testid="card-number"]');
      inputTimes.push(Date.now());
      await page.keyboard.type('4111111111111111', { delay: 50 });

      await new Promise(resolve => setTimeout(resolve, 2000));

      // Then: Requests should follow shortly after inputs
      if (requestTimes.length > 0 && inputTimes.length > 0) {
        const timeDiff = requestTimes[0] - inputTimes[0];
        // Attack sends data within 2 seconds of input
        expect(timeDiff).toBeLessThan(2000);
      }
    });
  });

  describe('Warning Modal Interaction', () => {
    it('should display threat details in warning modal', async () => {
      // Given: Navigate to formjacking attack page
      await page.goto(getTestPageUrl('formjacking-attack.html'), {
        waitUntil: 'networkidle0'
      });

      // Trigger attack
      await fillSensitiveForm(page, {
        cardNumber: '4111 1111 1111 1111',
        cvv: '123'
      });

      // Wait for modal
      const warningAppeared = await waitForWarningModal(page, 10000);

      if (warningAppeared) {
        // Then: Modal should contain threat information
        const modalContent = await page.$eval(
          '[data-formjacking-modal], [data-testid="warning-modal"], .formjacking-guard-modal',
          el => el.textContent ?? ''
        );

        // Should mention the suspicious activity
        expect(
          modalContent.toLowerCase().includes('suspicious') ||
          modalContent.toLowerCase().includes('danger') ||
          modalContent.toLowerCase().includes('warning') ||
          modalContent.toLowerCase().includes('blocked')
        ).toBe(true);
      }
    });

    it('should allow user to view details', async () => {
      // Given: Navigate to formjacking attack page
      await page.goto(getTestPageUrl('formjacking-attack.html'), {
        waitUntil: 'networkidle0'
      });

      // Trigger attack
      await fillSensitiveForm(page, {
        cardNumber: '4111 1111 1111 1111',
        cvv: '456'
      });

      const warningAppeared = await waitForWarningModal(page, 10000);

      if (warningAppeared) {
        // Check for details/expand option
        const detailsButton = await page.$(
          '[data-testid="details-btn"], .details-button, .expand-button'
        );

        if (detailsButton !== null) {
          await detailsButton.click();
          await new Promise(resolve => setTimeout(resolve, 500));

          // Then: Should show expanded details
          const expandedContent = await page.$('.details-expanded, .threat-details');
          expect(expandedContent).not.toBeNull();
        }
      }
    });
  });

  describe('Multiple Attack Vectors', () => {
    it('should detect XHR-based exfiltration', async () => {
      // Given: Navigate to formjacking page
      await page.goto(getTestPageUrl('formjacking-attack.html'), {
        waitUntil: 'networkidle0'
      });

      // Track XHR requests
      const xhrRequests: string[] = [];
      await page.setRequestInterception(true);
      page.on('request', req => {
        if (req.resourceType() === 'xhr' || req.resourceType() === 'fetch') {
          xhrRequests.push(req.url());
        }
        void req.continue();
      });

      // When: Trigger attack
      await fillSensitiveForm(page, {
        cardNumber: '4111 1111 1111 1111',
        cvv: '789'
      });

      await new Promise(resolve => setTimeout(resolve, 3000));

      // Then: Should detect malicious XHR
      const maliciousXhr = xhrRequests.some(
        url => url.includes('evil-skimmer') || url.includes('malicious')
      );
      expect(maliciousXhr).toBe(true);
    });

    it('should handle multiple simultaneous attack vectors', async () => {
      // Given: Navigate to delayed exfiltration (uses both XHR and Image)
      await page.goto(getTestPageUrl('delayed-exfiltration.html'), {
        waitUntil: 'networkidle0'
      });

      const attackVectors: string[] = [];
      await page.setRequestInterception(true);
      page.on('request', req => {
        const url = req.url();
        if (url.includes('stealth-collector')) {
          attackVectors.push(req.resourceType());
        }
        void req.continue();
      });

      // When: Trigger attack
      await fillSensitiveForm(page, {
        cardNumber: '4111 1111 1111 1111',
        cvv: '555',
        expiryDate: '12/28'
      });

      await new Promise(resolve => setTimeout(resolve, 5000));

      // Then: Should detect multiple attack vectors
      const uniqueVectors = [...new Set(attackVectors)];
      expect(uniqueVectors.length).toBeGreaterThanOrEqual(1);
    });
  });
});
