/**
 * ============================================================================
 * 파일: NetworkRequest.ts
 * ============================================================================
 *
 * [역할]
 * 웹페이지에서 발생하는 네트워크 요청 정보를 나타내는 "엔티티"입니다.
 * 폼재킹 공격은 주로 네트워크 요청을 통해 데이터를 탈취하므로,
 * 이 정보가 탐지의 핵심 분석 대상입니다.
 *
 * [비유]
 * 우체국의 "발송 기록"과 같습니다:
 * - 어디로(URL, domain), 언제(timestamp), 어떻게(method, type)
 * - 얼마나(payloadSize) 보내는지 기록합니다.
 *
 * [저장하는 정보]
 * - type: 요청 유형 (FETCH, XHR, BEACON, FORM, WEBSOCKET)
 * - url: 요청 대상 URL
 * - method: HTTP 메서드 (GET, POST 등)
 * - domain: URL에서 추출한 도메인
 * - payloadSize: 전송 데이터 크기
 * - timestamp: 요청 시간
 *
 * [주요 함수]
 * - createNetworkRequest(): 새 NetworkRequest 생성 (URL 유효성 검사 포함)
 * - isExternalRequest(): 현재 페이지와 다른 도메인인지 확인
 * - isPostRequest(): POST 요청인지 확인
 * - isBeaconRequest(): Beacon API 요청인지 확인
 *
 * [다른 파일과의 관계]
 * - NetworkInterceptor.ts: 네트워크 요청 가로채서 NetworkRequest 생성
 * - injected.ts: 실제 네트워크 API 후킹
 * - DetectionOrchestrator.ts: 분석할 요청으로 전달
 * - DangerRules.ts: 탐지 규칙에서 요청 정보 분석
 *
 * [흐름]
 * 웹페이지 JS → fetch/XHR/Beacon 호출 → injected.ts 가로챔
 * → NetworkRequest 생성 → DetectionOrchestrator로 전달 → 규칙 분석
 * ============================================================================
 */

import { PayloadFormat } from '@shared/utils/payloadFormatUtils';

/**
 * 네트워크 요청 타입 열거형
 */
export enum NetworkRequestType {
  FETCH = 'fetch',
  XHR = 'xhr',
  BEACON = 'beacon',
  FORM = 'form',
  WEBSOCKET = 'websocket'
}

/**
 * NetworkRequest 생성 Props
 */
export interface NetworkRequestProps {
  type: NetworkRequestType;
  url: string;
  method: string;
  headers?: Record<string, string>;
  payloadSize: number;
  payloadFormat?: PayloadFormat;
  initiatorScript?: string;
  triggerEvent?: 'click' | 'submit' | 'blur' | 'timer' | 'unknown';
  timestamp: number;
}

/**
 * NetworkRequest 엔티티 인터페이스
 */
export interface NetworkRequest extends Readonly<Omit<NetworkRequestProps, 'headers'>> {
  readonly id: string;
  readonly domain: string;
  readonly headers: Readonly<Record<string, string>>;
}

/**
 * 고유 ID 생성
 */
function generateId(): string {
  return `req-${Date.now()}-${Math.random().toString(36).substring(2, 9)}`;
}

/**
 * URL에서 도메인 추출
 */
function extractDomain(url: string): string {
  try {
    const parsed = new URL(url);
    return parsed.hostname;
  } catch {
    throw new Error('유효하지 않은 URL입니다');
  }
}

/**
 * NetworkRequest 생성 함수
 */
export function createNetworkRequest(props: NetworkRequestProps): NetworkRequest {
  // 유효성 검사
  if (props.method.trim() === '') {
    throw new Error('method는 비어있을 수 없습니다');
  }

  if (props.payloadSize < 0) {
    throw new Error('payloadSize는 0 이상이어야 합니다');
  }

  // URL 유효성 검사 및 도메인 추출
  const domain = extractDomain(props.url);

  // headers 불변 객체 생성
  const frozenHeaders = Object.freeze({ ...(props.headers ?? {}) });

  // 불변 객체 생성
  const networkRequest: NetworkRequest = Object.freeze({
    id: generateId(),
    type: props.type,
    url: props.url,
    method: props.method,
    headers: frozenHeaders,
    payloadSize: props.payloadSize,
    ...(props.payloadFormat !== undefined ? { payloadFormat: props.payloadFormat } : {}),
    ...(props.initiatorScript !== undefined ? { initiatorScript: props.initiatorScript } : {}),
    ...(props.triggerEvent !== undefined ? { triggerEvent: props.triggerEvent } : {}),
    timestamp: props.timestamp,
    domain
  });

  return networkRequest;
}

/**
 * 외부 요청인지 확인
 * @param request 네트워크 요청
 * @param currentDomain 현재 페이지 도메인
 */
export function isExternalRequest(
  request: NetworkRequest,
  currentDomain: string
): boolean {
  const requestDomain = request.domain.toLowerCase();
  const pageDomain = currentDomain.toLowerCase();

  // 정확히 같은 도메인
  if (requestDomain === pageDomain) {
    return false;
  }

  // 서브도메인 체크: request가 currentDomain의 서브도메인인 경우
  if (requestDomain.endsWith(`.${pageDomain}`)) {
    return false;
  }

  // 부모 도메인 체크: currentDomain이 request의 서브도메인인 경우
  if (pageDomain.endsWith(`.${requestDomain}`)) {
    return false;
  }

  return true;
}

/**
 * POST 요청인지 확인
 */
export function isPostRequest(request: NetworkRequest): boolean {
  return request.method.toUpperCase() === 'POST';
}

/**
 * Beacon API 요청인지 확인
 */
export function isBeaconRequest(request: NetworkRequest): boolean {
  return request.type === NetworkRequestType.BEACON;
}
