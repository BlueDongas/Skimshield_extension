/**
 * payload body에서 전송 포맷을 감지하는 유틸리티
 *
 * [감지 우선순위]
 * 1. Content-Type 헤더 (가장 확실)
 * 2. body 구조 분석 — JSON, Form, Base64 순
 * 3. UNKNOWN fallback
 */

export type PayloadFormat = 'JSON' | 'FORM_DATA' | 'BASE64' | 'UNKNOWN';

/**
 * JWT 패턴: header.payload.signature
 * base64url 문자셋으로 구성된 3개 파트가 점(.)으로 구분됨
 */
const JWT_PATTERN = /^[A-Za-z0-9_=-]+\.[A-Za-z0-9_=-]+\.[A-Za-z0-9_=-]*$/;

/**
 * Shannon entropy 계산 (비트/문자)
 *
 * 완전 균일한 분포(64가지 문자): log2(64) = 6.0 비트
 * 일반 영어 텍스트: 약 3.0~4.5 비트
 * base64 인코딩된 데이터: 약 4.5~6.0 비트
 * 16진수 문자열(0-9, a-f): log2(16) = 4.0 비트
 */
function shannonEntropy(str: string): number {
  const freq = new Map<string, number>();
  for (const ch of str) {
    freq.set(ch, (freq.get(ch) ?? 0) + 1);
  }
  let entropy = 0;
  for (const count of freq.values()) {
    const p = count / str.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

/**
 * BASE64 고정밀 감지
 *
 * 다음 조건을 모두 통과해야 BASE64로 판정:
 *
 * 1. 최소 길이 (24자)
 *    - 짧은 ID, 토큰 등 오탐 제외
 *    - 24자 base64 = 18바이트 decoded (카드번호 16자리 > 16바이트)
 *
 * 2. JWT 패턴 제외
 *    - header.payload.signature 형식은 정상적인 인증 요청
 *
 * 3. Base64 문자셋 100% 사용
 *    - 표준 base64: [A-Za-z0-9+/] + 패딩(=)
 *    - URL-safe base64: [A-Za-z0-9_-] + 패딩(=)
 *    - 하나라도 벗어나면 base64 아님
 *
 * 4. 유효한 Base64 길이
 *    - 패딩 제거 후 length % 4 === 1 은 항상 무효
 *    - 예: "abc" (3자) → remainder 3 → 유효 / "a" (1자) → remainder 1 → 무효
 *
 * 5. atob() 디코딩 성공
 *    - 브라우저 내장 base64 파서로 실제 디코딩 가능 여부 검증
 *    - URL-safe 형식은 표준으로 정규화 후 검증
 *
 * 6. Shannon entropy ≥ 4.5
 *    - 단조로운 반복 문자열 제외 (예: "aaaa...aaaa")
 *    - 16진수 문자열 제외 (0-9,a-f만 사용 → entropy ≈ 4.0)
 *    - base64 인코딩된 실제 데이터는 항상 4.5 이상
 */
function isLikelyBase64(str: string): boolean {
  // 1. 최소 길이
  if (str.length < 24) return false;

  // 2. JWT 제외
  if (JWT_PATTERN.test(str)) return false;

  // 3. 문자셋 검사
  const isStandard = /^[A-Za-z0-9+/]+=*$/.test(str);
  const isUrlSafe  = /^[A-Za-z0-9_-]+=*$/.test(str);
  if (!isStandard && !isUrlSafe) return false;

  // 4. 유효한 길이 (패딩 제거 후 remainder가 1이면 무효)
  const withoutPadding = str.replace(/=+$/, '');
  if (withoutPadding.length % 4 === 1) return false;

  // 5. atob() 디코딩 검증 (URL-safe는 표준으로 정규화 후 검증)
  const normalized = (isUrlSafe && !isStandard)
    ? withoutPadding.replace(/-/g, '+').replace(/_/g, '/')
    : withoutPadding;
  const paddingNeeded = (4 - (normalized.length % 4)) % 4;
  try {
    atob(normalized + '='.repeat(paddingNeeded));
  } catch {
    return false;
  }

  // 6. Shannon entropy 검사
  if (shannonEntropy(str) < 4.5) return false;

  return true;
}

/**
 * payload body에서 전송 포맷 감지
 *
 * @param body   인터셉트된 요청 body 문자열
 * @param contentType  Content-Type 헤더 값 (없으면 빈 문자열)
 */
export function detectPayloadFormat(body: string, contentType: string): PayloadFormat {
  // 1. Content-Type으로 명확히 판별
  if (contentType.includes('application/json')) return 'JSON';
  if (
    contentType.includes('application/x-www-form-urlencoded') ||
    contentType.includes('multipart/form-data')
  ) return 'FORM_DATA';

  const trimmed = body.trim();
  if (trimmed.length === 0) return 'UNKNOWN';

  // 2. JSON 구조 감지 (Content-Type 없이 JSON을 전송하는 경우)
  if (
    (trimmed.startsWith('{') && trimmed.endsWith('}')) ||
    (trimmed.startsWith('[') && trimmed.endsWith(']'))
  ) {
    try {
      JSON.parse(trimmed);
      return 'JSON';
    } catch {
      // 유효하지 않은 JSON → 계속 진행
    }
  }

  // 3. URL-encoded form data 감지 (key=value&key2=value2)
  //    조건: 개행 없음 + key=value 패턴이 & 으로 연결
  if (/^[^=&\s]+=[^&]*(&[^=&\s]+=[^&]*)*$/.test(trimmed) && !trimmed.includes('\n')) {
    return 'FORM_DATA';
  }

  // 4. BASE64 고정밀 감지
  if (isLikelyBase64(trimmed)) return 'BASE64';

  return 'UNKNOWN';
}
