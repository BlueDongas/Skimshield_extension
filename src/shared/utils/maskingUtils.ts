/**
 * ============================================================================
 * 파일: maskingUtils.ts
 * ============================================================================
 *
 * [역할]
 * 민감한 데이터를 마스킹(가리기)하는 유틸리티 함수들을 제공합니다.
 * 로그, 디버깅, UI 표시 시 실제 값을 노출하지 않기 위해 사용합니다.
 *
 * [비유]
 * "검열 마커"와 같습니다:
 * - 카드번호: 1234-****-****-5678
 * - 이메일: t***@example.com
 * - 실제 값은 숨기고 형태만 보여줌
 *
 * [제공하는 함수들]
 *
 * maskString(value, options):
 * - 기본 문자열 마스킹
 * - options: showFirst(앞 N자), showLast(뒤 N자), maskChar(마스킹 문자)
 * - 예: maskString("password", {showFirst: 1}) → "p*******"
 *
 * maskCardNumber(cardNumber):
 * - 카드번호 전용 마스킹 (앞 4자리, 뒤 4자리만 표시)
 * - 예: "1234567890123456" → "1234-********-3456"
 *
 * maskCVV(cvv):
 * - CVV 완전 마스킹 (전체 숨김)
 * - 예: "123" → "***"
 *
 * maskEmail(email):
 * - 이메일 마스킹 (로컬 파트 첫 글자만 표시)
 * - 예: "test@example.com" → "t***@example.com"
 *
 * maskPhoneNumber(phoneNumber):
 * - 전화번호 마스킹 (앞 3자리, 뒤 4자리만 표시)
 * - 예: "01012345678" → "010-****-5678"
 *
 * maskSensitiveFields(obj, sensitiveKeys):
 * - 객체에서 민감 필드들을 마스킹
 * - sensitiveKeys에 포함된 키의 값을 마스킹
 *
 * maskSensitiveJSON(jsonString, sensitiveKeys):
 * - JSON 문자열에서 민감 데이터 마스킹
 *
 * [다른 파일과의 관계]
 * - 디버그 로깅 시 민감 데이터 마스킹
 * - 이벤트 목록 UI 표시 시 사용 가능
 * ============================================================================
 */

/**
 * 마스킹 옵션
 */
export interface MaskingOptions {
  /** 앞에서 보여줄 문자 수 */
  showFirst?: number;
  /** 뒤에서 보여줄 문자 수 */
  showLast?: number;
  /** 마스킹 문자 */
  maskChar?: string;
}

const DEFAULT_OPTIONS: MaskingOptions = {
  showFirst: 0,
  showLast: 0,
  maskChar: '*'
};

/**
 * 문자열 마스킹
 */
export function maskString(
  value: string,
  options: MaskingOptions = {}
): string {
  const mergedOptions = { ...DEFAULT_OPTIONS, ...options };
  const showFirst = mergedOptions.showFirst ?? 0;
  const showLast = mergedOptions.showLast ?? 0;
  const maskChar = mergedOptions.maskChar ?? '*';

  if (value.length <= showFirst + showLast) {
    return maskChar.repeat(value.length);
  }

  const first = value.slice(0, showFirst);
  const last = showLast > 0 ? value.slice(-showLast) : '';
  const middleLength = value.length - showFirst - showLast;

  return first + maskChar.repeat(middleLength) + last;
}

/**
 * 카드 번호 마스킹 (예: 1234-****-****-5678)
 */
export function maskCardNumber(cardNumber: string): string {
  const digitsOnly = cardNumber.replace(/\D/g, '');

  if (digitsOnly.length < 13 || digitsOnly.length > 19) {
    return maskString(cardNumber);
  }

  const first4 = digitsOnly.slice(0, 4);
  const last4 = digitsOnly.slice(-4);
  const middleLength = digitsOnly.length - 8;

  return `${first4}-${'*'.repeat(middleLength)}-${last4}`;
}

/**
 * CVV 마스킹
 */
export function maskCVV(cvv: string): string {
  return '*'.repeat(cvv.length);
}

/**
 * 이메일 마스킹 (예: t***@example.com)
 */
export function maskEmail(email: string): string {
  const parts = email.split('@');
  const localPart = parts[0];
  const domain = parts[1];

  if (localPart === undefined || domain === undefined) {
    return maskString(email);
  }

  const maskedLocal =
    localPart.length <= 2
      ? '*'.repeat(localPart.length)
      : localPart[0] + '*'.repeat(localPart.length - 1);

  return `${maskedLocal}@${domain}`;
}

/**
 * 전화번호 마스킹 (예: 010-****-1234)
 */
export function maskPhoneNumber(phoneNumber: string): string {
  const digitsOnly = phoneNumber.replace(/\D/g, '');

  if (digitsOnly.length < 10) {
    return maskString(phoneNumber);
  }

  const first3 = digitsOnly.slice(0, 3);
  const last4 = digitsOnly.slice(-4);

  return `${first3}-****-${last4}`;
}

/**
 * 객체의 민감 필드 마스킹
 */
export function maskSensitiveFields(
  obj: Record<string, unknown>,
  sensitiveKeys: string[]
): Record<string, unknown> {
  const result: Record<string, unknown> = {};

  for (const [key, value] of Object.entries(obj)) {
    if (sensitiveKeys.some((k) => key.toLowerCase().includes(k.toLowerCase()))) {
      if (typeof value === 'string') {
        result[key] = maskString(value);
      } else {
        result[key] = '[MASKED]';
      }
    } else if (typeof value === 'object' && value !== null) {
      result[key] = maskSensitiveFields(
        value as Record<string, unknown>,
        sensitiveKeys
      );
    } else {
      result[key] = value;
    }
  }

  return result;
}

/**
 * URL의 쿼리 파라미터 값만 마스킹
 * scheme/host/path는 보존하고, fragment는 제거
 */
export function maskUrlQueryParams(url: string): string {
  try {
    const parsed = new URL(url);
    const masked = new URLSearchParams();
    parsed.searchParams.forEach((_value, key) => {
      masked.set(key, '****');
    });
    parsed.search = masked.size > 0 ? '?' + masked.toString() : '';
    parsed.hash = '';
    return parsed.toString();
  } catch {
    return url;
  }
}

/**
 * JSON 문자열에서 민감 데이터 마스킹
 */
export function maskSensitiveJSON(
  jsonString: string,
  sensitiveKeys: string[]
): string {
  try {
    const obj: unknown = JSON.parse(jsonString);
    if (typeof obj === 'object' && obj !== null && !Array.isArray(obj)) {
      const masked = maskSensitiveFields(obj as Record<string, unknown>, sensitiveKeys);
      return JSON.stringify(masked);
    }
    // 객체가 아닌 경우 그대로 반환
    return jsonString;
  } catch {
    // JSON 파싱 실패 시 전체 마스킹
    return maskString(jsonString);
  }
}
