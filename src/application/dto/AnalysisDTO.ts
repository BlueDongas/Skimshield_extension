/**
 * ============================================================================
 * 파일: AnalysisDTO.ts
 * ============================================================================
 *
 * [역할]
 * 데이터 전송 객체(DTO: Data Transfer Object)를 정의합니다.
 * 레이어 간 데이터를 주고받을 때 사용하는 "데이터 규격"입니다.
 *
 * [비유]
 * "택배 상자 규격"과 같습니다:
 * - 어떤 데이터를 어떤 형태로 보낼지 정의
 * - 보내는 쪽과 받는 쪽이 같은 형태를 사용
 *
 * [DTO vs 엔티티]
 * - 엔티티: 비즈니스 로직을 포함한 도메인 객체
 * - DTO: 순수한 데이터만 담은 전송용 객체 (로직 없음)
 *
 * [정의된 DTO들]
 *
 * 분석 관련:
 * - AnalysisRequestDTO: 네트워크 요청 분석을 요청할 때
 * - AnalysisResponseDTO: 분석 결과를 응답할 때
 *
 * 민감 입력 관련:
 * - SensitiveInputRequestDTO: 민감 입력 감지 요청
 * - SensitiveInputResponseDTO: 민감 입력 감지 결과
 *
 * 보안 상태 관련:
 * - SecurityStatusDTO: 현재 보안 상태 (팝업 표시용)
 *
 * 설정 관련:
 * - SettingsUpdateDTO: 설정 업데이트 요청
 * - WhitelistActionDTO: 화이트리스트 추가/제거 요청
 *
 * 이벤트 관련:
 * - EventListRequestDTO: 이벤트 목록 조회 요청
 * - EventSummaryDTO: 이벤트 요약 정보 (목록 표시용)
 *
 * [다른 파일과의 관계]
 * - 모든 유즈케이스에서 입력/출력 타입으로 사용
 * - MessageHandler에서 메시지 페이로드로 사용
 * - 팝업/콘텐츠 스크립트와 백그라운드 간 통신에 사용
 *
 * [흐름 예시]
 * Content Script → AnalysisRequestDTO 생성 → Background로 전송
 * → 분석 수행 → AnalysisResponseDTO 생성 → Content Script로 응답
 * ============================================================================
 */

import { NetworkRequestType } from '@domain/entities/NetworkRequest';
import { SensitiveFieldType } from '@domain/value-objects/SensitiveFieldType';
import { Recommendation, Verdict } from '@domain/value-objects/Verdict';
import { PayloadFormat } from '@shared/utils/payloadFormatUtils';

/**
 * 분석 요청 DTO
 */
export interface AnalysisRequestDTO {
  /** 네트워크 요청 정보 */
  request: {
    type: NetworkRequestType;
    url: string;
    method: string;
    headers?: Record<string, string>;
    payloadSize: number;
    payloadFormat?: PayloadFormat;
    initiatorScript?: string;
    timestamp: number;
  };
  /** 최근 민감 입력 정보 */
  recentInputs: ReadonlyArray<{
    fieldType: SensitiveFieldType;
    inputLength: number;
    timestamp: number;
  }>;
  /** 현재 도메인 */
  currentDomain: string;
  /** 외부 스크립트 목록 */
  externalScripts?: readonly string[];
}

/**
 * 분석 응답 DTO
 */
export interface AnalysisResponseDTO {
  /** 판정 결과 */
  verdict: Verdict;
  /** 신뢰도 (0.0 - 1.0) */
  confidence: number;
  /** 권장 조치 */
  recommendation: Recommendation;
  /** 판정 이유 */
  reason: string;
  /** 매칭된 규칙 ID (휴리스틱) */
  matchedRuleIds: readonly string[];
  /** AI 분석 사용 여부 */
  usedAI: boolean;
  /** 분석 소요 시간 (ms) */
  analysisTimeMs: number;
  /** 상세 정보 */
  details?: { suspiciousFactors: string[]; safeFactors: string[]; };
}

/**
 * 민감 입력 감지 요청 DTO
 */
export interface SensitiveInputRequestDTO {
  /** 필드 ID */
  fieldId: string;
  /** 필드 이름 또는 ID 속성 */
  fieldName?: string;
  /** input type 속성 */
  inputType?: string;
  /** autocomplete 속성 */
  autocomplete?: string;
  /** 입력 길이 */
  inputLength: number;
  /** DOM 경로 */
  domPath: string;
  /** 타임스탬프 */
  timestamp: number;
}

/**
 * 민감 입력 감지 응답 DTO
 */
export interface SensitiveInputResponseDTO {
  /** 민감 입력 여부 */
  isSensitive: boolean;
  /** 추론된 필드 타입 */
  fieldType: SensitiveFieldType;
  /** 고민감도 여부 */
  isHighSensitivity: boolean;
  /** 입력 ID */
  inputId: string;
}

/**
 * 보안 상태 DTO
 */
export interface SecurityStatusDTO {
  /** 전체 상태 */
  overallStatus: 'safe' | 'warning' | 'danger';
  /** 현재 도메인 */
  currentDomain: string;
  /** 현재 도메인이 화이트리스트에 있는지 */
  isWhitelisted: boolean;
  /** 최근 위험 이벤트 수 */
  recentDangerCount: number;
  /** 최근 의심 이벤트 수 */
  recentSuspiciousCount: number;
  /** 총 이벤트 수 */
  totalEventCount: number;
  /** 마지막 분석 시간 */
  lastAnalysisTime?: number;
  /** AI 분석 활성화 여부 */
  aiEnabled: boolean;
}

/**
 * 설정 업데이트 요청 DTO
 */
export interface SettingsUpdateDTO {
  /** AI 분석 활성화 */
  aiAnalysisEnabled?: boolean;
  /** 알림 활성화 */
  notificationsEnabled?: boolean;
  /** 자동 차단 활성화 */
  autoBlockEnabled?: boolean;
  /** 디버그 모드 */
  debugMode?: boolean;
  /** 데이터 보관 기간 (시간) */
  dataRetentionHours?: number;
}

/**
 * 화이트리스트 관리 요청 DTO
 */
export interface WhitelistActionDTO {
  /** 액션 타입 */
  action: 'add' | 'remove';
  /** 도메인 */
  domain: string;
}

/**
 * 이벤트 목록 요청 DTO
 */
export interface EventListRequestDTO {
  /** 필터 판정 */
  verdict?: Verdict;
  /** 필터 도메인 */
  domain?: string;
  /** 시작 시간 */
  fromTimestamp?: number;
  /** 종료 시간 */
  toTimestamp?: number;
  /** 최대 개수 */
  limit?: number;
}

/**
 * 이벤트 요약 DTO
 */
export interface EventSummaryDTO {
  /** 이벤트 ID */
  id: string;
  /** 판정 */
  verdict: Verdict;
  /** 신뢰도 */
  confidence: number;
  /** 대상 도메인 */
  targetDomain: string;
  /** 현재 도메인 */
  currentDomain: string;
  /** 이유 */
  reason: string;
  /** 타임스탬프 */
  timestamp: number;
}
