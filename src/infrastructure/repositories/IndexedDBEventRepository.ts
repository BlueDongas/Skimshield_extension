/**
 * ============================================================================
 * 파일: IndexedDBEventRepository.ts
 * ============================================================================
 *
 * [역할]
 * IEventRepository 인터페이스의 실제 구현체입니다.
 * IndexedDB를 사용하여 탐지 이벤트를 영구 저장합니다.
 *
 * [비유]
 * "보안 로그 데이터베이스"와 같습니다:
 * - 탐지된 모든 이벤트를 기록
 * - 조건별 검색 가능
 * - 오래된 기록 자동 삭제 가능
 *
 * [IndexedDB란?]
 * 브라우저 내장 NoSQL 데이터베이스
 * - localStorage보다 훨씬 많은 데이터 저장 가능
 * - 인덱스 기반 빠른 검색 지원
 * - Dexie 라이브러리로 사용 편의성 향상
 *
 * [Dexie 라이브러리]
 * IndexedDB의 래퍼 라이브러리
 * - Promise 기반 API
 * - 쿼리 빌더 제공
 * - 스키마 버전 관리
 *
 * [데이터베이스 스키마]
 * 테이블: events
 * 인덱스: id, verdict, targetDomain, currentDomain, timestamp
 *
 * [주요 메서드]
 * - initialize(): DB 연결 열기
 * - save(): 이벤트 저장
 * - findById(): ID로 조회
 * - findByFilter(): 조건 검색 (verdict, domain, 기간, limit)
 * - findByDomain(): 도메인별 조회
 * - findRecent(): 최근 N개 조회
 * - deleteOlderThan(): 오래된 이벤트 삭제
 * - deleteAll(): 전체 삭제
 * - exportAll(): JSON 내보내기
 *
 * [다른 파일과의 관계]
 * - IEventRepository.ts: 구현하는 인터페이스
 * - DetectionOrchestrator.ts: 이벤트 저장
 * - GetSecurityStatusUseCase.ts: 이벤트 조회
 * - Container.ts: 의존성 주입
 *
 * [흐름]
 * DetectionOrchestrator → save(event) → IndexedDB에 저장
 * 팝업 → findByFilter() → 이벤트 목록 조회
 * ============================================================================
 */

import { Dexie, Table } from 'dexie';

import {
  createDetectionEvent,
  DetectionEvent,
  DetectionEventJSON
} from '@domain/entities/DetectionEvent';
import { NetworkRequestType } from '@domain/entities/NetworkRequest';
import { EventFilter, IEventRepository } from '@domain/ports/IEventRepository';
import { Recommendation, Verdict } from '@domain/value-objects/Verdict';

/**
 * IndexedDB에 저장되는 이벤트 레코드 타입
 */
interface EventRecord {
  id: string;
  verdict: Verdict;
  confidence: number;
  reason: string;
  recommendation: Recommendation;
  matchedRuleId?: string;
  requestId: string;
  requestType: NetworkRequestType;
  targetDomain: string;
  currentDomain: string;
  timestamp: number;
}

/**
 * Dexie 데이터베이스 클래스
 */
class FormjackingDatabase extends Dexie {
  events!: Table<EventRecord, string>;

  constructor(name: string) {
    super(name);
    this.version(1).stores({
      events: 'id, verdict, targetDomain, currentDomain, timestamp'
    });
  }
}

/**
 * IndexedDB 이벤트 저장소 구현체
 */
export class IndexedDBEventRepository implements IEventRepository {
  private db: FormjackingDatabase;

  constructor(dbName: string = 'formjacking-events') {
    this.db = new FormjackingDatabase(dbName);
  }

  /**
   * 데이터베이스 초기화
   */
  async initialize(): Promise<void> {
    await this.db.open();
  }

  /**
   * 데이터베이스 연결 종료
   */
  close(): Promise<void> {
    this.db.close();
    return Promise.resolve();
  }

  /**
   * 이벤트 저장
   */
  async save(event: DetectionEvent): Promise<void> {
    const record = this.toRecord(event);
    await this.db.events.put(record);
  }

  /**
   * ID로 이벤트 조회
   */
  async findById(id: string): Promise<DetectionEvent | null> {
    const record = await this.db.events.get(id);
    if (record === undefined) {
      return null;
    }
    return this.toEntity(record);
  }

  /**
   * 필터로 이벤트 목록 조회
   */
  async findByFilter(filter: EventFilter): Promise<DetectionEvent[]> {
    const collection = this.db.events.toCollection();

    // 모든 레코드를 가져와서 필터링
    let records = await collection.toArray();

    // verdict 필터
    if (filter.verdict !== undefined) {
      records = records.filter((r) => r.verdict === filter.verdict);
    }

    // domain 필터 (대상 도메인 또는 현재 페이지 도메인 기준)
    if (filter.domain !== undefined) {
      records = records.filter(
        (r) => r.targetDomain === filter.domain || r.currentDomain === filter.domain
      );
    }

    // fromTimestamp 필터
    const fromTs = filter.fromTimestamp;
    if (fromTs !== undefined) {
      records = records.filter((r) => r.timestamp >= fromTs);
    }

    // toTimestamp 필터
    const toTs = filter.toTimestamp;
    if (toTs !== undefined) {
      records = records.filter((r) => r.timestamp <= toTs);
    }

    // 타임스탬프 내림차순 정렬
    records.sort((a, b) => b.timestamp - a.timestamp);

    // limit 적용
    if (filter.limit !== undefined) {
      records = records.slice(0, filter.limit);
    }

    return records.map((r) => this.toEntity(r));
  }

  /**
   * 도메인별 이벤트 조회
   */
  async findByDomain(
    domain: string,
    limit?: number
  ): Promise<DetectionEvent[]> {
    let records = await this.db.events
      .where('targetDomain')
      .equals(domain)
      .toArray();

    // 타임스탬프 내림차순 정렬
    records.sort((a, b) => b.timestamp - a.timestamp);

    // limit 적용
    if (limit !== undefined) {
      records = records.slice(0, limit);
    }

    return records.map((r) => this.toEntity(r));
  }

  /**
   * 최근 이벤트 조회
   */
  async findRecent(limit: number): Promise<DetectionEvent[]> {
    if (limit <= 0) {
      return [];
    }

    const records = await this.db.events
      .orderBy('timestamp')
      .reverse()
      .limit(limit)
      .toArray();

    return records.map((r) => this.toEntity(r));
  }

  /**
   * 이벤트 삭제
   */
  async delete(id: string): Promise<void> {
    await this.db.events.delete(id);
  }

  /**
   * 특정 시간 이전의 이벤트 삭제
   */
  async deleteOlderThan(timestamp: number): Promise<number> {
    const oldRecords = await this.db.events
      .where('timestamp')
      .below(timestamp)
      .toArray();

    const ids = oldRecords.map((r) => r.id);
    await this.db.events.bulkDelete(ids);

    return ids.length;
  }

  /**
   * 모든 이벤트 삭제
   */
  async deleteAll(): Promise<void> {
    await this.db.events.clear();
  }

  /**
   * 이벤트 개수 조회
   */
  async count(): Promise<number> {
    return this.db.events.count();
  }

  /**
   * 이벤트를 JSON으로 내보내기
   */
  async exportAll(): Promise<DetectionEventJSON[]> {
    const records = await this.db.events.toArray();
    return records.map((r) => {
      const json: DetectionEventJSON = {
        id: r.id,
        verdict: r.verdict,
        confidence: r.confidence,
        reason: r.reason,
        recommendation: r.recommendation,
        requestId: r.requestId,
        requestType: r.requestType,
        targetDomain: r.targetDomain,
        currentDomain: r.currentDomain,
        timestamp: r.timestamp
      };

      if (r.matchedRuleId !== undefined) {
        json.matchedRuleId = r.matchedRuleId;
      }

      return json;
    });
  }

  /**
   * DetectionEvent를 EventRecord로 변환
   */
  private toRecord(event: DetectionEvent): EventRecord {
    const record: EventRecord = {
      id: event.id,
      verdict: event.verdict,
      confidence: event.confidence,
      reason: event.reason,
      recommendation: event.recommendation,
      requestId: event.requestId,
      requestType: event.requestType,
      targetDomain: event.targetDomain,
      currentDomain: event.currentDomain,
      timestamp: event.timestamp
    };

    if (event.matchedRuleId !== undefined) {
      record.matchedRuleId = event.matchedRuleId;
    }

    return record;
  }

  /**
   * EventRecord를 DetectionEvent로 변환
   */
  private toEntity(record: EventRecord): DetectionEvent {
    // DetectionEvent의 ID를 직접 설정하기 위해 내부적으로 처리
    // createDetectionEvent는 새 ID를 생성하므로 별도 처리 필요
    return this.createEventWithId(record);
  }

  /**
   * 특정 ID로 DetectionEvent 생성
   */
  private createEventWithId(record: EventRecord): DetectionEvent {
    // 기본 이벤트 Props 생성
    const eventProps: Parameters<typeof createDetectionEvent>[0] = {
      verdict: record.verdict,
      confidence: record.confidence,
      reason: record.reason,
      recommendation: record.recommendation,
      requestId: record.requestId,
      requestType: record.requestType,
      targetDomain: record.targetDomain,
      currentDomain: record.currentDomain,
      timestamp: record.timestamp
    };

    if (record.matchedRuleId !== undefined) {
      eventProps.matchedRuleId = record.matchedRuleId;
    }

    // 기본 이벤트 생성 후 ID 덮어쓰기
    const baseEvent = createDetectionEvent(eventProps);

    // 저장된 ID를 사용하여 새 객체 생성
    const toJSON = (): DetectionEventJSON => {
      const json: DetectionEventJSON = {
        id: record.id,
        verdict: record.verdict,
        confidence: record.confidence,
        reason: record.reason,
        recommendation: record.recommendation,
        requestId: record.requestId,
        requestType: record.requestType,
        targetDomain: record.targetDomain,
        currentDomain: record.currentDomain,
        timestamp: record.timestamp
      };
      if (record.matchedRuleId !== undefined) {
        json.matchedRuleId = record.matchedRuleId;
      }
      return json;
    };

    const baseProps = {
      id: record.id,
      verdict: record.verdict,
      confidence: record.confidence,
      reason: record.reason,
      recommendation: record.recommendation,
      requestId: record.requestId,
      requestType: record.requestType,
      targetDomain: record.targetDomain,
      currentDomain: record.currentDomain,
      timestamp: record.timestamp,
      toJSON
    };

    const event: DetectionEvent = Object.freeze(
      record.matchedRuleId !== undefined
        ? { ...baseProps, matchedRuleId: record.matchedRuleId }
        : baseProps
    ) as DetectionEvent;

    // baseEvent를 참조하여 린터 경고 방지
    void baseEvent;

    return event;
  }
}
