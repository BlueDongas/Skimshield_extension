/**
 * ============================================================================
 * 파일: Container.ts
 * ============================================================================
 *
 * [역할]
 * 의존성 주입(DI, Dependency Injection) 컨테이너입니다.
 * Clean Architecture의 핵심인 "의존성 역전"을 구현합니다.
 *
 * [비유]
 * "부품 창고 관리자"와 같습니다:
 * - 모든 부품(서비스)을 등록하고 보관
 * - 필요한 부서(클래스)에 적절한 부품 배달
 * - 부품 간의 연결 관계를 자동으로 처리
 *
 * [의존성 주입이란?]
 * 클래스가 필요한 객체를 직접 만들지 않고, 외부에서 "주입" 받는 패턴입니다.
 *
 * ```typescript
 * // ❌ 직접 생성 (강한 결합)
 * class DetectionOrchestrator {
 *   private engine = new HeuristicEngine(); // 직접 생성
 * }
 *
 * // ✅ 의존성 주입 (느슨한 결합)
 * class DetectionOrchestrator {
 *   constructor(private engine: IDetectionEngine) {} // 외부에서 주입
 * }
 * ```
 *
 * [왜 DI 컨테이너가 필요한가?]
 * - 테스트 용이성: 실제 객체 대신 Mock 객체 주입 가능
 * - 유연성: 구현체를 쉽게 교체 가능 (예: StubAI → BedrockAI)
 * - 관리 용이성: 모든 서비스를 한 곳에서 관리
 *
 * [등록되는 서비스]
 *
 * Infrastructure (저장소, 어댑터):
 * - eventRepository: IndexedDB 이벤트 저장소
 * - settingsRepository: Chrome Storage 설정 저장소
 * - blockingRepository: declarativeNetRequest 차단 저장소
 * - aiAnalyzer: AI 분석기 (현재 StubAIAdapter)
 * - messenger: Chrome 메시지 통신
 *
 * Domain (도메인 서비스):
 * - heuristicEngine: 휴리스틱 탐지 엔진
 *
 * Application (유즈케이스, 오케스트레이터):
 * - detectionOrchestrator: 탐지 총괄 조율
 * - detectSensitiveInputUseCase: 민감 입력 탐지
 * - analyzeNetworkRequestUseCase: 네트워크 요청 분석
 * - getSecurityStatusUseCase: 보안 상태 조회
 * - manageSettingsUseCase: 설정 관리
 * - manageBlockingUseCase: 차단 관리
 *
 * [싱글톤 패턴]
 * Container 자체가 싱글톤으로, 애플리케이션 전체에서 하나만 존재합니다.
 * 등록된 서비스들도 기본적으로 싱글톤으로 생성됩니다.
 *
 * [주요 메서드]
 * - getInstance(): 컨테이너 싱글톤 인스턴스 반환
 * - initialize(): 모든 서비스 팩토리 등록
 * - resolve(key): 서비스 인스턴스 반환 (지연 생성)
 * - override(key, service): 테스트용 서비스 교체
 *
 * [다른 파일과의 관계]
 * - background/index.ts: 컨테이너 초기화 및 서비스 해결
 * - 모든 UseCase, Repository: 여기서 생성되어 주입됨
 * - IXxx.ts (인터페이스): 실제 구현체가 아닌 인터페이스에 의존
 *
 * [흐름]
 * ```
 * Container.getInstance()
 *     ↓
 * initialize()
 *     ├→ 팩토리 함수들 등록 (lazy)
 *     └→ initialized = true
 *     ↓
 * resolve('detectionOrchestrator')
 *     ├→ 캐시에 있으면 → 반환
 *     └→ 없으면 → 팩토리 실행 → 캐시 저장 → 반환
 * ```
 * ============================================================================
 */

import { SensitiveInputResponseDTO } from '@application/dto/AnalysisDTO';
import { DetectionOrchestrator, DetectionOrchestratorDeps } from '@application/services/DetectionOrchestrator';
import {
  AnalyzeNetworkRequestUseCase,
  AnalyzeNetworkRequestUseCaseDeps
} from '@application/use-cases/AnalyzeNetworkRequestUseCase';
import {
  DetectSensitiveInputUseCase,
  DetectSensitiveInputUseCaseDeps,
  InputStore
} from '@application/use-cases/DetectSensitiveInputUseCase';
import {
  GetSecurityStatusUseCase,
  GetSecurityStatusUseCaseDeps
} from '@application/use-cases/GetSecurityStatusUseCase';
import {
  ManageSettingsUseCase,
  ManageSettingsUseCaseDeps
} from '@application/use-cases/ManageSettingsUseCase';
import {
  ManageBlockingUseCase,
  ManageBlockingUseCaseDeps
} from '@application/use-cases/ManageBlockingUseCase';
import { IAIAnalyzer } from '@domain/ports/IAIAnalyzer';
import { IBlockingRepository } from '@domain/ports/IBlockingRepository';
import { IDetectionEngine } from '@domain/ports/IDetectionEngine';
import { IEventRepository } from '@domain/ports/IEventRepository';
import { IMessenger } from '@domain/ports/IMessenger';
import { ISettingsRepository } from '@domain/ports/ISettingsRepository';
import { createHeuristicEngine, HeuristicEngine } from '@domain/services/HeuristicEngine';
import { ProxyAIAdapter } from '@infrastructure/adapters/proxy/ProxyAIAdapter';
import { ChromeMessenger } from '@infrastructure/messaging/ChromeMessenger';
import { ChromeStorageSettingsRepository } from '@infrastructure/repositories/ChromeStorageSettingsRepository';
import { DeclarativeNetRequestBlockingRepository } from '@infrastructure/repositories/DeclarativeNetRequestBlockingRepository';
import { IndexedDBEventRepository } from '@infrastructure/repositories/IndexedDBEventRepository';

/**
 * 서비스 키 타입
 */
export type ServiceKey =
  | 'eventRepository'
  | 'settingsRepository'
  | 'blockingRepository'
  | 'aiAnalyzer'
  | 'messenger'
  | 'heuristicEngine'
  | 'detectionOrchestrator'
  | 'detectSensitiveInputUseCase'
  | 'analyzeNetworkRequestUseCase'
  | 'getSecurityStatusUseCase'
  | 'manageSettingsUseCase'
  | 'manageBlockingUseCase'
  | 'inputStore';

/**
 * 서비스 타입 매핑
 */
export interface ServiceMap {
  eventRepository: IEventRepository;
  settingsRepository: ISettingsRepository;
  blockingRepository: IBlockingRepository;
  aiAnalyzer: IAIAnalyzer;
  messenger: IMessenger;
  heuristicEngine: HeuristicEngine;
  detectionOrchestrator: DetectionOrchestrator;
  detectSensitiveInputUseCase: DetectSensitiveInputUseCase;
  analyzeNetworkRequestUseCase: AnalyzeNetworkRequestUseCase;
  getSecurityStatusUseCase: GetSecurityStatusUseCase;
  manageSettingsUseCase: ManageSettingsUseCase;
  manageBlockingUseCase: ManageBlockingUseCase;
  inputStore: InputStore;
}

/**
 * 타임스탬프를 포함한 입력 저장 항목
 */
interface StoredInput {
  input: SensitiveInputResponseDTO;
  timestamp: number;
}

/**
 * 간단한 인메모리 InputStore 구현
 */
class InMemoryInputStore implements InputStore {
  private inputs: StoredInput[] = [];
  private readonly maxSize = 100;

  add(input: SensitiveInputResponseDTO): void {
    this.inputs.push({ input, timestamp: Date.now() });
    if (this.inputs.length > this.maxSize) {
      this.inputs.shift();
    }
  }

  getRecent(withinMs: number): SensitiveInputResponseDTO[] {
    const threshold = Date.now() - withinMs;
    return this.inputs
      .filter((stored) => stored.timestamp >= threshold)
      .map((stored) => stored.input);
  }

  clear(): void {
    this.inputs = [];
  }
}

/**
 * DI 컨테이너 클래스
 */
export class Container {
  private static instance: Container | null = null;
  private services: Map<string, unknown> = new Map();
  private factories: Map<string, () => unknown> = new Map();
  private initialized = false;

  private constructor() {}

  /**
   * 싱글톤 인스턴스 반환
   */
  static getInstance(): Container {
    if (Container.instance === null) {
      Container.instance = new Container();
    }
    return Container.instance;
  }

  /**
   * 테스트용 인스턴스 리셋
   */
  static resetInstance(): void {
    Container.instance = null;
  }

  /**
   * 컨테이너 초기화
   */
  initialize(): void {
    if (this.initialized) {
      return;
    }

    // Infrastructure 레이어
    this.registerSingleton('eventRepository', () => new IndexedDBEventRepository());
    this.registerSingleton('settingsRepository', () => new ChromeStorageSettingsRepository());
    this.registerSingleton('blockingRepository', () => new DeclarativeNetRequestBlockingRepository());
    // AI 분석기 (프록시 서버를 통해 AI 분석 요청)
    this.registerSingleton('aiAnalyzer', () => new ProxyAIAdapter());
    this.registerSingleton('messenger', () => new ChromeMessenger());

    // Domain 서비스
    this.registerSingleton('heuristicEngine', () => createHeuristicEngine());

    // Input Store
    this.registerSingleton('inputStore', () => new InMemoryInputStore());

    // Application 서비스
    this.registerSingleton('detectionOrchestrator', () => {
      const deps: DetectionOrchestratorDeps = {
        heuristicEngine: this.resolve<IDetectionEngine>('heuristicEngine'),
        aiAnalyzer: this.resolve<IAIAnalyzer>('aiAnalyzer'),
        settingsRepository: this.resolve<ISettingsRepository>('settingsRepository'),
        eventRepository: this.resolve<IEventRepository>('eventRepository'),
        messenger: this.resolve<IMessenger>('messenger')
      };
      return new DetectionOrchestrator(deps);
    });

    // Use Cases
    this.registerSingleton('detectSensitiveInputUseCase', () => {
      const deps: DetectSensitiveInputUseCaseDeps = {
        inputStore: this.resolve<InputStore>('inputStore')
      };
      return new DetectSensitiveInputUseCase(deps);
    });

    this.registerSingleton('analyzeNetworkRequestUseCase', () => {
      const deps: AnalyzeNetworkRequestUseCaseDeps = {
        heuristicEngine: this.resolve<IDetectionEngine>('heuristicEngine'),
        aiAnalyzer: this.resolve<IAIAnalyzer>('aiAnalyzer'),
        settingsRepository: this.resolve<ISettingsRepository>('settingsRepository')
      };
      return new AnalyzeNetworkRequestUseCase(deps);
    });

    this.registerSingleton('getSecurityStatusUseCase', () => {
      const deps: GetSecurityStatusUseCaseDeps = {
        eventRepository: this.resolve<IEventRepository>('eventRepository'),
        settingsRepository: this.resolve<ISettingsRepository>('settingsRepository')
      };
      return new GetSecurityStatusUseCase(deps);
    });

    this.registerSingleton('manageSettingsUseCase', () => {
      const deps: ManageSettingsUseCaseDeps = {
        settingsRepository: this.resolve<ISettingsRepository>('settingsRepository')
      };
      return new ManageSettingsUseCase(deps);
    });

    this.registerSingleton('manageBlockingUseCase', () => {
      const deps: ManageBlockingUseCaseDeps = {
        blockingRepository: this.resolve<IBlockingRepository>('blockingRepository'),
        settingsRepository: this.resolve<ISettingsRepository>('settingsRepository')
      };
      return new ManageBlockingUseCase(deps);
    });

    this.initialized = true;
  }

  /**
   * 싱글톤 서비스 등록
   */
  registerSingleton<K extends ServiceKey>(key: K, factory: () => ServiceMap[K]): void {
    this.factories.set(key, factory);
  }

  /**
   * 서비스 해결
   */
  resolve<T>(key: ServiceKey): T {
    if (this.services.has(key)) {
      return this.services.get(key) as T;
    }

    const factory = this.factories.get(key);
    if (factory === undefined) {
      throw new Error(`Service not registered: ${key}`);
    }

    const service = factory();
    this.services.set(key, service);
    return service as T;
  }

  /**
   * 서비스 오버라이드 (테스트용)
   */
  override<K extends ServiceKey>(key: K, service: ServiceMap[K]): void {
    this.services.set(key, service);
  }

  /**
   * 컨테이너 리셋
   */
  reset(): void {
    this.services.clear();
    this.factories.clear();
    this.initialized = false;
  }

  /**
   * 초기화 여부 확인
   */
  isInitialized(): boolean {
    return this.initialized;
  }
}

/**
 * 전역 컨테이너 접근 함수
 */
export function getContainer(): Container {
  return Container.getInstance();
}

/**
 * 서비스 해결 헬퍼 함수
 */
export function resolveService<K extends ServiceKey>(key: K): ServiceMap[K] {
  return Container.getInstance().resolve<ServiceMap[K]>(key);
}
