# SkimShield Extension

AI 기반 실시간 폼재킹(Formjacking) 탐지 Chrome 확장 프로그램

## 소개

SkimShield는 웹사이트에서 발생하는 폼재킹 공격을 실시간으로 탐지하고 차단하여 사용자의 결제 정보와 개인정보를 보호합니다.

### 폼재킹이란?

폼재킹은 악성 JavaScript 코드가 웹페이지의 입력 폼에서 신용카드 번호, 비밀번호 등 민감한 정보를 가로채 공격자의 서버로 전송하는 공격 기법입니다.

## 주요 기능

- **실시간 네트워크 모니터링**: 민감한 데이터가 외부로 전송되는 것을 감지
- **휴리스틱 탐지 엔진**: 8개 규칙(D001~D005, S001~S003)으로 의심 패턴 분석
- **AI 분석 (ProxyAIAdapter)**: 휴리스틱으로 판단 불가한 케이스를 외부 프록시 서버에 위임하여 심층 분석
- **initiatorScript 추적**: call stack 분석으로 요청을 발생시킨 외부 스크립트 식별
- **신뢰 도메인 관리**: 안전한 결제 게이트웨이 자동 허용
- **시각적 경고 시스템**: 위협 감지 시 즉각적인 알림 제공
- **트래픽 라이트 UI**: 현재 보안 상태를 직관적으로 표시

## 설치 방법

### 개발자 모드 설치

1. 저장소 클론
```bash
git clone https://github.com/BlueDongas/Skimshield_extension.git
cd Skimshield_extension
```

2. 의존성 설치
```bash
npm install
```

3. 빌드
```bash
npm run build
```

4. Chrome에서 확장 프로그램 로드
   - Chrome에서 `chrome://extensions` 접속
   - 우측 상단 "개발자 모드" 활성화
   - "압축해제된 확장 프로그램을 로드합니다" 클릭
   - `dist` 폴더 선택

## 개발

### 사전 요구사항

- Node.js 18.0.0 이상
- npm

### 스크립트

| 명령어 | 설명 |
|--------|------|
| `npm run dev` | 개발 모드 (watch) |
| `npm run build` | 프로덕션 빌드 |
| `npm run test` | 테스트 실행 |
| `npm run test:coverage` | 테스트 커버리지 리포트 |
| `npm run test:e2e` | E2E 테스트 실행 |
| `npm run lint` | ESLint 검사 |
| `npm run format` | Prettier 포맷팅 |

### AI 프록시 서버

AI 분석 기능을 활성화하려면 별도 프록시 서버가 필요합니다.

```bash
# 기본값: localhost:3000 자동 연결 시도
npm run build

# 운영 서버 지정
PROXY_API_URL=https://my-proxy.example.com npm run build
```

프록시 서버가 없어도 확장 프로그램은 정상 동작합니다 (휴리스틱 결과만 사용).

### E2E 테스트 서버

E2E 테스트를 위한 로컬 서버를 실행하려면:

```bash
cd tests/e2e/pages
npx serve -l 3000
```

서버 실행 후 http://localhost:3000 에서 테스트 페이지에 접근할 수 있습니다.

**테스트 페이지 목록**:
| 페이지 | 설명 |
|--------|------|
| `/index.html` | 메인 페이지 |
| `/normal-payment.html` | 정상 결제 페이지 |
| `/formjacking-attack.html` | 폼재킹 공격 시뮬레이션 |
| `/beacon-exfiltration.html` | Beacon API 탈취 시뮬레이션 |
| `/delayed-exfiltration.html` | 지연 탈취 시뮬레이션 |
| `/trusted-gateway.html` | 신뢰 게이트웨이 테스트 |

### 프로젝트 구조

```
src/
├── application/        # 유스케이스 및 서비스
├── domain/            # 엔티티, 규칙, 값 객체
├── infrastructure/    # 외부 어댑터 (저장소, 메시징)
├── presentation/      # UI (팝업, 콘텐츠 스크립트, 백그라운드)
└── shared/           # 공통 유틸리티 및 타입
```

## 테스트 현황

- 단위/통합 테스트: **605개 통과** (`npm run test`)
- E2E 테스트: `npm run test:e2e` (별도 서버 필요)

## 기술 스택

- **TypeScript** - 타입 안전성
- **Webpack** - 번들링
- **Jest** - 테스트 (605 tests passing)
- **Dexie** - IndexedDB 래퍼
- **Clean Architecture** - 설계 패턴

## 라이선스

MIT License
