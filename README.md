# SkimShield Extension

AI 기반 실시간 폼재킹(Formjacking) 탐지 Chrome 확장 프로그램

## 소개

SkimShield는 웹사이트에서 발생하는 폼재킹 공격을 실시간으로 탐지하고 차단하여 사용자의 결제 정보와 개인정보를 보호합니다.

### 폼재킹이란?

폼재킹은 악성 JavaScript 코드가 웹페이지의 입력 폼에서 신용카드 번호, 비밀번호 등 민감한 정보를 가로채 공격자의 서버로 전송하는 공격 기법입니다.

## 주요 기능

- **실시간 네트워크 모니터링**: 민감한 데이터가 외부로 전송되는 것을 감지
- **휴리스틱 탐지 엔진**: 의심스러운 패턴을 분석하여 위협 식별
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

## 기술 스택

- **TypeScript** - 타입 안전성
- **Webpack** - 번들링
- **Jest** - 테스트
- **Clean Architecture** - 설계 패턴

## 라이선스

MIT License
