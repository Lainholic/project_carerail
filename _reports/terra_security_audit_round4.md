# CareRail 보안 감사 보고서 - Round 4 (GPT-6.1-Terra)

## 감사 일시: 2026-11-05
**감사 대상**: `policy/storage.py`, `policy/engine.py`, `contract/src/index.js`, `dashboard/index.html`

### 1. 종합 판정: P1-B 조건부 미해결 (추가 보완 필요)
- SQLite 스토리지 계층이 추가되었으나, `CareRailEngine.__init__`에서 제안(`self.proposals`) 복원 코드가 누락되어 프로세스 재시작 시 기존 대기 제안에 대한 승인/커밋 불가.
- 논스 소비, 일일 예약 차감, 지출 증가, 제안 상태 변경이 분리된 트랜잭션으로 커밋되어 장애 시 상태 불일치 위험 존재.
- SQLite 기본값이 `":memory:"`로 남아있어 호출자가 명시적 파일 경로를 지정하지 않을 경우 휘발됨.
- `set_daily_reserved()`가 단순 overwrite 방식으로 동작하여 동시 요청 시 Lost Update 가능성.
- 대시보드(`dashboard/index.html`)가 시뮬레이션 위주로 구성되어 있어 "실제 체인 정지/정산"으로 오인될 위험.

### 2. 핵심 개선 권고사항
1. **제안 완전 복원**: `CareRailEngine.__init__`에서 `storage.get_all_proposals()`를 호출하여 `self.proposals`를 메모리에 온전히 재구성하고 `ProposalState` 열거형으로 역직렬화.
2. **트랜잭션 원자성 (`BEGIN IMMEDIATE`)**: 논스 검사 및 삽입, 일일 한도 검사, 예약 차감/증가, 제안 상태 저장을 단일 SQLite 트랜잭션으로 원자화.
3. **영속 파일 DB 기본값 전환**: 기본 DB를 `C:\AI\project_carerail\data\carerail.db` 등 명시적 파일 경로로 설정하거나 유효한 영속 파일 경로를 강제.
4. **동시성 방어**: 논스 유니크 제약 위반 시 즉시 거절하고 `INSERT OR IGNORE`가 아닌 무결성 에러 감지.
5. **대시보드 모드 명시**: 대시보드 상단에 `[SIMULATION & INTERACTIVE DEMO MODE]` 배지를 명확히 표시하여 관제 오인 방지.
