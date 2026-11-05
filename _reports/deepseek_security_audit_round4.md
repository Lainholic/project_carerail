# CareRail 4차 최종 보안 재검증 보고서

**대상**: `policy/storage.py` (신규), `policy/engine.py` (연동 패치)
**판정**: **조건부 부적합 (CONDITIONAL FAIL)** — P1-B의 "영속성" 목표는 부분 달성했으나, 신규 레이어가 **P0급 신규 결함 3건**을 유입시켰습니다.

---

## 1. 질의 1: 영속 스토리지의 목표 달성 여부

### 1-1. 논스 재전송 영구 차단 — **부분 실패**

- `seen_nonces` 테이블과 `INSERT OR IGNORE`는 재시작 후에도 논스가 유지되는 구조 자체는 맞습니다.
- 그러나 **엔진의 1차 방어선은 여전히 인메모리 `self.seen_nonces` 집합**입니다 (`evaluate_proposal`의 `if proposal.nonce in self.seen_nonces`). 스토리지 조회(`is_nonce_consumed`)는 어디에서도 호출되지 않습니다.
- 결과적으로 **다중 프로세스/다중 인스턴스 환경에서 논스 재사용이 그대로 통과**합니다. 프로세스 A가 논스를 소비해도 프로세스 B의 인메모리 집합에는 반영되지 않습니다.
- `consume_nonce`의 `INSERT OR IGNORE`는 중복 삽입을 조용히 무시하므로, 경쟁 상태에서 **어느 쪽이 실제 승자인지 감지할 수 없습니다** (rowcount 미확인).

### 1-2. 일일 예산 복원 — **실패**

- `__init__`에서 **오직 오늘 날짜(`today_key`)의 원장만 복원**합니다.
- 어제 제출되어 `AWAITING_OWNER_APPROVAL` 상태로 남아 있던 예약(`reserved_spend`)은 인메모리 `daily_reserved_ledger`에 존재하지 않습니다.
- 이후 `commit_spend`가 어제 제출 건을 정산할 때 `self.daily_reserved_ledger.get(day_key, 0.0)` → `0.0`을 반환하고, `max(0.0, 0.0 - amount)` = `0.0`을 **스토리지에 덮어씁니다**. 이는 어제 원장의 다른 예약까지 **0으로 소거하는 데이터 파괴**입니다.

### 1-3. 프로세스 재시작 내구성 — **실패 (핵심 결함)**

- `self.proposals: Dict[str, PaymentProposal] = {}` — **재시작 시 빈 딕셔너리로 초기화**됩니다. `get_all_proposals()`는 구현되어 있으나 **호출되지 않습니다**.
- 따라서 재시작 후 `owner_approve(proposal_id, ...)`는 `"Proposal not found"`로 실패합니다. **P1-B(오프체인 상태 영속화)의 본래 목적이 무력화**됩니다.
- `get_proposal`이 반환하는 `state`는 문자열이며, `ProposalState` 열거형으로 역직렬화하는 코드가 없습니다. 복원을 시도하더라도 FSM 비교가 깨집니다.

---

## 2. 질의 2: 동시성·원자성·엣지케이스 정밀 평가

### P0 — 즉시 수정 필요

| # | 결함 | 위치 | 영향 |
|---|------|------|------|
| P0-1 | **TOCTOU 경쟁**: `evaluate_proposal`의 논스 검사 → 소비 → 예약 → 저장이 `self._lock` 밖에서 수행됨. 두 스레드가 동일 논스로 동시 진입 시 양쪽 모두 통과 | `engine.py` 전역 | 이중 지출, 예산 초과 |
| P0-2 | **다중 프로세스 논스 검증 부재**: 인메모리 집합만 신뢰 | `evaluate_proposal` | 재전송 공격 성립 |
| P0-3 | **재시작 시 proposals 미복원** | `__init__` | 승인 워크플로 전면 마비 |

### P1 — 설계 결함

- **비원자적 다단 트랜잭션**: `consume_nonce` → `set_daily_reserved` → `save_proposal`이 각각 별도 커밋. 중간 크래시 시 **논스만 소비되고 제안은 미저장** → 사용자 자금 영구 잠김.
- **`commit_spend`의 교차일 소거 버그**: 위 1-2 참조. 어제 원장의 `reserved_spend`를 0으로 덮어씀.
- **SQLite 동시성 미설정**: `PRAGMA journal_mode=WAL`, `PRAGMA busy_timeout`, `PRAGMA synchronous=NORMAL` 부재. 기본 롤백 저널 + `check_same_thread=False` 조합은 **"database is locked" 예외를 빈번히 유발**하며, 이 예외는 어디에서도 잡히지 않아 fail-open으로 이어질 수 있음.
- **부동소수점 화폐 연산**: `REAL` 타입과 `float` 누