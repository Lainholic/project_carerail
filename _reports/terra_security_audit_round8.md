# CareRail 보안 감사 Round 8 (GPT-6.1-Terra)

## 감사 일시: 2026-11-05
**감사 대상**: `contract/src/index.js`, `policy/engine.py`, `policy/reconciliation.py`, `sdk/carerail_tool.py`, `dashboard/index.html`

### 1. 종합 판정: P0/P1 잔존 결함 식별 (회계 상태 보존 및 브로드캐스트 후 롤백 엄단)

### 2. 핵심 분석 및 신규 식별 결함

#### P0-1. 브로드캐스트 후 결과 불명 시 섣부른 예약 해제로 인한 중복 지출(Double Spend) 위험
- **근거:** `sdk/carerail_tool.py`
- 트랜잭션이 브로드캐스트된 후 RPC 타임아웃, 일시적 영수증 미확인, 또는 검증 지연이 발생했을 때 `release_reservation()`을 호출하여 예약을 해제해 버리면, 실제로는 블록체인에서 송금이 성공했음에도 오프체인 장부는 미지출로 처리됨.
- 에이전트가 실패 응답을 보고 동일 결제를 재시도할 경우 **중복 자금 이체(Double Spending)**가 발생.
- **해결책:** 브로드캐스트 이후(`real_tx_hash` 수신 후)의 불확실한 실패는 예약을 해제하지 않고 `UNKNOWN` / `PENDING_RECONCILIATION` 상태로 잠그며, "확인 중이므로 재시도 금지" 피드백을 에이전트에 반환.

#### P1-1. 컨트랙트 콜백 반환값(boolean true)과 대사기(SUBMITTED dict) 스키마 수용
- **근거:** `contract/src/index.js`, `policy/reconciliation.py`
- 컨트랙트의 `propose_payment`는 자동 송금 시 `near.promiseReturn(callbackPromiseId)`를 호출하여 콜백의 반환값(`true`)이 최종 `SuccessValue`로 반환될 수 있음.
- 대사 엔진이 오직 `{ state: "SUBMITTED" }` JSON 딕셔너리만 허용할 경우, 실제 온체인 송금이 완료된 트랜잭션이 거부될 수 있음.
- **해결책:** `SuccessValue`가 boolean `true` (콜백 정상 정산)이거나, 딕셔너리의 `state == "SUBMITTED"`인 경우 모두 정상 정산으로 수용.

#### P1-3. 시뮬레이션 모드의 영속 원장 오염 방지
- **근거:** `sdk/carerail_tool.py`
- `simulation_mode=True`인 경우에도 공통 코드에서 `engine.commit_spend()`를 호출하여 영속 DB에 가상 트랜잭션을 기록하고 예산을 영구 차감하는 문제.
- **해결책:** 시뮬레이션 모드에서는 `commit_spend`를 호출하지 않고 순수 정책 적합성 결과(`SIMULATED_APPROVED`)만 반환.

#### P1-6. 대시보드 모의 시뮬레이션 명시 분리
- **근거:** `dashboard/index.html`
- 시뮬레이션 버튼과 모달에 `(SIMULATED)` 레이블을 명시하여 실제 온체인 트랜잭션과 명확히 구분.
