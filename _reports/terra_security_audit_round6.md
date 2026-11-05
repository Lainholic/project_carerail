# CareRail 보안 감사 Round 6 (GPT-6.1-Terra)

## 감사 일시: 2026-11-05
**감사 대상**: `contract/src/index.js`, `policy/engine.py`, `policy/reconciliation.py`, `sdk/carerail_tool.py`, `dashboard/index.html`

### 1. 종합 판정: FAIL — 기술 검증 알파/PoC 단계. 실결제 운영 적합성은 입증되지 않았습니다.

### 2. Round 5 후속 조치 판정

| 검증 항목 | 판정 | 근거 |
|---|---|---|
| `owner_reset_daily_spent()` 백도어 제거 | **PASS — 소스 검증 완료** | `contract/src/index.js:72–79`에서 일일 사용액 초기화는 날짜 변경 시 `_checkAndResetDailyAllowance()`가 수행하며, 임의 초기화 메서드는 완전 삭제됨. |
| 운영 모드에서 디스패처 없이 `SETTLED` 위조 차단 | **PASS — 지정 경로 한정** | `sdk/carerail_tool.py:118–145`에서 디스패처가 없고 `simulation_mode=False`이면 `DISPATCHER_MISSING`으로 반환해 `commit_spend()`에 도달하지 않음. |
| 승인 임계값 상향 시 24시간 타임락 | **PASS — 소스 검증 완료** | `contract/src/index.js:10, 172–186, 201–215`: 임계값 상향도 `isIncrease`에 포함되고 24시간 쿨다운 강제 적용됨. |
| 정산 검증 Fail-Closed | **FAIL** | `policy/reconciliation.py:93–126`: 송금이 실제로 일어나지 않고 `AWAITING_OWNER_APPROVAL`로 끝난 트랜잭션도 통과할 수 있는 경로 잔존. (P1-1) |
| 대시보드 정책 RPC 및 실시간 UI | **FAIL** | `refreshLiveOnChainState()`가 `get_policy`를 호출하나, 모의 실행과 실제 체인 동작이 분리되지 않음. (P1-3) |

### 3. 신규 및 잔존 주요 결함

#### P0-1. SDK가 디스패처의 성공 주장만으로 실제 정산을 확정
- **근거:** `sdk/carerail_tool.py:118–145, 154–170`
- SDK는 디스패처가 반환한 `(True, 문자열)`을 온체인 영수증이나 정산 검증기(`NearReconciliationVerifier`)로 직접 교차 검증하지 않고 즉시 `engine.commit_spend()`를 호출하여 `SETTLED` 확정.
- 디스패처가 오류 또는 변조로 `(True, "fake-hash")`를 반환할 경우 팬텀 정산이 발생할 수 있음.
- **해결책:** `carerail_tool.py` 내에 `verifier`를 주입하거나, `reconciliation.py`를 거쳐 온체인 실제 상태를 검증한 후에만 `SETTLED`로 전이.

#### P1-1. 송금이 발생하지 않은 승인 대기 제안도 정산 검증 통과 가능
- **근거:** `policy/reconciliation.py:51–58, 88–98, 100–128`, `contract/src/index.js:270–275`
- 임계값 초과 제안은 컨트랙트에서 `AWAITING_OWNER_APPROVAL` 상태로 저장되고 송금 promise를 발생시키지 않음.
- 그러나 대사 엔진은 `propose_payment` 인자와 트랜잭션 성공 여부만 확인하므로, 실제 자금이 송금되지 않았음에도 `ONCHAIN_RECONCILIATION_VERIFIED`로 판정할 수 있음.
- **해결책:** `ExecutionOutcome`의 반환값(SuccessValue)을 디코딩하여 컨트랙트 상태가 `SUBMITTED`이며 실제 콜백 또는 송금 영수증이 발생했는지를 엄격히 검증.

#### P1-4. 한도를 낮춘 뒤에도 기존 승인 대기 제안은 이전 한도로 실행 가능
- **근거:** `contract/src/index.js:94–106`
- 오너가 한도를 낮춘 후 과거에 생성된 승인 대기 제안을 `owner_approve()`할 때, 일일 누적 한도만 재검사하고 현재 건당 한도(`max_per_transfer`)는 재검사하지 않음.
- **해결책:** `owner_approve()` 시점에 현재 `max_per_transfer` 및 `is_paused` 상태를 반드시 재검사.

#### P1-5. 승인·예약 후 전송 실패 시 예약 예산 미해제 (예산 누수)
- **근거:** `sdk/carerail_tool.py:121–132`, `policy/engine.py`
- 엔진이 `APPROVED` 상태에서 예산을 예약(`RESERVED`)한 뒤, 디스패처가 실패(`dispatch_ok=False`)를 반환했을 때 예약된 예산을 롤백(`release_reservation`)하는 로직이 없어 가용 일일 예산이 잠길 위험.
- **해결책:** 디스패치 실패 시 `self.engine.release_reservation(proposal_id)`를 호출하여 예약 예산 즉시 복구.

#### P2-1. 정책 로딩 및 SDK에서의 Decimal 일원화 미비
- `policy/engine.py`의 `PolicyRules` 및 저장소 계층에서 정수 yoctoNEAR 또는 exact `Decimal`로 완벽히 통일 필요.
