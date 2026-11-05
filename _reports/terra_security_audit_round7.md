# CareRail 보안 감사 Round 7 (GPT-6.1-Terra)

## 감사 일시: 2026-11-05
**감사 대상**: `contract/src/index.js`, `policy/engine.py`, `policy/reconciliation.py`, `sdk/carerail_tool.py`, `dashboard/index.html`

### 1. 종합 판정: FAIL — 심층 결함 지속 발굴 및 보완 필요

### 2. Round 6 후속 조치 판정

| 항목 | 판정 | 근거 |
|---|---|---|
| **P0-1 디스패치 결과 온체인 교차 검증** | 부분 완화, 미해결 | SDK에서 `verifier=None`이면 검증을 건너뛰고 `commit_spend()`에 도달할 수 있음. |
| **P1-1 승인 대기 반환 거부** | 부분 완화, 미해결 | `reconciliation.py`에서 JSON이 아니거나 빈 반환값, `state` 필드 누락 시 통과 허점 잔존. |
| **P1-4 승인 시 현재 정책 재검사** | **완화 확인 (PASS)** | `contract/src/index.js` 104–110행에서 수취인, 건별 한도, 일일 한도를 재검사함. WASM 배포 완료. |
| **P1-5 실패 시 예약 해제** | 부분 완화, 미해결 | 브로드캐스트 전/후 불명확한 실패 상태의 구분 없이 일괄 해제 시 중복 지급 위험. |

### 3. 신규 및 잔존 결함 상세

#### P0-1. 운영 모드에서 검증기(Verifier) 미주입 시 SETTLED 허위 반환 허점
- **근거:** `sdk/carerail_tool.py`
- `simulation_mode=False`일 때 `verifier` 주입을 필수로 강제하지 않아 `verifier=None`인 경우 온체인 교차 대사 없이 `SETTLED` 확정 가능.
- **조치:** 운영 모드에서는 `verifier`를 필수 강제하거나 기본 주입하여 미검증 트랜잭션의 커밋을 원천 차단.

#### P0-2. 중복 제안 ID 시 기존 APPROVED 상태 재반환 허점
- **근거:** `policy/engine.py:199–207`
- 동일 제안 ID가 이미 존재하는 경우 기존 제안의 상태를 그대로 반환하여, 악의적 입력이 기존 `APPROVED` 상태를 업고 정책 검사를 우회해 디스패치될 위험.
- **조치:** 중복 ID 인입 시 즉시 `REJECTED (DUPLICATE_PROPOSAL_ID)`로 차단하고, 충돌 저항성 있는 고유 ID 체계 적용.

#### P1-1. 대사 엔진의 Fail-Closed 반환값 검증 강화
- **근거:** `policy/reconciliation.py`
- `SuccessValue`가 비어 있거나 유효한 JSON이 아니거나 `state` 필드가 누락된 경우 Fail-Closed로 거부하지 않고 통과하는 예외 처리 허점.
- **조치:** 반환값이 존재하고 파싱된 `state == "SUBMITTED"`인 경우에만 엄격하게 검증 통과(Fail-Closed).

#### P1-2. 수신인(receiver_id) 누락 트랜잭션 검증 허점
- **근거:** `policy/reconciliation.py`
- `actual_receiver`가 누락된 경우 거부하지 않고 통과하는 로직 수정 (`not actual_receiver or actual_receiver != contract_id`로 차단).
