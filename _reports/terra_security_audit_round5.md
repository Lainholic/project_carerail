# CareRail 보안 감사 보고서 - Round 5 (GPT-6.1-Terra)

## 감사 일시: 2026-11-05
**감사 대상**: `contract/src/index.js`, `policy/engine.py`, `policy/storage.py`, `policy/reconciliation.py`, `sdk/carerail_tool.py`, `dashboard/index.html`

### 1. 종합 판정: P0 결함 2건 발견 (실자금 투입 불가, 즉시 수정 필요)

| 우선순위 | 핵심 취약점 |
|---|---|
| **P0** | 온체인 `owner_reset_daily_spent()`로 일일 50 NEAR 절대 상한을 무제한 반복 리셋하여 금고 탈취 가능 |
| **P0** | SDK(`carerail_tool.py`)가 실제 온체인 송금과 영수증 검증 없이 가짜/빈 해시로 `SETTLED` 및 성공 반환 |
| **P1** | `request_limit_update`에서 승인 임계값(`owner_approval_threshold`) 상향 시 타임락 없이 즉시 적용되는 통제 우회 |
| **P1** | 정산 조정기(`reconciliation.py`)가 `expected_recipient`와 `expected_amount`를 인자로 받고도 실제 검증에 미사용 |
| **P1** | 대시보드(`dashboard/index.html`)가 컨트랙트의 `get_policy()` 대신 존재하지 않는 `get_vault_state`를 호출하여 실제 RPC 동기화 실패 |

### 2. 세부 결함 내용
1. **`owner_reset_daily_spent()` 백도어**:
   소유자 키 탈취 시 `propose_payment(10N)` -> `owner_reset_daily_spent()` -> `propose_payment(10N)` 반복 호출로 50 NEAR 일일 하드캡이 완전히 무력화됨.
2. **SDK 가짜 정산**:
   `carerail_tool.py`에서 `mock_tx=True` 시 가짜 해시 생성 후 즉시 `commit_spend` 호출, `mock_tx=False` 시 빈 해시로 커밋하여 실제 온체인 전송 없이 `PAYMENT_CONFIRMED`를 LLM에게 반환.
3. **거버넌스 타임락 우회**:
   건당 한도와 일일 한도를 그대로 둔 채 인간 승인 임계값만 10 NEAR로 올리면 `AppliedImmediately`로 분류되어 24시간 타임락 없이 인간 승인 방어선이 즉시 붕괴.
4. **대시보드 RPC 메서드 불일치**:
   `index.js`에 정의된 뷰 함수는 `get_policy`이나 대시보드는 `get_vault_state`를 호출하여 실제 체인 데이터 파싱 실패.
