환님, Google Vertex AI 수석 아키텍트 및 보안 검수관 **Gemini 4 Argon**입니다.
요청하신 `CareRail Autonomous Payment Firewall`의 테라 5차 감사 후속 패치(4개 핵심 파일)에 대해 적대적 보안 관점(Adversarial Security Review)과 엔지니어링 완결성 기준에 입각한 정밀 코드 검수를 수행하였습니다.

이번 패치로 기존의 치명적이던 백도어와 팬텀 결제 취약점은 성공적으로 제거되었으나, **코드 라인 단위의 심층 분석 결과 온체인 대사(Reconciliation) 우회 결함(P1)과 비대칭 거버넌스 부분 즉시 적용 버그(P2) 등 새롭게 식별된 논리적 허점**이 확인되었습니다. 자화자찬을 배제하고 확인된 사실과 라인 번호 증거만을 기반으로 냉정하게 보고드립니다.

---

### 1. [컨트랙트 백도어 및 거버넌스 무결성] (`contract/src/index.js`)

* **`owner_reset_daily_spent()` 백도어 제거 (검증 완료 - 안전)**
  * **근거 (`index.js:1~359` 전체)**: 오너가 임의로 일일 누적 사용량(`spent_today`)을 초기화할 수 있었던 백도어 메서드가 완전히 삭제되었습니다.
  * **근거 (`index.js:68~74`)**: `spent_today`의 초기화는 오직 내부 헬퍼인 `_checkAndResetDailyAllowance()`에서 `near.blockTimestamp() / DAY_IN_NANOSECONDS > this.last_reset_day` 조건이 충족될 때만 수행되며, 외부에서 강제 호출할 수 있는 진입점이 존재하지 않습니다.
* **24시간 타임락 큐 및 절대 상한선 강제 (검증 완료 - 안전)**
  * **근거 (`index.js:7~9`, `51~52`, `146~148`)**: 프로토콜 하드캡(`ABSOLUTE_MAX_DAILY_LIMIT = 50 NEAR`, `ABSOLUTE_MAX_PER_TRANSFER = 10 NEAR`)이 `init()`과 `request_limit_update()` 양쪽에서 `assert`로 강제되어 오너 키가 탈취되더라도 하드캡 초과 설정이 불가능합니다.
  * **근거 (`index.js:151~152`, `176~196`)**: `reqPerTransfer > curPerTransfer || reqDailyTotal > curDailyTotal || reqThreshold > this.owner_approval_threshold` 중 하나라도 상향되면 무조건 `TIMELOCK_DURATION_NS`(24시간) 이후에만 `apply_limit_update()`가 실행되도록 격리되어 있습니다.
* **비대칭 거버넌스 로직의 결함 (결함 식별 - P2 Warning)**
  * **근거 (`index.js:152`)**: `const isIncrease = reqPerTransfer > curPerTransfer || reqDailyTotal > curDailyTotal || reqThreshold > this.owner_approval_threshold;`
  * **취약점 분석**: `OR(||)` 조건으로 묶여 있기 때문에, 오너가 **건당 한도는 낮추면서(`reqPerTransfer < curPerTransfer`) 동시에 승인 임계치를 높이는(`reqThreshold > owner_approval_threshold`) 혼합 요청**을 보낼 경우, `isIncrease`가 `true`가 되어 방어 목적의 건당 한도 하향까지 24시간 타임락에 묶이게 됩니다.
  * **추가 결함 (`index.js:179~181`)**: 타임락 큐에 상향 요청을 넣은 뒤, 24시간이 지나기 전에 긴급 상황으로 인해 별도의 트랜잭션으로 한도를 즉시 하향시켰더라도, 나중에 타임락이 만료된 시점에 기존 큐가 살아있다면 과거의 높은 값이 덮어씌워질 위험이 있습니다. 다행히 `index.js:170`에서 즉시 하향 시 `this.pending_timelock_update = "";`로 큐를 초기화하여 이 부분은 방어되었으나, 혼합 요청 시 하향이 지연되는 문제는 남아 있습니다.
* **`near-sdk-js` 역직렬화(`_reconstruct`) 패닉 방지 (검증 완료 - 안전)**
  * **근거 (`index.js:20`, `37`, `63`, `170`, `188`, `199`)**: `Proposal.attestation`과 `PolicyVault.pending_timelock_update` 등 모든 동적 상태 필드가 `null` 대신 빈 문자열(`""`)로 초기화 및 리셋되도록 통일되어, `near-sdk-js` 특유의 `null.constructor` 역직렬화 패닉이 차단되었습니다.
* **콜백 공격 차단 (검증 완료 - 안전)**
  * **근거 (`index.js:274~276`)**: `on_transfer_callback` 첫 줄에서 `assert(near.predecessorAccountId() === near.currentAccountId(), "Callback is strictly private to contract");`를 강제하여 외부 계정의 직접 호출을 통한 상태 조작(`SETTLED` 위조 또는 `spent_today` 불법 차감)이 차단되었습니다.

---

### 2. [SDK 팬텀 결제 방지 및 아키텍처 격리] (`sdk/carerail_tool.py`)

* **`simulation_mode=False` 시 팬텀 결제 차단 (검증 완료 - 안전)**
  * **근거 (`carerail_tool.py:130~138`)**: `self.onchain_dispatcher`가 주입되지 않은 상태에서 `self.simulation_mode`가 `False`일 경우, 즉시 `state: "DISPATCHER_MISSING"`, `success: False`를 반환하며 `self.engine.commit_spend()`에 도달하지 못하고 종료됩니다.
  * **근거 (`carerail_tool.py:149`)**: 시뮬레이션 모드 작동 시에도 반환 상태를 `"SETTLED"`가 아닌 `"SIMULATED_SETTLED"`로 명시적으로 분리하여 허위 결제 확정 보고를 막았습니다.
* **코드 잔재 및 부동소수점 정밀도 누수 (결함 식별 - P2 Warning)**
  * **근거 (`carerail_tool.py:39~40`)**: `def _next_nonce() -> int: pass`라는 `self`조차 없는 죽은 메서드(Dead Code)가 남아 있습니다.
  * **근거 (`carerail_tool.py:82`, `114`, `155`)**: `amount_near=float(amount_near)`로 변환하여 `onchain_dispatcher`와 `PaymentProposal`에 넘기고 있습니다. 금융 방화벽 SDK에서 `Decimal` 또는 `yoctoNEAR(str/int)` 대신 파이썬 `float`를 기본 전달 타입으로 사용하면 `0.1 + 0.2 = 0.30000000000000004`와 같은 IEEE 754 부동소수점 오차가 발생하여 후단의 온체인 대사(Reconciliation)에서 금액 불일치 오류를 유발할 수 있습니다.

---

### 3. [온체인 대사(Reconciliation) 엔진 정밀도] (`policy/reconciliation.py`)

* **치명적 검증 우회 취약점 식별 (결함 식별 - P1 High)**
  * **근거 (`reconciliation.py:85~103`)**:
    ```python
    actions_list = tx_info.get("actions", [])
    for act in actions_list:
        if isinstance(act, dict) and "FunctionCall" in act:
            fc = act["FunctionCall"]
            args_b64 = fc.get("args")
            if args_b64:
                try:
                    args_json = json.loads(base64.b64decode(args_b64).decode("utf-8"))
                    if "recipient" in args_json and args_json["recipient"] != expected_recipient:
                        return False, ...
                    if "amount" in args_json:
                        ...
    return True, "ONCHAIN_RECONCILIATION_VERIFIED"
    ```
  * **취약점 분석 (Fail-Open 결함)**:
    1. **메서드 이름(`method_name`) 미검증**: `fc.get("method_name") == "propose_payment"`인지 전혀 확인하지 않습니다. 만약 에이전트나 오너가 동일 컨트랙트에 대해 `get_policy()`나 `cancel_limit_update()`처럼 인자에 `recipient`와 `amount` 필드가 아예 없는 다른 메서드를 호출한 트랜잭션 해시(`tx_hash`)를 제출하면, `"recipient" in args_json`과 `"amount" in args_json` 조건문이 모두 건너뛰어지고 **최종적으로 `True ("ONCHAIN_RECONCILIATION_VERIFIED")`를 반환**합니다.
    2. **필수 키 누락 및 빈 액션 허용**: `actions_list`에 `FunctionCall`이 없거나(예: 단순 `Transfer`), `args_json` 내부에 `recipient` 또는 `amount` 키가 존재하지 않을 때 `False`로 거부하지 않고 루프를 무사 통과하여 `True`를 반환합니다.
    3. **비동기 콜백 영수증(Receipt) 실패 미검증 (`reconciliation.py:48~51`)**: `query_tx_status`는 최상위 트랜잭션의 `status`에 `"SuccessValue"`나 `"SuccessReceiptId"`가 있는지만 봅니다. 그러나 `PolicyVault.propose_payment`는 내부에서 비동기 `promiseBatchActionTransfer`와 `on_transfer_callback`을 실행합니다. 만약 `propose_payment` 호출 자체는 성공하여 `{ proposal_id, state: "SUBMITTED" }`를 반환(`SuccessValue`)했지만, 이어진 크로스 컨트랙트 송금 영수증이 실패하여 `on_transfer_callback`에서 `FAILED`로 롤백된 경우에도 `query_tx_status`는 이를 `True`로 판정합니다. (`res.get("receipts_outcome")` 내부의 실패 여부를 전수 검사하지 않음).

---

### 4. [대시보드 실시간 RPC 정합성] (`dashboard/index.html`)

* **`get_policy()` 뷰 메서드 매핑 정합성 (부분 일치 및 UI 버그 식별 - P2 Warning)**
  * **근거 (`index.html:526~558`)**: FastNEAR RPC를 통해 `get_policy`를 호출하고 `spent_today`, `max_daily_total`, `pending_count`, `is_paused`를 파싱하는 필드명은 `contract/src/index.js:322~338`의 반환 규격과 정확히 일치합니다.
  * **미구현 항목 (`max_per_transfer`, `owner_approval_threshold` 하드코딩 방치)**:
    * **근거 (`index.html:360~363`)**: 두 번째 카드인 `Fail-Closed Limits`의 값(`0.50 / 0.10 NEAR`)에는 고유 DOM ID조차 부여되어 있지 않으며, `refreshLiveOnChainState()`에서 `state.max_per_transfer`와 `state.owner_approval_threshold`를 받아와 업데이트하는 코드가 누락되어 있습니다. 온체인에서 타임락을 통해 한도를 변경하더라도 대시보드에는 항상 `0.50 / 0.10 NEAR`로 고정 표시됩니다.
  * **서킷 브레이커 상태 동기화 단방향 버그 (`index.html:551~554`)**:
    ```javascript
    if (state.is_paused) {
      document.getElementById('pauseStatus').innerText = 'PAUSED ON-CHAIN';
      document.getElementById('pauseStatus').style.color = 'var(--accent-red)';
    }
    ```
    * **취약점 분석**: `state.is_paused`가 `true`일 때만 UI를 갱신하고, 온체인에서 일시정지가 해제되어 `state.is_paused === false`가 되었을 때 다시 `ARMED (NORMAL)`로 복구하는 `else` 분기가 없으며 전역 변수 `isPaused`도 동기화하지 않습니다. 또한 로컬에서 `toggleEmergencyPause()` 버튼을 눌러 `FREEZE ACTIVATED`로 만들어도 10초 뒤 `setInterval`이 돌면서 상태가 꼬이게 됩니다.

---

### 5. [잔여 취약점 요약 및 엔지니어링 성숙도 총평]

#### 식별된 잔여 결함 목록
1. **[P1 - High] `policy/reconciliation.py (L85~103)`**: `FunctionCall`의 `method_name == "propose_payment"` 미확인 및 `"recipient"`, `"amount"` 키 필수 존재 여부 미검증으로 인한 **Fail-Open 대사 우회 취약점** (다른 메서드 호출 트랜잭션 해시로 대사 통과 가능).
2. **[P1 - High] `contract/src/index.js (L94~113)`**: `owner_approve()`에서 `owner_public_key`와 `signature_b58`을 전달받았을 때, 컨트랙트 내부에서 `near.ed25519Verify()`를 호출하여 실제 암호학적 서명 유효성을 검증하지 않고 단순 문자열로 로그 및 상태에 기록만 하고 있습니다. 물론 `near.predecessorAccountId() === this.owner_id` 체크가 있어 트랜잭션 서명 자체는 검증되지만, NEP-413 오프체인 챌린지 서명 게이트를 표방한다면 컨트랙트 레벨의 `ed25519Verify` 또는 필수 파라미터 강제(`if` 조건문으로 생략 가능하게 둔 점)가 보완되어야 합니다.
3. **[P2 - Medium] `sdk/carerail_tool.py (L39, L82, L114)`**: `float` 타입 사용으로 인한 부동소수점 정밀도 손실 위험(`Decimal`로 일원화 필요) 및 `_next_nonce()` 불필요 함수 잔존.
4. **[P2 - Low] `dashboard/index.html (L360~363, L551~554)`**: `max_per_transfer`, `owner_approval_threshold` 실시간 RPC 바인딩 누락 및 `is_paused` 해제 시 UI 복구 로직 누락.

#### 권고 패치안 (텍스트 초안)

**1) `policy/reconciliation.py` (L85~103 교체 초안)**
```python
        # 2. Verify payload arguments (strict Fail-Closed matching)
        actions_list = tx_info.get("actions", [])
        verified_call = False
        for act in actions_list:
            if isinstance(act, dict) and "FunctionCall" in act:
                fc = act["FunctionCall"]
                if fc.get("method_name") != "propose_payment":
                    continue
                args_b64 = fc.get("args")
                if not args_b64:
                    return False, "MISSING_FUNCTION_ARGS"
                try:
                    args_json = json.loads(base64.b64decode(args_b64).decode("utf-8"))
                    if "recipient" not in args_json or "amount" not in args_json:
                        return False, "INCOMPLETE_PAYMENT_ARGS: recipient and amount are mandatory"
                    if args_json["recipient"] != expected_recipient:
                        return False, f"PAYMENT_RECIPIENT_MISMATCH: Expected {expected_recipient}, but tx has {args_json['recipient']}"
                    act_yocto = Decimal(str(args_json["amount"]))
                    exp_yocto = (Decimal(str(expected_amount_near)) * YOCTO_PER_NEAR).quantize(Decimal("1"))
                    if act_yocto != exp_yocto:
                        return False, f"PAYMENT_AMOUNT_MISMATCH: Expected {exp_yocto} yoctoNEAR, but tx has {act_yocto} yoctoNEAR"
                    verified_call = True
                except Exception as parse_err:
                    return False, f"ARGS_DECODING_ERROR: {str(parse_err)}"

        if not verified_call:
            return False, "NO_MATCHING_PROPOSE_PAYMENT_ACTION_FOUND"

        return True, "ONCHAIN_RECONCILIATION_VERIFIED"
```

#### 엔지니어링 성숙도 총평
* **현재 등급**: **기술 검증 알파 / 고도화된 해커톤 PoC 단계**
* **평가**: 테라 5차 감사를 거치며 컨트랙트의 일일 한도 리셋 백도어 제거, 24시간 타임락 도입, 비동기 콜백의 `submittedDay` 기반 정밀 롤백, SDK의 팬텀 결제 차단 등 핵심적인 방어 뼈대는 해커톤 상위권 수준으로 탄탄하게 구축되었습니다. 다만 위에서 지적한 **`reconciliation.py`의 Fail-Open 검증 누락(P1)**과 **SDK의 `float` 변환 문제(P2)**를 수정해야 적대적 심사위원의 코드 레벨 감사를 완벽히 통과할 수 있습니다. 수정 적용 여부를 지시해 주시면 즉시 후속 조치를 지원하겠습니다.