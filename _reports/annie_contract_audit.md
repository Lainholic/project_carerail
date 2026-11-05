안녕하세요, 환님. 구글 딥마인드 수석 아키텍트 애니(Annie)입니다.

환님의 CareRail 스마트 컨트랙트 보안 강화를 위한 **‘온체인 서명 박제(Attestation)’** 및 **‘하드캡 & 타임락 거버넌스’** 설계에 대한 아키텍처 보안 평가와 `near-sdk-js` 기반 프로덕션 레디 구현 코드입니다.

---

### [1] 보안 설계 평가 (장점과 엣지케이스)

1. **장점 (자금 유출 방어 및 부인방지)**: 소유자 키가 탈취되더라도 절대 하드캡(1회 10N / 일 50N)에 의해 즉각적인 대량 탈취(Drain)가 원천 차단되며, 24시간 타임락 큐를 통해 방어자가 키 교체 및 비상 조치를 취할 수 있는 '골든타임'을 확보함과 동시에 NEP-297 이벤트 박제로 온체인 감사 추적성을 극대화합니다.
2. **엣지케이스 (서명 검증 유효성 및 재전송 위험)**: 현재 구현은 서명 문자열을 온체인에 단순 저장(Attest)하는 구조이므로, 체인 상에서 `near.curve25519_verify` 등을 통한 실제 암호학적 검증이 결합되지 않으면 유효하지 않은 서명이 등록될 위험이 있으며, 제안서 간 서명 재전송 공격(Replay Attack) 방지를 위해 `proposal_id`와 체인 ID가 페이로드에 완벽히 바인딩되어야 합니다.
3. **엣지케이스 (타임락 덮어쓰기 및 시간 단위)**: NEAR의 `near.blockTimestamp()`는 나노초(ns) 단위이므로 초 단위 연산 시 오차가 발생하지 않아야 하며, 이미 대기 중인 상향 타임락이 있을 때 악의적/실수 요청으로 덮어쓰거나 즉각 감액 시 펜딩 큐가 의도치 않게 잔존하지 않도록 정합성 초기화 처리가 필수적입니다.

---

### [2] `near-sdk-js` 프로덕션 구현 코드 스니펫

```javascript
import { NearBindgen, call, view, near, assert, LookupMap } from "near-sdk-js";

// ==========================================
// 1. 보안 상수 정의 (절대 하드캡 & 시간 단위)
// ==========================================
// 1 NEAR = 10^24 yoctoNEAR
const ABSOLUTE_MAX_DAILY_LIMIT = BigInt("50000000000000000000000000"); // 절대 일일 최대 50 NEAR
const ABSOLUTE_MAX_PER_TRANSFER = BigInt("10000000000000000000000000"); // 절대 1회 최대 10 NEAR
const TIMELOCK_DURATION_NS = BigInt(86400) * BigInt(1e9); // 24시간 (나노초 단위: 86,400,000,000,000 ns)

@NearBindgen({ requireInit: true })
export class CareRailContract {
  constructor() {
    this.owner_id = "";
    this.max_per_transfer = "5000000000000000000000000"; // 기본 5 NEAR
    this.max_daily_total = "20000000000000000000000000";  // 기본 20 NEAR
    this.owner_threshold = 1;
    this.pending_timelock_update = null; // 타임락 큐
    this.proposals = new LookupMap("p");
  }

  // 내부 헬퍼: 소유자 권한 검증
  internalAssertOwner() {
    assert(
      near.predecessorAccountId() === this.owner_id,
      "CareRail: Caller is not the contract owner"
    );
  }

  // ==========================================
  // [기능 1] 온체인 암호학적 서명 박제 (Attestation)
  // ==========================================
  @call({})
  owner_approve({ proposal_id, owner_public_key, signature_b58 }) {
    this.internalAssertOwner();

    // 1. 제안서 유효성 검증
    const proposal = this.proposals.get(proposal_id);
    assert(proposal !== null, `CareRail: Proposal #${proposal_id} does not exist`);
    assert(!proposal.attestation, `CareRail: Proposal #${proposal_id} already has attestation`);
    assert(proposal.status === "Pending", `CareRail: Proposal is not in Pending status`);

    // 2. 온체인 서명 및 승인 메타데이터 박제
    const current_timestamp_ns = near.blockTimestamp().toString();
    proposal.attestation = {
      owner_public_key: owner_public_key,
      signature: signature_b58,
      approved_at: current_timestamp_ns
    };
    proposal.status = "Approved";
    this.proposals.set(proposal_id, proposal);

    // 3. NEP-297 표준 이벤트 로그 방출 (인덱서 및 실시간 모니터링 추적용)
    const eventPayload = {
      standard: "carerail",
      version: "1.0.0",
      event: "owner_approval_attestation",
      data: [
        {
          proposal_id: proposal_id.toString(),
          public_key: owner_public_key,
          signature: signature_b58
        }
      ]
    };
    near.log(`EVENT_JSON:${JSON.stringify(eventPayload)}`);

    return proposal;
  }

  // ==========================================
  // [기능 2-A] 한도 변경 요청 (상향 시 24시간 타임락, 감액 시 즉시 적용)
  // ==========================================
  @call({})
  request_limit_update({ new_max_per_transfer, new_max_daily_total, new_owner_threshold }) {
    this.internalAssertOwner();

    const reqPerTransfer = BigInt(new_max_per_transfer);
    const reqDailyTotal = BigInt(new_max_daily_total);
    const curPerTransfer = BigInt(this.max_per_transfer);
    const curDailyTotal = BigInt(this.max_daily_total);

    // 1. 절대 하드캡 검증 (절대 규칙: 어떤 경우에도 하드캡 초과 불가)
    assert(
      reqDailyTotal <= ABSOLUTE_MAX_DAILY_LIMIT,
      `CareRail: new_max_daily_total exceeds absolute cap (${ABSOLUTE_MAX_DAILY_LIMIT.toString()} yoctoNEAR)`
    );
    assert(
      reqPerTransfer <= ABSOLUTE_MAX_PER_TRANSFER,
      `CareRail: new_max_per_transfer exceeds absolute cap (${ABSOLUTE_MAX_PER_TRANSFER.toString()} yoctoNEAR)`
    );
    assert(
      reqPerTransfer <= reqDailyTotal,
      "CareRail: Single transfer limit cannot exceed daily limit"
    );

    // 2. 한도 상향(증액) 여부 판별
    const isIncrease = reqPerTransfer > curPerTransfer || reqDailyTotal > curDailyTotal;

    if (isIncrease) {
      // 상향 조정: 24시간(86400초 = 86,400,000,000,000 ns) 타임락 큐에 저장
      const unlock_timestamp = (near.blockTimestamp() + TIMELOCK_DURATION_NS).toString();
      this.pending_timelock_update = {
        new_max_per_transfer: reqPerTransfer.toString(),
        new_max_daily_total: reqDailyTotal.toString(),
        new_owner_threshold: new_owner_threshold !== undefined ? Number(new_owner_threshold) : this.owner_threshold,
        unlock_timestamp: unlock_timestamp
      };

      near.log(
        `[SECURITY TIMELOCK QUEUED] Limit increase requested. Unlocks at blockTimestamp: ${unlock_timestamp}`
      );
      return { status: "QueuedInTimelock", unlock_timestamp };
    } else {
      // 감액 또는 동결 (긴급 방어 조치): 즉시 적용 및 대기 중이던 상향 큐 무효화
      this.max_per_transfer = reqPerTransfer.toString();
      this.max_daily_total = reqDailyTotal.toString();
      if (new_owner_threshold !== undefined) {
        this.owner_threshold = Number(new_owner_threshold);
      }
      this.pending_timelock_update = null; // 악의적 펜딩 요청 제거

      near.log(
        `[SECURITY LIMIT DECREASED] Instant update applied. New transfer: ${this.max_per_transfer}, Daily: ${this.max_daily_total}`
      );
      return { status: "AppliedImmediately" };
    }
  }

  // ==========================================
  // [기능 2-B] 타임락 한도 변경 적용 (24시간 경과 후)
  // ==========================================
  @call({})
  apply_limit_update() {
    this.internalAssertOwner();

    // 1. 대기 중인 타임락 큐 존재 확인
    assert(
      this.pending_timelock_update !== null,
      "CareRail: No pending timelock update found"
    );

    // 2. 24시간(86400초) 경과 여부 확인 (나노초 정밀 비교)
    const current_timestamp = near.blockTimestamp();
    const unlock_timestamp = BigInt(this.pending_timelock_update.unlock_timestamp);

    assert(
      current_timestamp >= unlock_timestamp,
      `CareRail: Timelock has not expired yet. Current: ${current_timestamp.toString()}, Unlocks at: ${unlock_timestamp.toString()}`
    );

    // 3. 상태 적용 및 큐 초기화
    this.max_per_transfer = this.pending_timelock_update.new_max_per_transfer;
    this.max_daily_total = this.pending_timelock_update.new_max_daily_total;
    this.owner_threshold = this.pending_timelock_update.new_owner_threshold;
    this.pending_timelock_update = null;

    near.log(
      `[SECURITY TIMELOCK APPLIED] Limits updated successfully: per_transfer=${this.max_per_transfer}, daily_total=${this.max_daily_total}`
    );

    return {
      status: "Success",
      max_per_transfer: this.max_per_transfer,
      max_daily_total: this.max_daily_total,
      owner_threshold: this.owner_threshold
    };
  }

  // ==========================================
  // 조회용 뷰 메서드
  // ==========================================
  @view({})
  get_security_limits() {
    return {
      max_per_transfer: this.max_per_transfer,
      max_daily_total: this.max_daily_total,
      owner_threshold: this.owner_threshold,
      pending_timelock_update: this.pending_timelock_update,
      absolute_caps: {
        max_daily: ABSOLUTE_MAX_DAILY_LIMIT.toString(),
        max_per_transfer: ABSOLUTE_MAX_PER_TRANSFER.toString()
      }
    };
  }
}
```

---

### [3] 애니의 추가 아키텍처 제언
- **타임락 비상 취소 (`cancel_limit_update`)**: 키 탈취 의심 시 24시간 타임락 기간 동안 소유자가 즉시 큐를 비울 수 있는 명시적 취소 인터페이스를 추가해 두면 방어 탄력성이 한 층 더 높아집니다.
- **오프체인 서명 바인딩**: `signature_b58` 서명 생성 시 `sha256("${contract_id}:${proposal_id}:${amount}:${receiver_id}:${nonce}")` 형식의 표준화된 직렬화 페이로드를 사용해야 교차 컨트랙트 재전송 공격을 완벽히 차단할 수 있습니다.