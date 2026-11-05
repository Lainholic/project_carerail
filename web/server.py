"""CareRail Interactive Web Showcase Server
Serves the monitoring dashboard and handles real-time scenario evaluations.
"""

from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import sys
import urllib.parse

# Ensure project root is in path
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from policy.engine import CareRailEngine, PolicyRules, ProposalState
from agent.service_agent import UntrustedCareAgent
from agent.llm_agent import AutonomousCareAgent
from near_rail.client import NearRailClient

RULES_PATH = os.path.join(ROOT_DIR, "policy", "rules.json")
ENV_FILE = os.path.join(ROOT_DIR, ".env")
def get_env_account_id():
    if os.path.exists(ENV_FILE):
        with open(ENV_FILE, "r", encoding="utf-8") as f:
            for line in f:
                if line.startswith("CARERAIL_TESTNET_ACCOUNT_ID="):
                    return line.split("=", 1)[1].strip()
    return "carerail-vault.testnet"

SENDER_ACCOUNT_ID = get_env_account_id()
policy_rules = PolicyRules.load_from_json(RULES_PATH)
engine = CareRailEngine(policy_rules)
agent = UntrustedCareAgent()
llm_agent = AutonomousCareAgent("carerail-live-agent")
near_client = NearRailClient()


class CareRailServerHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        web_dir = os.path.join(ROOT_DIR, "web")
        super().__init__(*args, directory=web_dir, **kwargs)

    def _send_json(self, data: dict, status: int = 200):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self._send_json({"ok": True})

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path in ["/dashboard", "/dashboard/", "/dashboard/index.html"]:
            dash_path = os.path.join(ROOT_DIR, "dashboard", "index.html")
            if os.path.exists(dash_path):
                with open(dash_path, "rb") as f:
                    content = f.read()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(content)))
                self.end_headers()
                self.wfile.write(content)
                return

        if parsed.path == "/api/status":
            rules_data = {
                "allowed_recipients": engine.rules.allowed_recipients,
                "max_per_transfer_near": engine.rules.max_per_transfer_near,
                "max_daily_total_near": engine.rules.max_daily_total_near,
                "owner_approval_threshold_near": engine.rules.owner_approval_threshold_near,
                "today_spent_near": engine.get_today_spent(),
                "blocked_keywords": engine.rules.blocked_memo_keywords,
            }
            proposals_list = [
                {
                    "proposal_id": p.proposal_id,
                    "agent_id": p.agent_id,
                    "recipient": p.recipient,
                    "amount_near": p.amount_near,
                    "intent_memo": p.intent_memo,
                    "state": p.state.value,
                    "rejection_reason": p.rejection_reason,
                    "tx_hash": p.tx_hash,
                    "created_at": p.created_at,
                }
                for p in engine.proposals.values()
            ]
            self._send_json({"rules": rules_data, "proposals": proposals_list})
            return

        super().do_GET()

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        content_len = int(self.headers.get("Content-Length", 0))
        body = {}
        if content_len > 0:
            raw = self.rfile.read(content_len).decode("utf-8")
            try:
                body = json.loads(raw)
            except Exception:
                body = {}

        if parsed.path == "/api/chat":
            user_msg = body.get("message", "")
            web_context = body.get("web_context", "")

            # 1. Agent processes user natural language
            prop = llm_agent.process_instruction(user_msg, untrusted_web_context=web_context)

            # 2. Policy engine evaluates proposal
            state, reason = engine.evaluate_proposal(prop)
            result = {
                "proposal_id": prop.proposal_id,
                "recipient": prop.recipient,
                "amount_near": prop.amount_near,
                "intent_memo": prop.intent_memo,
                "state": state.value,
                "rejection_reason": reason,
                "proposal_hash": prop.compute_hash(),
                "created_at": getattr(prop, 'created_at', None),
            }

            if state == ProposalState.APPROVED:
                tx_res = near_client.submit_settlement(
                    sender_account=SENDER_ACCOUNT_ID,
                    recipient_account=prop.recipient,
                    amount_near=prop.amount_near,
                    proposal_hash=prop.compute_hash(),
                    dry_run=False,
                )
                tx_hash = tx_res.get("transaction_hash")
                if tx_res.get("success") and tx_hash:
                    engine.commit_spend(prop.proposal_id, tx_hash)
                    result["tx"] = tx_res
                    result["state"] = ProposalState.CONFIRMED.value
                    result["bot_response"] = f"예약 결제가 성공적으로 완료되었습니다 ({prop.amount_near} NEAR). 온체인 트랜잭션이 확정되었습니다."
                else:
                    result["state"] = ProposalState.REJECTED.value
                    result["bot_response"] = f"온체인 브로드캐스트 실패: {tx_res.get('error', 'Unknown error')}"
            elif state == ProposalState.AWAITING_OWNER_APPROVAL:
                result["bot_response"] = f"요청 금액({prop.amount_near} NEAR)이 자율 한도(2.0 NEAR)를 초과하여 소유자 승인 대기 중입니다. 지문/서명 승인을 진행해주세요."
            else:
                result["bot_response"] = f"[보안 경고] 비인가 결제 시도가 감지되어 CareRail 방화벽이 차단했습니다! (사유: {reason})"

            self._send_json(result)
            return

        if parsed.path == "/api/scenario/run":
            scenario_type = body.get("type", "normal")
            if scenario_type == "normal":
                prop = agent.propose_legitimate_care_booking()
            elif scenario_type == "attack":
                prop = agent.propose_injected_drainage_attack()
            elif scenario_type == "high_value":
                prop = agent.propose_high_value_equipment()
            else:
                self._send_json({"error": "Unknown scenario"}, status=400)
                return

            state, reason = engine.evaluate_proposal(prop)
            result = {
                "proposal_id": prop.proposal_id,
                "recipient": prop.recipient,
                "amount_near": prop.amount_near,
                "intent_memo": prop.intent_memo,
                "state": state.value,
                "rejection_reason": reason,
                "proposal_hash": prop.compute_hash(),
                "created_at": getattr(prop, 'created_at', None),
            }

            # If instantly approved, execute settlement
            if state == ProposalState.APPROVED:
                tx_res = near_client.submit_settlement(
                    sender_account=SENDER_ACCOUNT_ID,
                    recipient_account=prop.recipient,
                    amount_near=prop.amount_near,
                    proposal_hash=prop.compute_hash(),
                    dry_run=False,
                )
                tx_hash = tx_res.get("transaction_hash")
                if tx_res.get("success") and tx_hash:
                    engine.commit_spend(prop.proposal_id, tx_hash)
                    result["tx"] = tx_res
                    result["state"] = ProposalState.CONFIRMED.value
                else:
                    result["state"] = ProposalState.REJECTED.value
                    result["reason"] = f"BROADCAST_FAILED: {tx_res.get('error')}"

            self._send_json(result)
            return

        if parsed.path == "/api/proposal/approve":
            proposal_id = body.get("proposal_id", "")
            owner_pk = engine.rules.owner_public_key or "ed25519:6E8sCci9badyRkXb3JoRtubqwUMoVMMNaY2LTCSt6Z11"
            sig_b58 = body.get("signature") or "simulated-sig-ed25519-valid"
            ok, msg = engine.owner_approve(proposal_id, owner_pk, sig_b58)
            if not ok:
                self._send_json({"error": msg}, status=400)
                return

            prop = engine.proposals[proposal_id]
            tx_res = near_client.submit_settlement(
                sender_account=SENDER_ACCOUNT_ID,
                recipient_account=prop.recipient,
                amount_near=prop.amount_near,
                proposal_hash=prop.compute_hash(),
                dry_run=False,
            )
            tx_hash = tx_res.get("transaction_hash")
            if tx_res.get("success") and tx_hash:
                engine.commit_spend(proposal_id, tx_hash)
                self._send_json({"success": True, "state": "CONFIRMED", "tx": tx_res})
            else:
                self._send_json({"success": False, "state": "BROADCAST_FAILED", "error": tx_res.get("error")}, status=500)
            return

        self._send_json({"error": "Not Found"}, status=404)


def run_server(port: int = 8095):
    server = ThreadingHTTPServer(("0.0.0.0", port), CareRailServerHandler)
    print(f"CareRail Server running on http://0.0.0.0:{port}")
    server.serve_forever()


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8095
    run_server(port)
