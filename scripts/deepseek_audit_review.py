import os
import json
import urllib.request
from pathlib import Path
from dotenv import load_dotenv

def run_deepseek_audit():
    load_dotenv('C:/AI/project_nebius_agent/.env')
    api_key = os.getenv('NEBIUS_API_KEY')
    if not api_key:
        raise ValueError("NEBIUS_API_KEY not found in C:/AI/project_nebius_agent/.env")

    root = Path(r"C:\AI\project_carerail")
    
    # Read relevant files to provide context
    html_code = (root / "dashboard" / "index.html").read_text(encoding="utf-8")
    server_code = (root / "web" / "server.py").read_text(encoding="utf-8")
    engine_code = (root / "policy" / "engine.py").read_text(encoding="utf-8")
    rules_json = (root / "policy" / "rules.json").read_text(encoding="utf-8")
    
    system_prompt = (
        "당신은 실리콘밸리 웹3 인프라 및 AI 에이전트 보안 분야의 수석 감사관(DeepSeek)입니다.\n"
        "NEAR HACKATHON 2026 [06/SEC] AI Security & Defense 트랙 출품작인 'CareRail'의 아키텍처와 최신 전면 개편 UI/UX에 대해 엄밀하고 냉정한 적대적 감사를 수행하세요.\n"
        "원칙:\n"
        "1. 허위나 과장, 예의 차리기식 칭찬을 엄단하고, 철저히 공학적 사실과 보안 경계에 기반하여 냉정하게 비판 및 평가할 것.\n"
        "2. 취소선(~~...~~)은 절대 사용하지 말 것.\n"
        "3. 한국어로 정연하고 전문적으로 작성할 것."
    )

    user_prompt = f"""[CareRail 프로젝트 개요 및 최신 전면 개편 현황]
프로젝트: CareRail — Autonomous Payment Firewall for AI Agents on NEAR
트랙: [06/SEC] AI Security & Defense
컨트랙트: carerail-274071e4.testnet (WASM 557KB, QuickJS 엔진 배포 완료)
상태: 12/12 자동 검증 스위트 100% 통과 (불변식, 암호학, 온체인 RPC, 머클 트리, 동시성)

[환님(Director)의 핵심 요구 및 최근 개편 사항]
1. 기존 AI 템플릿의 고질적인 클리셰 박멸:
   - 칙칙한 검정/네이비 배경 및 네온 초록 펄스 글로우를 전면 삭제하고 Stripe/Mercury 스타일의 소프트 슬레이트(#f8fafc) & 퓨어 화이트(#ffffff)로 전면 개편.
   - 색상은 Chrome(틀)에 일절 쓰지 않고, 오직 판정 뱃지(BLOCK, HELD, SETTLED)에만 1% 미만으로 한정.
2. 가짜 눈속임 터미널 완전 제거:
   - 클라이언트 자바스크립트의 log() 문자열 출력용 가짜 검은색 콘솔 박스를 100% 영구 삭제.
   - Cloudflare WAF / Stripe Radar 스타일의 '실물 Security Event Inspector'로 교체하여 표의 거래 클릭 시 실제 파이썬 백엔드(POST /api/scenario/run) 및 온체인 RPC 응답, RFC 6962 32바이트 머클 해시, 원본 JSON 페이로드를 바인딩.
3. Stripe Radar식 워터폴 규칙 스택(Rule 1 주입 차단 ➔ Rule 2 화이트리스트 ➔ Rule 3 한도 ➔ Rule 4 인간 게이트)과 Gnosis Safe식 24시간 한도 게이지 바 탑재.

[제출 코드 핵심 발췌]
--- dashboard/index.html (발췌) ---
{html_code[:4000]}
... [중략] ...
{html_code[12000:18000]}

--- web/server.py (발췌) ---
{server_code[:3500]}

[질의 사항]
1. UI/UX 및 가짜 터미널 제거의 공학적 완성도 평가:
   - 기존의 흔해빠진 AI 대시보드 클리셰와 가짜 터미널이 상용 보안 제품(Stripe Radar, Cloudflare WAF, Safe) 표준에 부합하게 실질적으로 개선되었는가? 잔존하는 결함이나 사각지대는 없는가?
2. AI 에이전트 자율 결제 방화벽 관점의 보안 경계 검증:
   - LLM 프롬프트 주입 방어, 화이트리스트, 속도 제한(120 RPM), NEP-413 Ed25519 인간 승인 게이트, 머클 감사 추적(RFC 6962)의 설계가 온체인 자금 탈취를 방지하기에 충분히 견고한가?
3. 해커톤 심사위원(Claude Code, Codex AI, NEAR 재단) 관점의 총평 및 최종 점수(100점 만점):
   - 심사위원들이 봤을 때 '기술적 실체가 있는 진짜 보안 인프라 프로덕트'로 인정받을 수 있는가? 보완할 점이 있다면 무엇인가?
"""

    payload = {
        "model": "deepseek-ai/DeepSeek-V4.1-Flash-1017",
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ],
        "temperature": 0.3,
        "max_tokens": 3500
    }

    print("[*] Dispatching review request to DeepSeek-V4.1-Flash-1017 on Nebius...")
    req = urllib.request.Request(
        "https://api.tokenfactory.nebius.com/v1/chat/completions",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}"
        }
    )

    with urllib.request.urlopen(req, timeout=60) as resp:
        res_data = json.loads(resp.read().decode("utf-8"))
        msg = res_data["choices"][0]["message"]
        text = msg.get("content") or msg.get("reasoning_content") or json.dumps(msg, ensure_ascii=False)
        
        report_path = root / "_reports" / "deepseek_audit_round5.md"
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(text, encoding="utf-8")
        print(f"[*] DeepSeek review successfully saved to {report_path} (length: {len(text)} bytes)")
        return text

if __name__ == "__main__":
    run_deepseek_audit()
