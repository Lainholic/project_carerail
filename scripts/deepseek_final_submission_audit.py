import os
import json
import urllib.request
from pathlib import Path
from dotenv import load_dotenv

def run_deepseek_final_audit():
    load_dotenv('C:/AI/project_nebius_agent/.env')
    api_key = os.getenv('NEBIUS_API_KEY')
    if not api_key:
        raise ValueError("NEBIUS_API_KEY not found in C:/AI/project_nebius_agent/.env")

    root = Path(r"C:\AI\project_carerail")
    
    readme = (root / "README.md").read_text(encoding="utf-8")
    hackathon_md = (root / "HACKATHON.md").read_text(encoding="utf-8")
    receipt = (root / "SUBMISSION_RECEIPT.json").read_text(encoding="utf-8")
    verify_script = (root / "verify_all.py").read_text(encoding="utf-8")
    
    system_prompt = (
        "당신은 실리콘밸리 웹3 해커톤 수석 기술 심사위원(DeepSeek)입니다.\n"
        "방금 NEAR HACKATHON 2026 [06/SEC] AI Security & Defense 트랙에 공식 최종 제출(201 Created)을 완료한 'CareRail' 프로젝트에 대해 '혹시 빠뜨리거나 잊은 것이 없는지' 전수 종합 검수를 수행하세요.\n"
        "원칙:\n"
        "1. 허위나 과장, 예의 차리기식 칭찬을 엄단하고, 심사 탈락 요인이나 사각지대를 냉정하고 날카롭게 적대적으로 색출할 것.\n"
        "2. 취소선(~~...~~, <del>, <s>)은 어떤 이유로든 절대 사용하지 말 것.\n"
        "3. 한국어로 정연하고 전문적인 공학 보고서 형식으로 작성할 것."
    )

    user_prompt = f"""[NEAR HACKATHON 2026 CareRail 최종 제출 현황 및 실물 데이터]

1. 공식 제출 영수증 (SUBMISSION_RECEIPT.json):
{receipt}

2. 해커톤 규정 요약 (HACKATHON.md 주요 조항):
{hackathon_md[:2500]}

3. 프로젝트 공개 README.md (전체):
{readme}

4. 자동 검증 진입점 (verify_all.py 발췌):
{verify_script[:2000]}

5. 현재 배포 및 온체인 실물 현황:
- 공개 GitHub: https://github.com/Lainholic/project_carerail (master 브랜치 정상 푸시 완료)
- 공식 X 데모 포스트: https://x.com/LainHolic/status/2118314930608930992 (1080p 37초 비디오 포함)
- 온체인 컨트랙트: carerail-274071e4.testnet (WASM 557KB 배포 완료)
- 상금 수령 계정: synapsecreate.near
- 자동화 테스트: verify_all.py 실행 시 12/12 스위트 100% PASS (약 15초 소요)

[검수 요청 사항]
1. 해커톤 규격 및 필수 제출 요건 대조 검수:
   - HACKATHON.md 및 심사 가이드라인 기준, 혹시 누락되거나 미비한 필수 파일/항목/라이선스가 있는가?
2. 1차 AI 심사관 (Claude Code & Codex) 자동 검증 대비:
   - 심사 AI가 repo를 clone하여 README의 지침대로 `python verify_all.py`를 실행할 때 발생할 수 있는 의존성 결함(Node.js, near-api-js, Python 패키지 등)이나 재현성(Reproducibility) 병목이 있는가?
3. README 및 기술 문서의 적정성:
   - 과대 포장이나 오해를 부를 만한 표현이 남아 있는가?
   - 심사위원이 직접 온체인 영수증이나 대시보드를 검증할 때 걸릴 만한 점은 무엇인가?
4. 종합 판정 및 최종 체크리스트:
   - 잊은 것이 있는가? 있다면 즉시 보완해야 할 우선순위 P0, P1 과제는 무엇인가?
"""

    payload = {
        "model": "deepseek-ai/DeepSeek-V4.1-Flash-1017",
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ],
        "temperature": 0.2,
        "max_tokens": 3500
    }

    print("[*] Dispatching final submission audit to DeepSeek-V4.1-Flash-1017...")
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
        
        report_path = root / "_reports" / "deepseek_final_submission_audit.md"
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(text, encoding="utf-8")
        print(f"[*] DeepSeek final audit saved to {report_path} (length: {len(text)} bytes)")
        return text

if __name__ == "__main__":
    run_deepseek_final_audit()
