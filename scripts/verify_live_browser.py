import asyncio
import threading
import time
import sys
from pathlib import Path
from playwright.async_api import async_playwright

sys.path.insert(0, r"C:\AI\project_carerail")
from web.server import ThreadingHTTPServer, CareRailServerHandler

def start_server():
    server = ThreadingHTTPServer(("127.0.0.1", 8098), CareRailServerHandler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server

async def verify():
    start_server()
    await asyncio.sleep(1)

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()

        console_logs = []
        page.on("console", lambda msg: console_logs.append(f"[{msg.type}] {msg.text}"))
        page.on("pageerror", lambda err: console_logs.append(f"[EXCEPTION] {err}"))

        print("[1] Loading http://127.0.0.1:8098/dashboard...")
        resp = await page.goto("http://127.0.0.1:8098/dashboard", timeout=10000)
        print(f"    HTTP Status: {resp.status}")
        await asyncio.sleep(2)

        print("[2] Checking Dynamic KPI DOM Values...")
        budget_text = await page.inner_text("#valDailyBudget")
        boundaries_text = await page.inner_text("#valBoundaries")
        print(f"    valDailyBudget: {budget_text}")
        print(f"    valBoundaries: {boundaries_text}")

        print("[3] Testing 'Execute Compliant Payment' API interaction...")
        await page.click("button:has-text('Execute Compliant Payment')")
        await asyncio.sleep(2)

        print("[4] Testing 'Execute Red-Team Injection' API interaction...")
        await page.click("button:has-text('Execute Red-Team Injection')")
        await asyncio.sleep(2)

        print("[5] Inspecting Inspector Card contents...")
        badge = await page.inner_text("#inspectStatusBadge")
        trace = await page.inner_text("#inspectRuleTrace")
        payload = await page.inner_text("#inspectPayload")
        print(f"    Status Badge: {badge}")
        print(f"    Rule Trace: {trace.replace(chr(10), ' | ')}")
        print(f"    Payload Preview: {payload[:80]}...")

        errors = [log for log in console_logs if "[error]" in log or "[EXCEPTION]" in log]
        print(f"[6] Total Console Errors: {len(errors)}")
        if errors:
            for err in errors:
                print(f"    ERROR: {err}")
        else:
            print("    CLEAN: 0 Console Errors detected in browser runtime.")

        await browser.close()

if __name__ == "__main__":
    asyncio.run(verify())
