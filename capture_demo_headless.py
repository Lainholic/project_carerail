import asyncio
import os
import sys
import threading
import time
from pathlib import Path
from playwright.async_api import async_playwright

ROOT_DIR = Path(r"C:\AI\project_carerail")
sys.path.insert(0, str(ROOT_DIR))

from web.server import ThreadingHTTPServer, CareRailServerHandler

SCREENSHOT_PATH = ROOT_DIR / "docs" / "carerail_dashboard_live_onchain.png"

def start_server_in_thread(port=8096):
    server = ThreadingHTTPServer(("127.0.0.1", port), CareRailServerHandler)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    return server

async def run_headless_demo():
    print("[1] Starting internal CareRail web server on port 8096...")
    start_server_in_thread(8096)
    await asyncio.sleep(1)

    print("[2] Launching 100% Headless browser (NO GUI, completely background)...")
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context(viewport={"width": 1280, "height": 900})
        page = await context.new_page()

        try:
            print("[3] Navigating to http://127.0.0.1:8096...")
            await page.goto("http://127.0.0.1:8096", timeout=10000)
            await asyncio.sleep(1)

            print("[4] Scenario 1: Triggering Live On-Chain Care Booking...")
            await page.click("button:has-text('Scenario 1: Legitimate Care Booking')")
            # Wait for live on-chain NEAR settlement confirmation
            print("    Waiting for NEAR blockchain finality (approx 4s)...")
            await asyncio.sleep(4)

            print("[5] Scenario 2: Triggering Prompt Injection Drainage Attack...")
            await page.click("button:has-text('Scenario 2: Prompt Injection Attack')")
            await asyncio.sleep(1)

            print("[6] Scenario 3: Triggering High-Value Equipment Escalation...")
            await page.click("button:has-text('Scenario 3: High-Value Equipment')")
            await asyncio.sleep(1)

            print("[7] Approving held proposal via simulated WebAuthn authorization...")
            await page.click("button:has-text('Sign & Approve with WebAuthn')")
            print("    Waiting for live on-chain approval broadcast (approx 4s)...")
            await asyncio.sleep(4)

            print(f"[8] Capturing evidence screenshot to {SCREENSHOT_PATH}...")
            await page.screenshot(path=str(SCREENSHOT_PATH), full_page=True)
            print("SUCCESSFULLY_CAPTURED_HEADLESS_EVIDENCE")
        finally:
            await browser.close()

if __name__ == "__main__":
    asyncio.run(run_headless_demo())
