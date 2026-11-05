import asyncio
import os
import sys
import threading
import time
from pathlib import Path
from playwright.async_api import async_playwright

# Add project root
ROOT_DIR = Path(r"C:\AI\project_carerail")
sys.path.insert(0, str(ROOT_DIR))

from web.server import ThreadingHTTPServer, CareRailServerHandler

SCREENSHOT_PATH = ROOT_DIR / "docs" / "carerail_dashboard_demo.png"

def start_server_in_thread(port=8095):
    server = ThreadingHTTPServer(("127.0.0.1", port), CareRailServerHandler)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    return server

async def run_demo():
    print("[1] Starting internal CareRail web server on port 8095...")
    start_server_in_thread(8095)
    await asyncio.sleep(1)

    print("[2] Connecting to Brave browser via CDP on port 9222...")
    async with async_playwright() as p:
        browser = await p.chromium.connect_over_cdp("http://127.0.0.1:9222")
        context = browser.contexts[0]
        page = await context.new_page()

        try:
            print("[3] Navigating to http://127.0.0.1:8095...")
            await page.goto("http://127.0.0.1:8095", timeout=10000)
            await asyncio.sleep(1)

            print("[4] Scenario 1: Executing Legitimate Care Booking...")
            await page.click("button:has-text('Scenario 1: Legitimate Care Booking')")
            await asyncio.sleep(1)

            print("[5] Scenario 2: Executing Prompt Injection Attack...")
            await page.click("button:has-text('Scenario 2: Prompt Injection Attack')")
            await asyncio.sleep(1)

            print("[6] Scenario 3: Executing High-Value Equipment Proposal...")
            await page.click("button:has-text('Scenario 3: High-Value Equipment')")
            await asyncio.sleep(1)

            print("[7] Approving held high-value transaction via WebAuthn simulation...")
            await page.click("button:has-text('Sign & Approve with WebAuthn')")
            await asyncio.sleep(1.5)

            print(f"[8] Taking full-page screenshot to {SCREENSHOT_PATH}...")
            await page.screenshot(path=str(SCREENSHOT_PATH), full_page=True)
            print("SUCCESSFULLY_CAPTURED_EVIDENCE")
        finally:
            await page.close()

if __name__ == "__main__":
    asyncio.run(run_demo())
