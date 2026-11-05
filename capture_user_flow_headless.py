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

SCREENSHOT_PATH = ROOT_DIR / "docs" / "carerail_user_journey_demo.png"

def start_server_in_thread(port=8097):
    server = ThreadingHTTPServer(("127.0.0.1", port), CareRailServerHandler)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    return server

async def run_user_journey():
    print("[1] Starting CareRail user showcase server on port 8097...")
    start_server_in_thread(8097)
    await asyncio.sleep(1)

    print("[2] Launching 100% Headless browser...")
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context(viewport={"width": 1280, "height": 920})
        page = await context.new_page()

        try:
            print("[3] Navigating to http://127.0.0.1:8097...")
            await page.goto("http://127.0.0.1:8097", timeout=10000)
            await asyncio.sleep(1)

            print("[4] Step 1: User requests physiotherapy booking (0.05 NEAR)...")
            await page.click("button:has-text('소액 예약')")
            print("    Waiting for live on-chain confirmation (4s)...")
            await asyncio.sleep(4)

            print("[5] Step 2: User requests booking based on web review (Malicious Injection)...")
            await page.click("button:has-text('해커 함정')")
            await asyncio.sleep(2)

            print("[6] Step 3: User requests high-value equipment purchase (2.5 NEAR)...")
            await page.click("button:has-text('고액 비품')")
            await asyncio.sleep(2)

            print("[7] Step 4: User clicks biometric owner approval button...")
            approve_btn = page.locator("button.btn-approve")
            if await approve_btn.is_visible():
                await approve_btn.click()
                print("    Owner approval clicked! Waiting for on-chain broadcast (4s)...")
                await asyncio.sleep(4)
            else:
                print("    Approval button not visible, skipping...")

            print(f"[8] Capturing evidence screenshot to {SCREENSHOT_PATH}...")
            await page.screenshot(path=str(SCREENSHOT_PATH), full_page=True)
            print("USER_JOURNEY_CAPTURE_SUCCESS")
        finally:
            await browser.close()

if __name__ == "__main__":
    asyncio.run(run_user_journey())
