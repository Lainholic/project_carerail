import asyncio
import os
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path
from playwright.async_api import async_playwright

ROOT = Path(r"C:\AI\project_carerail")
sys.path.insert(0, str(ROOT))
from web.server import ThreadingHTTPServer, CareRailServerHandler

def start_server(port=8099):
    server = ThreadingHTTPServer(("127.0.0.1", port), CareRailServerHandler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server

async def record_full_hd_demo():
    print("[*] Starting CareRail backend server on port 8099...")
    server = start_server(8099)
    await asyncio.sleep(1)

    video_tmp = ROOT / "_work" / "tmp_video_hd"
    if video_tmp.exists():
        shutil.rmtree(video_tmp, ignore_errors=True)
    video_tmp.mkdir(parents=True, exist_ok=True)

    print("[*] Launching Chromium browser at 1920x1080 Full HD...")
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context(
            viewport={"width": 1920, "height": 1080},
            record_video_dir=str(video_tmp),
            record_video_size={"width": 1920, "height": 1080}
        )
        page = await context.new_page()

        # Step 1: Open Dashboard
        print("[1] Navigating to http://127.0.0.1:8099/dashboard...")
        await page.goto("http://127.0.0.1:8099/dashboard", timeout=15000)
        await asyncio.sleep(2.5)

        # Smooth hover over 4 KPI cards
        print("[2] Highlighting Gnosis Safe-style KPI Metrics...")
        await page.mouse.move(300, 150)
        await asyncio.sleep(1.0)
        await page.mouse.move(750, 150)
        await asyncio.sleep(1.0)
        await page.mouse.move(1200, 150)
        await asyncio.sleep(1.0)
        await page.mouse.move(1650, 150)
        await asyncio.sleep(1.2)

        # Step 2: Hover over Waterfall Rules
        print("[3] Highlighting Stripe Radar Waterfall Rule Hierarchy...")
        await page.mouse.move(500, 320)
        await asyncio.sleep(2.0)

        # Step 3: Execute Compliant Micropayment
        print("[4] Clicking 'Execute Compliant Payment' (Real API call)...")
        btn_legit = page.locator("button:has-text('Execute Compliant Payment')")
        await btn_legit.hover()
        await asyncio.sleep(0.8)
        await btn_legit.click()
        await asyncio.sleep(3.5)

        # Step 4: Execute Red-Team Prompt Injection Attack
        print("[5] Clicking 'Execute Red-Team Injection' (Fail-Closed block)...")
        btn_attack = page.locator("button:has-text('Execute Red-Team Injection')")
        await btn_attack.hover()
        await asyncio.sleep(0.8)
        await btn_attack.click()
        await asyncio.sleep(3.5)

        # Step 5: Security Event Inspector examination
        print("[6] Highlighting Cloudflare WAF Security Event Inspector...")
        await page.mouse.move(1500, 720)
        await asyncio.sleep(2.5)

        # Step 6: Open Human-in-the-Loop NEP-413 Authorization Modal
        print("[7] Clicking 'Sign NEP-413' on held transaction...")
        btn_sign = page.locator("button:has-text('Sign NEP-413')").first
        await btn_sign.hover()
        await asyncio.sleep(0.8)
        await btn_sign.click()
        await asyncio.sleep(2.5)

        # Step 7: Confirm Cryptographic Signature
        print("[8] Signing and broadcasting Ed25519 authorization...")
        btn_broadcast = page.locator("button[onclick='confirmSignatureModal()']")
        await btn_broadcast.hover()
        await asyncio.sleep(1.0)
        await btn_broadcast.click()
        await asyncio.sleep(3.5)

        # Step 8: Demonstrate Circuit Breaker Freeze & Resume
        print("[9] Toggling Emergency Circuit Breaker...")
        btn_killswitch = page.locator("#btnKillswitch")
        await btn_killswitch.hover()
        await asyncio.sleep(0.8)
        await btn_killswitch.click()
        await asyncio.sleep(2.0)
        await btn_killswitch.click()
        await asyncio.sleep(2.5)

        await page.close()
        await context.close()
        await browser.close()

    # Locate recorded WebM
    recorded = list(video_tmp.glob("*.webm"))
    if not recorded:
        raise RuntimeError("No WebM recording found in tmp directory!")

    webm_path = recorded[0]
    mp4_out = ROOT / "docs" / "carerail_demo_video.mp4"
    thumb_out = ROOT / "docs" / "carerail_demo_video_thumb.png"
    ffmpeg_exe = r"C:\AI\tools\liveportrait\ffmpeg\ffmpeg.exe"

    print(f"[*] Encoding Full HD 1080p MP4 via ffmpeg: {mp4_out}...")
    cmd = [
        ffmpeg_exe, "-y", "-i", str(webm_path),
        "-c:v", "libx264", "-preset", "medium", "-crf", "18",
        "-pix_fmt", "yuv420p", "-r", "30",
        str(mp4_out)
    ]
    subprocess.run(cmd, check=True)
    print(f"[*] DEMO VIDEO SUCCESSFULLY RECORDED: {mp4_out}")
    print(f"    File Size: {mp4_out.stat().st_size:,} bytes")

    # Extract high-res thumbnail at 12s
    print(f"[*] Extracting video thumbnail: {thumb_out}...")
    cmd_thumb = [
        ffmpeg_exe, "-y", "-ss", "00:00:12", "-i", str(mp4_out),
        "-vframes", "1", "-q:v", "2",
        str(thumb_out)
    ]
    subprocess.run(cmd_thumb, check=True)

    # Cleanup tmp
    shutil.rmtree(video_tmp, ignore_errors=True)
    print("[*] Recording and encoding pipeline complete!")

if __name__ == "__main__":
    asyncio.run(record_full_hd_demo())
