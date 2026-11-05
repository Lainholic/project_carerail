import asyncio
import os
import shutil
import subprocess
from pathlib import Path
from playwright.async_api import async_playwright

async def record_demo():
    root = Path(r"C:\AI\project_carerail")
    video_tmp = root / "_work" / "tmp_video"
    video_tmp.mkdir(parents=True, exist_ok=True)
    html_path = root / "dashboard" / "index.html"
    
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context(
            viewport={"width": 1280, "height": 720},
            record_video_dir=str(video_tmp),
            record_video_size={"width": 1280, "height": 720}
        )
        page = await context.new_page()
        
        # 1. Load Dashboard
        print("[1] Navigating to dashboard...")
        await page.goto(f"file:///{html_path.as_posix()}")
        await asyncio.sleep(2)
        
        # 2. Trigger Legitimate Payment
        print("[2] Clicking Legitimate Payment...")
        await page.click("button:has-text('Execute Compliant Payment')")
        await asyncio.sleep(2.5)
        
        # 3. Trigger Red-Team Injection Attack
        print("[3] Clicking Red-Team Injection Attack...")
        await page.click("button:has-text('Execute Red-Team Injection')")
        await asyncio.sleep(2.5)
        
        # 4. Open NEP-413 Approval Modal
        print("[4] Clicking Sign NEP-413...")
        await page.click("button:has-text('Sign NEP-413')")
        await asyncio.sleep(2)
        
        # 5. Confirm Signature
        print("[5] Confirming Signature...")
        await page.click("button:has-text('Sign & Broadcast')")
        await asyncio.sleep(2.5)
        
        # 6. Test Circuit Breaker Toggle
        print("[6] Toggling Circuit Breaker...")
        await page.click("#btnKillswitch")
        await asyncio.sleep(1.5)
        await page.click("#btnKillswitch")
        await asyncio.sleep(2)
        
        await page.close()
        await context.close()
        await browser.close()
        
    # Find recorded video
    recorded = list(video_tmp.glob("*.webm"))
    if recorded:
        webm_file = recorded[0]
        mp4_out = root / "docs" / "carerail_demo_video.mp4"
        ffmpeg_exe = r"C:\AI\tools\liveportrait\ffmpeg\ffmpeg.exe"
        print(f"Converting {webm_file} to {mp4_out} via ffmpeg...")
        cmd = [
            ffmpeg_exe, "-y", "-i", str(webm_file),
            "-c:v", "libx264", "-pix_fmt", "yuv420p", "-r", "30", str(mp4_out)
        ]
        subprocess.run(cmd, check=True)
        print("Successfully converted demo video to MP4!")
        # Clean tmp
        shutil.rmtree(video_tmp, ignore_errors=True)

if __name__ == "__main__":
    asyncio.run(record_demo())
