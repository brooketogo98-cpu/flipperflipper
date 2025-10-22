#!/usr/bin/env python3
"""
Capture screenshot of the premium login page
"""

import asyncio
import os
import base64
from playwright.async_api import async_playwright

async def capture_login_screenshot():
    async with async_playwright() as p:
        # Launch browser in headless mode
        browser = await p.chromium.launch(headless=True)
        
        # Create a new page with desktop viewport
        page = await browser.new_page(viewport={'width': 1920, 'height': 1080})
        
        # Navigate to the login page HTML file
        login_file = f"file://{os.path.abspath('/workspace/web/login.html')}"
        await page.goto(login_file)
        
        # Wait for animations to start
        await page.wait_for_timeout(2000)
        
        # Take screenshot
        screenshot = await page.screenshot(full_page=False)
        
        # Save screenshot
        with open('/workspace/login_screenshot.png', 'wb') as f:
            f.write(screenshot)
        
        print("✅ Screenshot saved as login_screenshot.png")
        
        # Also create a smaller preview version
        await page.set_viewport_size({'width': 1280, 'height': 720})
        await page.wait_for_timeout(500)
        preview = await page.screenshot()
        
        with open('/workspace/login_preview.png', 'wb') as f:
            f.write(preview)
        
        print("✅ Preview saved as login_preview.png")
        
        # Close browser
        await browser.close()
        
        # Display file info
        size = os.path.getsize('/workspace/login_screenshot.png')
        print(f"\n📸 Screenshot captured:")
        print(f"   Size: {size:,} bytes")
        print(f"   Resolution: 1920x1080")
        print(f"   Path: /workspace/login_screenshot.png")

if __name__ == "__main__":
    asyncio.run(capture_login_screenshot())