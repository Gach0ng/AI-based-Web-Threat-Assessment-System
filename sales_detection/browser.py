#!/usr/bin/env python3
"""Browser utilities for fetching pages"""
import asyncio
from typing import Optional
from playwright.async_api import async_playwright


async def _fetch_page_async(url: str, timeout: int = 30000) -> str:
    """Fetch page content asynchronously"""
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context(
            viewport={"width": 1920, "height": 1080},
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        )
        page = await context.new_page()

        try:
            await page.goto(url, wait_until='networkidle', timeout=timeout)
            await page.wait_for_timeout(1000)
            content = await page.content()
        finally:
            await browser.close()

        return content


def fetch_page(url: str, timeout: int = 30000) -> str:
    """Fetch page content synchronously"""
    return asyncio.run(_fetch_page_async(url, timeout))