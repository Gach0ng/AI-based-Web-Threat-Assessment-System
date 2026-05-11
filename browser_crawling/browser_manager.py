"""Browser manager for dynamic page rendering"""
import asyncio
from dataclasses import dataclass
from typing import Optional, List, Dict, Any
from playwright.async_api import async_playwright, Browser, Page, BrowserContext
from .config import Config


@dataclass
class PageResult:
    """Result of page rendering"""
    html: str
    links: List[Dict[str, str]]
    title: str
    status: int


@dataclass
class BrowserResult:
    """Browser rendering result with JS enabled and disabled"""
    js_enabled: Optional[PageResult]
    js_disabled: Optional[PageResult]
    success: bool
    error: Optional[str] = None


class BrowserManager:
    """Manages browser instances for page rendering"""

    def __init__(self, config: Config = None):
        self.config = config or Config()
        self.browser: Optional[Browser] = None
        self.context: Optional[BrowserContext] = None
        self.playwright = None

    async def __aenter__(self):
        self.playwright = await async_playwright().start()
        self.browser = await self.playwright.chromium.launch(
            headless=self.config.headless
        )
        self.context = await self.browser.new_context(
            viewport={"width": self.config.viewport_width, "height": self.config.viewport_height},
            user_agent=self.config.user_agent
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.context:
            await self.context.close()
        if self.browser:
            await self.browser.close()
        if self.playwright:
            await self.playwright.stop()

    async def analyze(self, url: str) -> BrowserResult:
        """Analyze URL with both JS enabled and disabled"""
        # Render with JS disabled first
        js_disabled_result = await self._render_page(url, java_script_enabled=False)

        # Render with JS enabled
        js_enabled_result = await self._render_page(url, java_script_enabled=True)

        return BrowserResult(
            js_enabled=js_enabled_result,
            js_disabled=js_disabled_result,
            success=js_enabled_result is not None or js_disabled_result is not None
        )

    async def _render_page(self, url: str, java_script_enabled: bool) -> Optional[PageResult]:
        """Render a single page"""
        retries = self.config.retry_times
        last_error = None

        for attempt in range(retries):
            page = None
            try:
                page = await self.context.new_page()

                # Set extra HTTP headers to reduce bot detection
                await page.set_extra_http_headers({
                    'Accept-Language': 'zh-CN,zh;q=0.9',
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                })

                await page.goto(url, wait_until='networkidle', timeout=self.config.timeout_ms)

                # Disable JavaScript if needed
                if not java_script_enabled:
                    await page.context.route('**/*.js', lambda route: route.abort())

                # Wait for dynamic content to fully render (AJAX, SPA, etc.)
                await page.wait_for_timeout(8000)

                # Use evaluate to extract full DOM as string (captures dynamically modified DOM)
                html = await page.evaluate('document.documentElement.outerHTML')
                links = await self._extract_links(page)
                title = await page.title()
                status = 200  # Simplified

                await page.close()
                return PageResult(html=html, links=links, title=title, status=status)

            except Exception as e:
                last_error = str(e)
                if page:
                    try:
                        await page.close()
                    except:
                        pass

        return None

    async def _extract_links(self, page: Page) -> List[Dict[str, str]]:
        """Extract links from page"""
        links = []
        try:
            link_elements = await page.query_selector_all('a[href]')
            for elem in link_elements:
                href = await elem.get_attribute('href')
                text = await elem.text_content() or ""
                if href:
                    links.append({
                        'href': href,
                        'text': text.strip()[:200]
                    })
        except:
            pass
        return links


async def process_with_browser(url: str, brand_owner: str = "", **kwargs) -> Dict[str, Any]:
    """
    使用无头浏览器获取页面数据

    Args:
        url: 待检测URL
        brand_owner: 保护的品牌主体
        **kwargs: 其他参数

    Returns:
        包含页面分析结果的字典
    """
    config = Config()
    async with BrowserManager(config) as bm:
        browser_result = await bm.analyze(url)

    from .diff_analyzer import DiffAnalyzer
    from .sensitive_element_scanner import SensitiveElementScanner

    diff_analyzer = DiffAnalyzer()
    sensitive_scanner = SensitiveElementScanner()

    if browser_result.js_enabled:
        js_enabled_html = browser_result.js_enabled.html
    else:
        js_enabled_html = ""

    if browser_result.js_disabled:
        js_disabled_html = browser_result.js_disabled.html
    else:
        js_disabled_html = ""

    diff = diff_analyzer.analyze(browser_result.js_enabled, browser_result.js_disabled)

    sensitive_report = sensitive_scanner.scan(js_enabled_html if js_enabled_html else js_disabled_html)

    return {
        'url': url,
        'brand_owner': brand_owner,
        'browser_result': browser_result,
        'diff': diff,
        'sensitive_report': sensitive_report,
    }
