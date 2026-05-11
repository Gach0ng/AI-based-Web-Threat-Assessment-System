#!/usr/bin/env python3
"""
按需交互核验脚本
由 Skill 调用，仅在以下2种场景触发：
1. 剪枝后候选分类得分接近（分差 < 10）
2. 钓鱼欺诈（含登录框）进入 Top5 候选

执行2步核验：
1. 静态解析：修复页面源码解析，提取真实表单、跳转链接
2. 动态检测（Playwright）：定位登录框/表单，模拟点击/hover，捕获动态生成链接
"""

import asyncio
import json
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse, urljoin

try:
    from playwright.async_api import async_playwright, Page, Locator
except ImportError:
    print("请安装 playwright: pip install playwright && playwright install chromium")
    sys.exit(1)


# 高危后缀列表
HIGH_RISK_SUFFIXES = {
    '.xyz', '.top', '.cyou', '.icu', '.buzz', '.win', '.racing',
    '.online', '.site', '.tech', '.fun', '.link', '.click', '.loan',
    '.party', '.stream', '.download', '.bid', '.review', '.work',
    '.trade', '.accountant', '.cricket', '.date', '.faith', '.tk', '.ml', '.ga', '.cf', '.gq'
}

# 白名单域名（可配置）
WHITELIST_DOMAINS = {
    'baidu.com', 'qq.com', '163.com', 'sina.com', 'sohu.com',
    'alipay.com', 'taobao.com', 'jd.com', 'tmall.com',
    'weibo.com', 'bilibili.com', 'douyin.com'
}


class PlaywrightVerifier:
    """交互核验器"""

    def __init__(self, timeout: int = 15000):
        self.timeout = timeout
        self.results = {}

    async def verify(self, url: str, interaction_type: str = "auto") -> Dict:
        """
        执行核验

        Args:
            url: 待核验URL
            interaction_type: 核验类型
                - "auto": 自动选择核验方式
                - "login_form": 专门核验登录表单
                - "link_suspicious": 专门核验可疑链接
                - "score_close": 得分接近时的核验

        Returns:
            核验结果字典
        """
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            page = await browser.new_page()

            try:
                # Step 1: 访问页面
                await page.goto(url, timeout=self.timeout, wait_until='domcontentloaded')

                # 等待页面稳定
                await asyncio.sleep(2)

                # Step 2: 静态解析
                static_result = await self._static_analysis(page, url)

                # Step 3: 动态核验
                if interaction_type in ["auto", "login_form"]:
                    dynamic_result = await self._dynamic_login_check(page, url)
                    static_result.update(dynamic_result)

                if interaction_type in ["auto", "link_suspicious"]:
                    link_result = await self._dynamic_link_check(page, url)
                    static_result.update(link_result)

                # Step 4: 判定
                final_result = self._judge(static_result, url)

                return final_result

            except Exception as e:
                return {
                    "success": False,
                    "error": str(e),
                    "url": url
                }
            finally:
                await browser.close()

    async def _static_analysis(self, page: Page, original_url: str) -> Dict:
        """静态解析：提取表单、链接、脚本"""
        result = {
            "has_form_tag": False,
            "has_login_form": False,
            "has_password_input": False,
            "form_action_urls": [],
            "internal_links": [],
            "external_links": [],
            "suspicious_links": [],
            "login_keywords_found": [],
            "redirect_chain": [],
        }

        try:
            # 检查表单
            forms = await page.query_selector_all("form")
            result["has_form_tag"] = len(forms) > 0

            for form in forms:
                action = await form.get_attribute("action")
                if action:
                    result["form_action_urls"].append(action)

                # 检查密码输入框
                password_inputs = await form.query_selector_all('input[type="password"]')
                if password_inputs:
                    result["has_password_input"] = True
                    result["has_login_form"] = True

                # 检查普通输入框
                text_inputs = await form.query_selector_all('input[type="text"], input[type="email"], input:not([type])')
                if text_inputs and not result["has_login_form"]:
                    result["has_login_form"] = True

            # 检查登录按钮
            submit_buttons = await page.query_selector_all('button[type="submit"], input[type="submit"]')
            if submit_buttons:
                result["has_login_form"] = True

            # 提取所有链接
            links = await page.query_selector_all("a")
            for link in links:
                href = await link.get_attribute("href")
                if not href:
                    continue

                # 解析链接
                parsed = urlparse(href)
                if not parsed.scheme:
                    # 相对路径
                    full_url = urljoin(original_url, href)
                    parsed = urlparse(full_url)

                domain = parsed.netloc.lower()

                # 分类
                if domain and domain != urlparse(original_url).netloc.lower():
                    result["external_links"].append(href)

                    # 检查是否可疑
                    if self._is_suspicious_link(parsed.netloc, parsed.path):
                        result["suspicious_links"].append(href)
                else:
                    result["internal_links"].append(href)

            # 检查登录关键词
            page_text = await page.content()
            login_keywords = ["登录", "登陆", "login", "signin", "账号", "密码", "password", "username"]
            for kw in login_keywords:
                if kw.lower() in page_text.lower():
                    result["login_keywords_found"].append(kw)

        except Exception as e:
            result["static_error"] = str(e)

        return result

    async def _dynamic_login_check(self, page: Page, original_url: str) -> Dict:
        """动态核验：定位登录框/表单"""
        result = {
            "dynamic_login_form_found": False,
            "dynamic_login_verified": False,
            "login_form_details": "",
        }

        try:
            # 等待登录表单出现（如果存在）
            selectors = [
                'input[type="password"]',
                'input[name*="password" i]',
                'input[name*="pass" i]',
                'form',
                'button[type="submit"]',
                '.login', '.signin', '#login', '#signin',
            ]

            for selector in selectors:
                try:
                    locator = page.locator(selector)
                    if await locator.first.is_visible(timeout=3000):
                        result["dynamic_login_form_found"] = True

                        # 检查是否是密码输入框
                        if "password" in selector:
                            result["dynamic_login_verified"] = True
                            result["login_form_details"] = f"找到密码输入框: {selector}"
                            break
                        elif selector == "form":
                            # 检查form内是否有密码输入框
                            form_locator = page.locator(selector).first
                            password_in_form = form_locator.locator('input[type="password"]')
                            if await password_in_form.count() > 0:
                                result["dynamic_login_verified"] = True
                                result["login_form_details"] = "表单内含密码输入框"
                                break
                except:
                    continue

        except Exception as e:
            result["dynamic_error"] = str(e)

        return result

    async def _dynamic_link_check(self, page: Page, original_url: str) -> Dict:
        """动态核验：模拟hover/click，捕获动态链接"""
        result = {
            "dynamic_links_captured": [],
            "hovered_links": [],
            "clicked_links": [],
            "final_destination_url": original_url,
        }

        try:
            original_domain = urlparse(original_url).netloc.lower()

            # 查找所有链接
            links = await page.query_selector_all("a")

            for link in links[:10]:  # 限制检查数量
                try:
                    href = await link.get_attribute("href")
                    if not href:
                        continue

                    # Hover
                    await link.hover()
                    await asyncio.sleep(0.3)

                    # 检查href变化
                    new_href = await link.get_attribute("href")
                    if new_href and new_href != href:
                        result["hovered_links"].append({
                            "original": href,
                            "after_hover": new_href
                        })

                    # 解析域名
                    parsed = urlparse(new_href if new_href else href)
                    if parsed.netloc and parsed.netloc.lower() != original_domain:
                        result["dynamic_links_captured"].append({
                            "url": new_href if new_href else href,
                            "domain": parsed.netloc
                        })

                except:
                    continue

            # 记录最终URL（可能因重定向改变）
            result["final_destination_url"] = page.url

        except Exception as e:
            result["link_check_error"] = str(e)

        return result

    def _is_suspicious_link(self, domain: str, path: str) -> bool:
        """判断链接是否可疑"""
        if not domain:
            return False

        domain_lower = domain.lower()

        # 1. 高危后缀
        for suffix in HIGH_RISK_SUFFIXES:
            if domain_lower.endswith(suffix):
                return True

        # 2. 数字字母混淆（如 paypa1, g00gle）
        if re.search(r'[0-9]+[a-z]+|[a-z]+[0-9]+', domain_lower):
            return True

        # 3. 品牌混淆（同形字）
        confusion_chars = {'o': ['0'], 'l': ['1', 'i'], 'i': ['1', 'l'], 'a': ['4', '@'], 'e': ['3']}
        for char, variants in confusion_chars.items():
            for v in variants:
                if v in domain_lower:
                    # 检查是否可能是品牌混淆
                    confused = domain_lower.replace(v, char)
                    brand_names = ['baidu', 'alipay', 'weixin', 'weibo', 'taobao', 'jingdong']
                    for brand in brand_names:
                        if brand in confused or confused in brand:
                            return True

        # 4. 短域名（可能是恶意跳转）
        if len(domain_lower.split('.')[0]) < 4 and '.' in domain_lower:
            return True

        return False

    def _judge(self, result: Dict, original_url: str) -> Dict:
        """综合判定"""
        judgment = {
            "success": True,
            "url": original_url,
            "login_form_verified": False,
            "suspicious_redirects": [],
            "is_abnormal_url": False,
            "abnormal_reasons": [],
            "risk_level": "低危",
            "summary": "",
        }

        # 1. 登录表单判定
        if result.get("has_login_form") or result.get("dynamic_login_form_found"):
            judgment["login_form_verified"] = True

        # 2. 可疑链接判定
        suspicious = result.get("suspicious_links", [])
        dynamic_suspicious = result.get("dynamic_links_captured", [])

        for link_info in dynamic_suspicious:
            domain = link_info.get("domain", "")
            if self._is_suspicious_link(domain, ""):
                judgment["suspicious_redirects"].append(link_info["url"])
                judgment["abnormal_reasons"].append(f"动态链接跳转到可疑域名: {domain}")

        # 3. 异常URL判定
        original_domain = urlparse(original_url).netloc.lower()

        # 无备案 + 高危后缀
        for suffix in HIGH_RISK_SUFFIXES:
            if original_domain.endswith(suffix):
                judgment["abnormal_reasons"].append(f"高危域名后缀: {suffix}")
                judgment["is_abnormal_url"] = True

        # 数字字母混淆
        if re.search(r'[0-9]+[a-z]+|[a-z]+[0-9]+', original_domain):
            judgment["abnormal_reasons"].append("数字字母混淆域名")
            judgment["is_abnormal_url"] = True

        # 跳转后域名与原域名不符
        final_url = result.get("final_destination_url", original_url)
        final_domain = urlparse(final_url).netloc.lower()
        if final_domain and final_domain != original_domain:
            judgment["abnormal_reasons"].append(f"域名跳转: {original_domain} -> {final_domain}")
            judgment["is_abnormal_url"] = True

        # 4. 风险级别
        if judgment["login_form_verified"] and judgment["suspicious_redirects"]:
            judgment["risk_level"] = "高危"
            judgment["summary"] = "存在登录表单且跳转到可疑域名"
        elif judgment["login_form_verified"]:
            judgment["risk_level"] = "中危"
            judgment["summary"] = "存在登录表单"
        elif judgment["suspicious_redirects"]:
            judgment["risk_level"] = "中危"
            judgment["summary"] = "跳转到可疑域名"
        elif judgment["is_abnormal_url"]:
            judgment["risk_level"] = "中危"
            judgment["summary"] = "; ".join(judgment["abnormal_reasons"])
        else:
            judgment["risk_level"] = "低危"
            judgment["summary"] = "未发现明显异常"

        return judgment


async def main():
    """命令行入口"""
    if len(sys.argv) < 2:
        print("用法: python playwright_verify.py <url> [interaction_type]")
        print("  interaction_type: auto | login_form | link_suspicious | score_close")
        sys.exit(1)

    url = sys.argv[1]
    interaction_type = sys.argv[2] if len(sys.argv) > 2 else "auto"

    print(f"核验URL: {url}")
    print(f"核验类型: {interaction_type}")
    print("-" * 60)

    verifier = PlaywrightVerifier()
    result = await verifier.verify(url, interaction_type)

    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    asyncio.run(main())
