#!/usr/bin/env python3
"""Main entry point for web analysis tool."""
import asyncio
import argparse
import json
import sys
from pathlib import Path
from browser_manager import BrowserManager
from content_extractor import ContentExtractor
from redirect_detector import RedirectDetector
from sensitive_element_scanner import SensitiveElementScanner
from link_validator import LinkValidator
from diff_analyzer import DiffAnalyzer
from gray_blacklist import GrayBlackFilter
from reporter import generate_report, save_report, print_summary
from config import Config


async def analyze_url(url: str, config: Config = Config()) -> dict:
    async with BrowserManager(config) as bm:
        browser_result = await bm.analyze(url)

    extractor = ContentExtractor()
    diff_analyzer = DiffAnalyzer()
    redirect_detector = RedirectDetector()
    sensitive_scanner = SensitiveElementScanner()
    link_validator = LinkValidator(config)
    gray_black_filter = GrayBlackFilter()

    if browser_result.js_enabled:
        html_enabled = browser_result.js_enabled.html
    else:
        html_enabled = ""

    if browser_result.js_disabled:
        html_disabled = browser_result.js_disabled.html
    else:
        html_disabled = ""

    diff = diff_analyzer.analyze(browser_result.js_enabled, browser_result.js_disabled)

    redirect_chain = await redirect_detector.detect(
        browser_result.js_enabled or browser_result.js_disabled,
        url
    )

    sensitive_report = sensitive_scanner.scan(html_enabled if html_enabled else html_disabled)

    links = browser_result.js_enabled.links if browser_result.js_enabled else browser_result.js_disabled.links if browser_result.js_disabled else []
    link_report = link_validator.validate_links(links, url)

    gray_black_report = _build_gray_black_report(links, html_enabled if html_enabled else html_disabled, gray_black_filter)

    report = generate_report(
        url=url,
        browser_result=browser_result,
        redirect_chain=redirect_chain,
        sensitive_report=sensitive_report,
        link_report=link_report,
        diff=diff,
        gray_black_report=gray_black_report
    )

    return report


def _build_gray_black_report(links: list, html_content: str, filter: GrayBlackFilter) -> dict:
    report = {
        'total_matches': 0,
        'by_category': [],
        'matched_items': []
    }

    by_category = {}

    for link in links:
        href = link.get('href', '')
        text = link.get('text', '')
        matches = filter.match_link_text(text)
        for match in matches:
            report['total_matches'] += 1
            cat_name = match['category']
            if cat_name not in by_category:
                by_category[cat_name] = {'name': cat_name, 'risk_level': match['risk_level'], 'match_count': 0}
            by_category[cat_name]['match_count'] += 1
            report['matched_items'].append({
                'type': 'link',
                'category': cat_name,
                'risk_level': match['risk_level'],
                'matched_keyword': match['matched_keyword'],
                'source': text[:100] if text else href,
                'url': href
            })

    if html_content:
        content_matches = filter.match_text_content(html_content)
        for match in content_matches:
            cat_name = match['category']
            if cat_name not in by_category:
                by_category[cat_name] = {'name': cat_name, 'risk_level': match['risk_level'], 'match_count': 0}
            by_category[cat_name]['match_count'] += 1
            report['total_matches'] += 1
            report['matched_items'].append({
                'type': 'content',
                'category': cat_name,
                'risk_level': match['risk_level'],
                'matched_keyword': match['matched_keyword'],
                'source': '(page content)',
                'url': ''
            })

    report['by_category'] = list(by_category.values())
    return report


def _url_to_filename(url: str) -> str:
    from urllib.parse import urlparse
    parsed = urlparse(url)
    host = parsed.netloc.replace(':', '_').replace('.', '_')
    return host


def main():
    parser = argparse.ArgumentParser(
        description='Web Page Dynamic Analysis Tool - JS rendering comparison and security analysis'
    )
    parser.add_argument('url', help='Target URL to analyze')
    parser.add_argument('-o', '--output', help='Output JSON file path (default: auto-save to results/)')
    parser.add_argument('--no-save', action='store_true', help='Disable auto-save to results/')
    parser.add_argument('--timeout', type=int, default=30000, help='Timeout in milliseconds')
    parser.add_argument('--retries', type=int, default=2, help='Number of retry attempts')

    args = parser.parse_args()

    config = Config(
        timeout_ms=args.timeout,
        retry_times=args.retries
    )

    print(f"Analyzing: {args.url}")

    try:
        report = asyncio.run(analyze_url(args.url, config))
        print_summary(report)

        if args.output:
            save_report(report, args.output)
            print(f"\nReport saved to: {args.output}")

        elif not args.no_save:
            import os
            results_dir = os.path.join(os.path.dirname(__file__), 'results')
            os.makedirs(results_dir, exist_ok=True)

            name = _url_to_filename(args.url)
            import time
            timestamp = time.strftime('%Y%m%d_%H%M%S')
            json_path = os.path.join(results_dir, f"{name}_{timestamp}.json")
            txt_path = os.path.join(results_dir, f"{name}_{timestamp}.txt")

            save_report(report, json_path)

            with open(txt_path, 'w', encoding='utf-8') as f:
                f.write(f"URL: {report['url']}\n")
                f.write(f"Timestamp: {report['timestamp']}\n\n")

                sensitive = report.get('sensitive_elements', {})
                login_count = sensitive.get('login_form_count', 0)
                high_risk = sensitive.get('high_risk_forms', 0)
                if login_count > 0:
                    f.write(f"[!] 登录/注册表单: {login_count} 个 (高风险 {high_risk} 个)\n")
                    for form in sensitive.get('forms', []):
                        if form.get('is_login_form') or form.get('type') in ('login', 'register'):
                            f.write(f"    - 类型: {form.get('type')} | 风险: {form.get('risk')} | "
                                    f"密码字段: {'有' if form.get('has_password_field') else '无'} | "
                                    f"地址: {form.get('action_url', 'N/A')[:60]}\n")
                else:
                    f.write(f"[+] 登录/注册表单: 未检测到\n")

                links = report.get('link_analysis', {})
                sus_count = links.get('suspicious_count', 0)
                if sus_count > 0:
                    f.write(f"\n[!] 可疑链接: {sus_count} 条\n")
                    for link in links.get('suspicious_links', []):
                        f.write(f"    [{link['risk_score']:.2f}] {link['url'][:65]}\n")
                        f.write(f"         原因: {link['reason']}\n")
                else:
                    f.write(f"\n[+] 可疑链接: 0 条\n")

                diff = report.get('differences', {})
                if not diff:
                    status = report.get('status', {})
                    js_ok = status.get('js_enabled_success', False) and status.get('js_disabled_success', False)
                    if not js_ok:
                        f.write(f"\n[!] JS开/关对比: 无法对比 (部分模式加载失败)\n")
                    else:
                        f.write(f"\n[+] JS开/关内容: 一致\n")
                else:
                    identical = diff.get('text_identical', True)
                    if identical:
                        f.write(f"\n[+] JS开/关内容: 一致\n")
                    else:
                        f.write(f"\n[!] JS开/关内容: 不一致\n")
                        ac = diff.get('article_comparison', {})
                        sim = ac.get('content_similarity', 0)
                        f.write(f"    相似度: {sim:.1%} | JS模式: {ac.get('js_generated_paragraphs', 0)} 段落 | "
                                f"非JS模式: {ac.get('disabled_paragraphs', 0)} 段落\n")

            print(f"\nReport saved to: {json_path}")
            print(f"Text summary saved to: {txt_path}")
        else:
            print("\nFull JSON Report:")
            print(json.dumps(report, ensure_ascii=False, indent=2))

    except KeyboardInterrupt:
        print("\nAnalysis interrupted by user.")
        sys.exit(1)
    except Exception as e:
        import traceback
        traceback.print_exc()
        print(f"\nError: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()