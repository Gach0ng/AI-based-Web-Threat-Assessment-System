"""
运行时模块
提供决策树与浏览器分析结果的整合
"""

import asyncio
from dataclasses import dataclass, field
from typing import Dict, Any, Optional, List
from pathlib import Path
import sys

# 添加路径
_current_dir = Path(__file__).parent.parent
sys.path.insert(0, str(_current_dir))
sys.path.insert(0, str(_current_dir / 'rules_engine'))
sys.path.insert(0, str(_current_dir / 'browser_crawling'))

from rules_engine.engine import get_engine
from rules_engine.decision_tree import ThreatDecisionTree
from rules_engine.conditions import RISK_LEVEL_MAP
from browser_crawling.browser_manager import BrowserManager
from browser_crawling.diff_analyzer import DiffAnalyzer
from browser_crawling.sensitive_element_scanner import SensitiveElementScanner
from browser_crawling.gray_blacklist import GrayBlackFilter


@dataclass
class BrowserAnalysisResult:
    """浏览器分析结果"""
    js_enabled_html: str = ""
    js_disabled_html: str = ""
    js_enabled_title: str = ""
    js_disabled_title: str = ""
    has_login_form: bool = False
    login_form_count: int = 0
    form_types: List[str] = field(default_factory=list)
    form_risk_level: str = "unknown"
    js_diff_ratio: float = 0.0
    content_similarity: float = 1.0
    text_identical: bool = True
    link_count_diff: int = 0
    form_count_diff: int = 0
    links: List[Dict[str, str]] = field(default_factory=list)


@dataclass
class DetectionResult:
    """检测结果"""
    url: str
    brand_owner: str
    detection_time: str
    browser_analysis: Optional[BrowserAnalysisResult]
    decision_tree_category: str
    decision_tree_risk_level: str
    decision_path: List[str]
    intermediate_nodes: Dict[str, Any]
    threat_intel: Dict[str, Any]
    brand_keywords_matched: List[str]
    form_detection_report: Dict[str, Any]
    js_diff_report: Dict[str, Any]


class ThreatClassificationRuntime:
    """威胁分类运行时"""

    def __init__(self):
        self.decision_tree = ThreatDecisionTree()
        self._scanner = None
        self._gray_filter = None

    def _get_scanner(self):
        if self._scanner is None:
            self._scanner = SensitiveElementScanner()
        return self._scanner

    def _get_gray_filter(self):
        if self._gray_filter is None:
            self._gray_filter = GrayBlackFilter()
        return self._gray_filter

    def process(self, raw_data: Dict[str, Any], browser_result=None, **kwargs) -> DetectionResult:
        """处理单条数据"""
        from datetime import datetime
        import json

        # 获取浏览器分析结果
        browser_analysis = None
        if browser_result:
            ba = BrowserAnalysisResult()
            ba.js_enabled_html = browser_result.js_enabled.html if browser_result.js_enabled else ""
            ba.js_disabled_html = browser_result.js_disabled.html if browser_result.js_disabled else ""
            ba.js_enabled_title = browser_result.js_enabled.title if browser_result.js_enabled else ""
            ba.js_disabled_title = browser_result.js_disabled.title if browser_result.js_disabled else ""

            # 分析表单
            scanner = self._get_scanner()
            html_content = ba.js_enabled_html or ba.js_disabled_html
            scan_report = scanner.scan(html_content)
            ba.has_login_form = scan_report.login_form_count > 0
            ba.login_form_count = scan_report.login_form_count
            ba.form_types = [f.form_type for f in scan_report.forms]
            ba.form_risk_level = 'high' if scan_report.high_risk_forms > 0 else 'low'

            # 分析JS差异
            diff_analyzer = DiffAnalyzer()
            diff = diff_analyzer.analyze(browser_result.js_enabled, browser_result.js_disabled)
            content_similarity = diff.get('content_similarity', 1.0)
            ba.js_diff_ratio = 1.0 - content_similarity
            ba.content_similarity = content_similarity
            ba.text_identical = diff.get('text_identical', True)
            ba.link_count_diff = diff.get('link_count_diff', 0)

            ba.links = browser_result.js_enabled.links if browser_result.js_enabled else []

            browser_analysis = ba

        # 提取中间节点
        intermediate_nodes = self._extract_intermediate_nodes(raw_data, browser_analysis)

        # 将JS差异度和渲染后HTML加入raw_data，供决策树使用
        if browser_analysis:
            raw_data['JS开关页面相似度'] = 1.0 - browser_analysis.js_diff_ratio
            # 用Playwright渲染后的HTML覆盖原始源码字段，供节点10判断使用
            if browser_result.js_enabled:
                raw_data['当前快照源码命中结果'] = browser_result.js_enabled.html

        # 决策树分类
        threat_intel = raw_data.get('threat_intel', {})
        category, risk_level, decision_path, reasoning = self.decision_tree.classify(
            raw_data, threat_intel
        )

        # 品牌关键词匹配
        brand_keywords_matched = self._match_brand_keywords(raw_data)

        return DetectionResult(
            url=raw_data.get('URL', ''),
            brand_owner=raw_data.get('保护的品牌主体', ''),
            detection_time=datetime.now().isoformat(),
            browser_analysis=browser_analysis,
            decision_tree_category=category,
            decision_tree_risk_level=risk_level,
            decision_path=decision_path,
            intermediate_nodes=intermediate_nodes,
            threat_intel=threat_intel,
            brand_keywords_matched=brand_keywords_matched,
            form_detection_report={},
            js_diff_report={}
        )

    def _extract_intermediate_nodes(self, parsed_data: Dict[str, Any], browser_analysis: BrowserAnalysisResult = None) -> Dict[str, Any]:
        """提取中间节点用于调试和展示"""
        from rules_engine.conditions import (
            is_icp_empty, is_brand_in_title, yolo_ocr_empty,
            has_brand_sales_info, is_entertainment_gambling_porn,
            is_login_form_related_title, is_new_domain_overseas,
            get_icp_subject_type
        )

        nodes = {
            'threat_related': parsed_data.get('threat_related', True),
            'icp_empty': is_icp_empty(parsed_data),
            'is_ip_access': parsed_data.get('is_ip_access', False),
            'has_brand_keywords': is_brand_in_title(parsed_data),
            'has_gray_black_category': parsed_data.get('_has_gray_black_category', False),
            'has_login_form': browser_analysis.has_login_form if browser_analysis else False,
            'js_diff_ratio': browser_analysis.js_diff_ratio if browser_analysis else 0.0,
            'yolo_ocr_empty': yolo_ocr_empty(parsed_data),
            'icp_subject_type': get_icp_subject_type(parsed_data),
        }

        return nodes

    def _match_brand_keywords(self, parsed_data: Dict[str, Any]) -> List[str]:
        """匹配品牌关键词"""
        brand_owner = parsed_data.get('保护的品牌主体', '')
        if not brand_owner:
            return []

        text_content = ' '.join([
            parsed_data.get('当前快照源码命中结果', ''),
            parsed_data.get('当前网站标题', ''),
            parsed_data.get('URL', '')
        ])

        matched = []
        for i in range(len(brand_owner) - 1):
            for length in [2, 3, 4]:
                if i + length <= len(brand_owner):
                    word = brand_owner[i:i+length]
                    if len(word) >= 2 and word.lower() in text_content.lower():
                        matched.append(word)

        return list(set(matched))


async def process_with_browser(url: str, brand_owner: str = "", threat_intel: dict = None, **kwargs) -> DetectionResult:
    """使用浏览器分析并返回检测结果"""
    config_path = Path(__file__).parent.parent / 'browser_crawling' / 'config'
    sys.path.insert(0, str(config_path.parent))

    from browser_crawling.browser_manager import BrowserManager
    from browser_crawling.config import Config
    from rules_engine.sc_api import get_threat_intel
    from urllib.parse import urlparse

    config = Config()

    async with BrowserManager(config) as bm:
        browser_result = await bm.analyze(url)

    # 如果没有传入 threat_intel，自己查
    if threat_intel is None:
        parsed = urlparse(url)
        host = kwargs.get('仿冒网站host', '') or parsed.netloc or url
        threat_intel = get_threat_intel(url=url, domain=host, ip='')

    # 构建原始数据
    raw_data = {
        'URL': url,
        '保护的品牌主体': brand_owner,
        '当前网站标题': browser_result.js_enabled.title if browser_result.js_enabled else '',
        '当前快照源码命中结果': browser_result.js_enabled.html if browser_result.js_enabled else '',
        'threat_intel': threat_intel,
        **kwargs
    }

    runtime = ThreatClassificationRuntime()
    result = runtime.process(raw_data, browser_result)

    return result


# 全局运行时实例
_runtime = None


def get_runtime() -> ThreatClassificationRuntime:
    global _runtime
    if _runtime is None:
        _runtime = ThreatClassificationRuntime()
    return _runtime