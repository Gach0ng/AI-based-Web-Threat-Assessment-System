"""Diff analyzer for comparing JS enabled vs disabled content"""
from typing import Optional, Dict, Any
import re
from .content_extractor import ContentExtractor
from .browser_manager import PageResult


class DiffAnalyzer:
    """Analyzes differences between JS enabled and disabled page content"""

    def __init__(self):
        self.extractor = ContentExtractor()

    def analyze(self, js_enabled: Optional[PageResult], js_disabled: Optional[PageResult]) -> Dict[str, Any]:
        """Compare JS enabled and disabled page content"""
        if not js_enabled and not js_disabled:
            return {}

        js_enabled_text = ""
        js_disabled_text = ""
        js_enabled_links = []
        js_disabled_links = []

        if js_enabled:
            js_enabled_text = self.extractor.extract_text(js_enabled.html)
            js_enabled_links = js_enabled.links

        if js_disabled:
            js_disabled_text = self.extractor.extract_text(js_disabled.html)
            js_disabled_links = js_disabled.links

        # Calculate similarity
        similarity = self._calculate_similarity(js_enabled_text, js_disabled_text)

        # Count differences
        added_links = len(js_enabled_links) - len(js_disabled_links)

        # Extract preview paragraphs
        js_preview = self._get_preview(js_enabled_text, 200)
        no_js_preview = self._get_preview(js_disabled_text, 200)

        return {
            'text_identical': js_enabled_text == js_disabled_text,
            'content_similarity': similarity,
            'js_generated_paragraphs': self._count_paragraphs(js_enabled_text),
            'disabled_paragraphs': self._count_paragraphs(js_disabled_text),
            'added_links_count': added_links,
            'js_generated_preview': js_preview,
            'removed_preview': no_js_preview,
            'link_count_diff': added_links,
        }

    def _calculate_similarity(self, text1: str, text2: str) -> float:
        """Calculate text similarity (simple Jaccard)"""
        if not text1 and not text2:
            return 1.0
        if not text1 or not text2:
            return 0.0

        set1 = set(text1.split())
        set2 = set(text2.split())

        intersection = len(set1 & set2)
        union = len(set1 | set2)

        return intersection / union if union > 0 else 0.0

    def _get_preview(self, text: str, length: int) -> str:
        """Get preview of text"""
        if not text:
            return ""
        return text[:length].strip()

    def _count_paragraphs(self, text: str) -> int:
        """Count paragraphs in text"""
        if not text:
            return 0
        paragraphs = re.split(r'[\n\r]+', text)
        return len([p for p in paragraphs if p.strip()])