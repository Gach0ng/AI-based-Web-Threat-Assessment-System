#!/usr/bin/env python3
"""Sales behavior detector"""
from dataclasses import dataclass
from typing import List, Dict, Any, Optional
from pathlib import Path
import os

from .keyword_loader import KeywordLoader


@dataclass
class DetectionResult:
    """Detection result"""
    url: str
    text_length: int
    has_sales: bool
    matched_categories: List[str]
    matched_keywords: List[str]
    risk_level: str
    details: Dict[str, Any]


class Detector:
    """Detects sales behavior patterns in web content"""

    def __init__(self, config_dir: Optional[str] = None):
        if config_dir is None:
            config_dir = os.path.join(
                os.path.dirname(__file__), '..', 'config', 'sales_keywords'
            )
        self.config_dir = config_dir
        self.keyword_loader = KeywordLoader(config_dir)

    def detect(self, url: str, text: str) -> DetectionResult:
        """Detect sales behavior in text content"""
        matched_categories = set()
        matched_keywords = []
        details = {}

        text_lower = text.lower()

        # Load keywords
        sales_keywords = self.keyword_loader.get_sales_keywords()
        institution_keywords = self.keyword_loader.get_institution_keywords()

        # Check sales keywords
        for category, keywords in sales_keywords.items():
            for keyword in keywords:
                if keyword in text_lower:
                    matched_categories.add(category)
                    matched_keywords.append(keyword)

        # Check institution keywords
        institution_matches = []
        for keyword in institution_keywords:
            if keyword in text_lower:
                institution_matches.append(keyword)

        # Determine if has sales behavior
        has_sales = len(matched_categories) > 0

        # Determine risk level
        risk_level = self._determine_risk_level(matched_categories)

        details = {
            'institution_matches': institution_matches,
            'category_counts': {cat: matched_keywords.count(cat) for cat in matched_categories}
        }

        return DetectionResult(
            url=url,
            text_length=len(text),
            has_sales=has_sales,
            matched_categories=list(matched_categories),
            matched_keywords=matched_keywords,
            risk_level=risk_level,
            details=details
        )

    def _determine_risk_level(self, categories: set) -> str:
        """Determine risk level based on matched categories"""
        high_risk_categories = {'违规销售', '诱导投资', '诈骗相关', '借贷违规', '保险违规'}
        medium_risk_categories = {'虚假宣传', '促销优惠', '价格诱导', '会员权益'}

        if any(cat in high_risk_categories for cat in categories):
            return 'high'
        elif any(cat in medium_risk_categories for cat in categories):
            return 'medium'
        elif categories:
            return 'low'
        return 'none'