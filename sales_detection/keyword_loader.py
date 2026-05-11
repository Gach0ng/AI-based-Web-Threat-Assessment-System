#!/usr/bin/env python3
"""Keyword loader for sales detection"""
from typing import Dict, List
import os


class KeywordLoader:
    """Loads keywords for sales behavior detection"""

    def __init__(self, config_dir: str):
        self.config_dir = config_dir
        self._sales_keywords: Dict[str, List[str]] = {}
        self._institution_keywords: List[str] = []
        self._load_keywords()

    def _load_keywords(self):
        """Load keywords from config files"""
        # Load sales keywords
        sales_file = os.path.join(self.config_dir, 'financial_sales_keywords.txt')
        if os.path.exists(sales_file):
            self._sales_keywords = self._parse_sales_keywords(sales_file)

        # Load institution keywords
        institution_file = os.path.join(self.config_dir, 'institution_keywords.txt')
        if os.path.exists(institution_file):
            self._institution_keywords = self._parse_institution_keywords(institution_file)

    def _parse_sales_keywords(self, filepath: str) -> Dict[str, List[str]]:
        """Parse sales keywords file"""
        keywords = {}
        current_category = 'other'

        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue

                if '|' in line:
                    parts = line.split('|')
                    if len(parts) == 2:
                        keyword, category = parts
                        if category not in keywords:
                            keywords[category] = []
                        keywords[category].append(keyword.strip())

        return keywords

    def _parse_institution_keywords(self, filepath: str) -> List[str]:
        """Parse institution keywords file"""
        keywords = []

        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue

                # Format: 全称|简称|别名
                parts = line.split('|')
                keywords.extend([p.strip() for p in parts if p.strip()])

        return keywords

    def get_sales_keywords(self) -> Dict[str, List[str]]:
        """Get sales keywords"""
        return self._sales_keywords

    def get_institution_keywords(self) -> List[str]:
        """Get institution keywords"""
        return self._institution_keywords