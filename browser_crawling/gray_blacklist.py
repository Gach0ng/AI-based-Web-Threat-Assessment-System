"""Gray/black hat link text category dictionary and filter"""
from dataclasses import dataclass
from typing import Dict, List
import json
import os


@dataclass
class CategoryKeywords:
    name: str
    risk_level: str
    keywords: List[str]


def load_gray_black_categories() -> List[CategoryKeywords]:
    """Load gray black categories from config"""
    config_path = os.path.join(
        os.path.dirname(__file__), '..', 'config', 'gray_black_keywords', 'gray_black_categories.json'
    )

    if os.path.exists(config_path):
        with open(config_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            categories = []
            for cat in data.get('categories', []):
                categories.append(CategoryKeywords(
                    name=cat['name'],
                    risk_level=cat['risk_level'],
                    keywords=cat.get('keywords', [])
                ))
            return categories

    return []


GRAY_BLACK_CATEGORIES = load_gray_black_categories()


class GrayBlackFilter:
    def __init__(self):
        self._build_index()

    def _build_index(self):
        self.category_map: Dict[str, CategoryKeywords] = {}
        self.keyword_to_category: Dict[str, CategoryKeywords] = {}

        for cat in GRAY_BLACK_CATEGORIES:
            self.category_map[cat.name] = cat
            for kw in cat.keywords:
                self.keyword_to_category[kw.lower()] = cat

    def match_link_text(self, text: str) -> List[Dict]:
        text_lower = text.lower().strip()
        results = []

        for kw, cat in self.keyword_to_category.items():
            if kw in text_lower:
                results.append({
                    'category': cat.name,
                    'matched_keyword': kw,
                    'risk_level': cat.risk_level,
                    'link_text': text.strip()
                })

        return results

    def match_text_content(self, content: str) -> List[Dict]:
        content_lower = content.lower()
        results = []

        for kw, cat in self.keyword_to_category.items():
            if kw in content_lower:
                results.append({
                    'category': cat.name,
                    'matched_keyword': kw,
                    'risk_level': cat.risk_level
                })

        return results

    def get_all_categories(self) -> List[Dict]:
        return [
            {'name': cat.name, 'risk_level': cat.risk_level, 'keyword_count': len(cat.keywords)}
            for cat in GRAY_BLACK_CATEGORIES
        ]