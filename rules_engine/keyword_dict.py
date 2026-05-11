"""
关键词泛化字典管理模块
"""

import json
import os
from typing import Dict, List, Any, Optional
from pathlib import Path


# 常见品牌关键词泛化模式
BRAND_VARIATION_PATTERNS = {
    'suffixes': [
        '有限公司', '股份有限公司', '集团有限公司', '集团',
        '公司', '银行', '证券公司', '保险公司', '投资基金',
        'Co.', 'Ltd.', 'Inc.', 'Corp.', 'LLC'
    ],
    'abbreviations': {
        '示例品牌A': ['BRANDA', 'branda', 'example_a'],
        '示例品牌B': ['BRANDB', 'brandb', 'example_b'],
        '示例品牌C': ['BRANDC', 'brandc', 'example_c'],
    },
    'homograph_chars': {
        'o': ['0', 'ο', 'О'],
        'l': ['1', 'ι', 'I', '|'],
        'i': ['1', 'l', 'Ι', '|'],
        'a': ['α', '@', '4'],
        'e': ['ξ', 'ε', '3'],
        'c': ['(', 'С', 'ç'],
        'u': ['υ', 'ü', 'μ'],
        'n': ['ñ', 'ν'],
        'w': ['vv', 'ω', 'Ш'],
        's': ['5', '$', 'ѕ'],
    },
    'digit_letter_map': {
        'a': '4', 'e': '3', 'i': '1', 'o': '0', 's': '5',
        'A': '4', 'E': '3', 'I': '1', 'O': '0', 'S': '5'
    }
}


def extract_keywords_from_brand_name(brand_name: str) -> List[str]:
    """从品牌名称中提取核心关键词"""
    if not brand_name:
        return []

    import re

    keywords = []

    clean_name = brand_name
    for suffix in BRAND_VARIATION_PATTERNS['suffixes']:
        if suffix.lower() in clean_name.lower():
            clean_name = clean_name.lower().replace(suffix.lower(), '')
            break

    for length in [2, 3, 4]:
        for i in range(len(clean_name) - length + 1):
            word = clean_name[i:i+length]
            if re.match(r'^[\u4e00-\u9fff]+$', word):
                keywords.append(word)

    english_words = re.findall(r'[a-zA-Z]{3,}', clean_name)
    keywords.extend([w.lower() for w in english_words])

    return list(set(keywords))


def generate_brand_variations(brand_name: str) -> Dict[str, List[str]]:
    """为品牌生成变体词列表"""
    keywords = extract_keywords_from_brand_name(brand_name)

    variations = {
        '标准词': keywords if keywords else [brand_name],
        '变体词': [],
        '拼音变体': [],
        '同形字变体': []
    }

    for kw in keywords:
        if len(kw) >= 3:
            for char, replacements in BRAND_VARIATION_PATTERNS['homograph_chars'].items():
                if char in kw.lower():
                    for rep in replacements:
                        variant = kw.lower().replace(char, rep)
                        if variant != kw.lower():
                            variations['同形字变体'].append(variant)

    for full_name, abbrevs in BRAND_VARIATION_PATTERNS['abbreviations'].items():
        if full_name in brand_name:
            variations['拼音变体'].extend(abbrevs)

    for kw in keywords:
        if len(kw) >= 4:
            variant = kw
            for char, digit in BRAND_VARIATION_PATTERNS['digit_letter_map'].items():
                if char in variant.lower():
                    variant = variant.lower().replace(char, digit)
            if variant != kw.lower():
                variations['变体词'].append(variant)

    return variations


class KeywordDictionary:
    """关键词字典管理器"""

    def __init__(self, dict_path: Optional[str] = None):
        self.dict_path = dict_path
        self.dictionary: Dict[str, Any] = {}
        self._all_keywords: set = set()

        if dict_path and os.path.exists(dict_path):
            self.load(dict_path)

    def load(self, dict_path: str):
        """加载关键词字典"""
        with open(dict_path, 'r', encoding='utf-8') as f:
            self.dictionary = json.load(f)
        self._build_keyword_set()

    def _build_keyword_set(self):
        """构建所有关键词集合"""
        self._all_keywords = set()
        for brand, info in self.dictionary.items():
            standard = info.get('标准词', [])
            generalized = info.get('泛化词', [])
            self._all_keywords.update(standard)
            self._all_keywords.update(generalized)

    def match_keywords(self, text: str) -> List[Dict[str, Any]]:
        """在文本中匹配关键词"""
        if not text:
            return []

        text_lower = text.lower()
        matches = []

        for brand, info in self.dictionary.items():
            matched_keywords = []

            standard = info.get('标准词', [])
            for kw in standard:
                if len(kw) >= 2 and kw.lower() in text_lower:
                    matched_keywords.append({'keyword': kw, 'type': '标准词'})

            generalized = info.get('泛化词', [])
            for kw in generalized:
                if len(kw) >= 2 and kw.lower() in text_lower:
                    matched_keywords.append({'keyword': kw, 'type': '泛化词'})

            if matched_keywords:
                matches.append({
                    'brand': brand,
                    'matched_keywords': matched_keywords
                })

        return matches

    def has_brand_match(self, text: str, brand: str) -> bool:
        """检查文本是否包含指定品牌的关键词"""
        if not text or brand not in self.dictionary:
            return False

        text_lower = text.lower()
        info = self.dictionary[brand]

        for kw in info.get('标准词', []) + info.get('泛化词', []):
            if len(kw) >= 2 and kw.lower() in text_lower:
                return True

        return False

    def get_all_keywords(self) -> set:
        """获取所有关键词集合"""
        return self._all_keywords


def generate_keyword_dict(test_data_path: str) -> Dict[str, Any]:
    """从测试数据生成关键词泛化字典"""
    with open(test_data_path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    keyword_dict = {}

    if isinstance(data, list):
        brand_subjects = set()
        for item in data:
            brand = item.get('保护的品牌主体', '')
            if brand:
                brand_subjects.add(brand)

        for brand in brand_subjects:
            variations = generate_brand_variations(brand)
            keyword_dict[brand] = {
                '标准词': variations['标准词'],
                '泛化词': list(set(
                    variations['变体词'] +
                    variations['拼音变体'] +
                    variations['同形字变体']
                ))
            }

    return keyword_dict


def save_keyword_dict(keyword_dict: Dict[str, Any], output_path: str):
    """保存关键词泛化字典到文件"""
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(keyword_dict, f, ensure_ascii=False, indent=2)


def load_brand_keyword_dicts() -> Dict[str, Any]:
    """加载所有品牌关键词字典"""
    config_dir = Path(__file__).parent.parent / "config" / "brand_keywords"
    result = {}
    for f in config_dir.glob("*.json"):
        with open(f, 'r', encoding='utf-8') as fp:
            result.update(json.load(fp))
    return result