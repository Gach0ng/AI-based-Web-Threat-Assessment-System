"""
黑类型查询客户端
通过API获取URL对应的黑类型数据
"""

import requests
from typing import List, Dict, Any, Optional
from .black_type_mapper import map_black_type, map_wd_info_type
import os
import json

# 尝试从配置加载
CONFIG_PATH = os.path.join(os.path.dirname(__file__), '..', 'config', 'api_keys.json')


def _load_config():
    """加载API配置"""
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, 'r', encoding='utf-8') as f:
            return json.load(f)
    return {}


# 默认配置
_config = _load_config()
DEFAULT_API_URL = _config.get("wd_api_url", "http://10.16.20.11:8004/api/urlcloud")
DEFAULT_API_KEY = _config.get("wd_api_key", "6554a3a6-66cf-473e-8c53-9b098f6eda5f")


class WDClient:
    """黑类型查询客户端"""

    def __init__(self, api_url: str = None, api_key: str = None):
        self.api_url = api_url or DEFAULT_API_URL
        self.api_key = api_key or DEFAULT_API_KEY
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {self.api_key}",
        })

    def query_urls(self, urls: List[str]) -> List[Dict[str, Any]]:
        """批量查询URL的黑类型"""
        if not urls:
            return []

        payload = {"urls": urls}

        try:
            response = self.session.post(
                self.api_url,
                json=payload,
                timeout=30
            )
            response.raise_for_status()
            result = response.json()

            return self._parse_response(urls, result)

        except requests.exceptions.RequestException as e:
            return [{
                "url": url,
                "error": str(e),
                "black_type": None
            } for url in urls]

    def _parse_response(self, urls: List[str], raw_result: Any) -> List[Dict[str, Any]]:
        """解析API返回结果"""
        results = []

        data_map = raw_result.get("data", {}) if isinstance(raw_result, dict) else {}

        for url in urls:
            raw_data = data_map.get(url, {})

            if not raw_data:
                results.append({
                    "url": url,
                    "error": "未找到该URL的数据",
                    "black_type": None
                })
                continue

            level = raw_data.get("Level", 0)
            st = raw_data.get("St", 0)
            is_black = raw_data.get("IsBlack", False)
            is_phishing = raw_data.get("IsPhishing", False)
            phishing_detail = raw_data.get("PhishingDetail", "")
            is_gwd = raw_data.get("IsGwd", False)

            gwd_info = raw_data.get("GwdInfo", {})
            wd_info = raw_data.get("WdInfo", {})

            info_data = gwd_info if gwd_info.get("Sc") else wd_info
            sc = info_data.get("Sc", "")
            ssc = info_data.get("Ssc", "")

            try:
                level_int = int(level) if level else 0
                st_int = int(st) if st else 0
                sc_int = int(sc) if sc else 0
                ssc_int = int(ssc) if ssc else 0
            except (ValueError, TypeError):
                level_int, st_int, sc_int, ssc_int = 0, 0, 0, 0

            is_wd_type = (level_int == 60 and st_int in [10, 30]) or (level_int == 0 and st_int == 30)

            if is_wd_type and is_gwd:
                category_info = map_wd_info_type(level_int, st_int, sc_int, ssc_int, sc_int)
            else:
                category_info = map_black_type(level_int, st_int, sc_int, ssc_int)

            results.append({
                "url": url,
                "raw_data": {
                    "level": level_int,
                    "st": st_int,
                    "sc": sc_int,
                    "ssc": ssc_int,
                    "is_black": is_black,
                    "is_phishing": is_phishing,
                    "phishing_detail": phishing_detail,
                    "is_gwd": is_gwd
                },
                "category_name": category_info["category_name"],
                "suggested_level": category_info["suggested_level"],
                "is_wd_type": is_wd_type and is_gwd,
                "error": None
            })

        return results

    def query_single(self, url: str) -> Dict[str, Any]:
        """查询单个URL"""
        results = self.query_urls([url])
        return results[0] if results else {"url": url, "error": "No result", "black_type": None}


def query_wd_black_type(urls: List[str]) -> List[Dict[str, Any]]:
    """便捷函数：批量查询URL的黑类型"""
    client = WDClient()
    return client.query_urls(urls)


def query_single_url(url: str) -> Dict[str, Any]:
    """便捷函数：查询单个URL的黑类型"""
    client = WDClient()
    return client.query_single(url)