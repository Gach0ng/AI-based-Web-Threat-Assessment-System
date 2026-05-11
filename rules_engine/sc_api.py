"""
威胁情报API预留接口
"""
from typing import Dict, Any, Optional
import asyncio
import json
import hashlib
import random
import time
import os
from urllib.parse import urlparse

# 从配置文件加载API配置
CONFIG_PATH = os.path.join(os.path.dirname(__file__), '..', 'config', 'api_keys.json')

def _load_config() -> dict:
    """加载API配置"""
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, 'r', encoding='utf-8') as f:
            return json.load(f)
    return {}

_config = _load_config()

# 威胁情报API接口配置（从配置文件读取）
THREAT_API_TEST_URL = _config.get("sc_api_test_url", "http://api.safe.example.com")
THREAT_API_TEST_APPID = _config.get("sc_api_test_appid", "")
THREAT_API_TEST_SECRET = _config.get("sc_api_test_secret", "")
THREAT_LEVEL_THRESHOLD = _config.get("sc_level_threshold", 30)

# 威胁情报API可用性
THREAT_API_AVAILABLE = bool(THREAT_API_TEST_APPID and THREAT_API_TEST_SECRET)

DEFAULT_THREAT_INTEL = {
    'threat_api_available': THREAT_API_AVAILABLE,
    'in_official_whitelist': False,
    'threat_level': 0,
}


def get_threat_intel(url: str = "", domain: str = "", ip: str = "") -> Dict[str, Any]:
    """
    获取威胁情报
    调用威胁情报API接口获取IOC Tags，根据level分流
    """
    if not domain:
        domain = _extract_domain(url)

    # 如果都没有，返回默认空情报
    if not domain and not ip:
        return DEFAULT_THREAT_INTEL.copy()

    # 调用威胁情报API获取威胁情报
    threat_result = query_threat_ioc_tags(domain)
    level = extract_threat_level(threat_result)

    return {
        'threat_api_available': THREAT_API_AVAILABLE,
        'in_official_whitelist': False,
        'threat_level': level,
    }


def _extract_domain(url: str) -> str:
    """从URL提取域名"""
    if not url:
        return ""
    try:
        parsed = urlparse(url)
        return parsed.netloc or ""
    except:
        return ""


def _make_api_headers(body_str: str) -> dict:
    """生成威胁情报API签名请求头"""
    headers = {}
    headers["X-API-Key"] = THREAT_API_TEST_APPID
    headers["X-Nonce"] = str(random.randint(0, 99999999)).zfill(8)
    headers["X-Timestamp"] = str(int(time.time()))
    body_md5 = hashlib.md5(body_str.encode("utf8")).hexdigest()
    s = body_md5 + headers["X-API-Key"] + headers["X-Nonce"] + headers["X-Timestamp"] + THREAT_API_TEST_SECRET
    headers["X-Signature"] = hashlib.md5(s.encode("utf8")).hexdigest()[16:]
    headers["Content-Type"] = "application/json"
    return headers


def query_threat_ioc_tags(domain: str) -> Dict[str, Any]:
    """
    调用威胁情报API接口: IOC Tags
    返回包含level字段的字典
    """
    import requests

    url = THREAT_API_TEST_URL + "/custom/intelligence/v1/tags"
    body = {
        "query": {
            "keywords": [
                {"field": "category", "value": "domain"},
                {"field": "query", "value": domain}
            ]
        }
    }
    body_str = json.dumps(body)
    headers = _make_api_headers(body_str)

    try:
        resp = requests.post(url, data=body_str, headers=headers, timeout=30)
        if resp.status_code == 200:
            result = resp.json()
            return {'code': 200, 'data': result}
        else:
            return {'code': resp.status_code, 'message': f'HTTP {resp.status_code}', 'data': None}
    except Exception as e:
        return {'code': -1, 'message': str(e), 'data': None}


def extract_threat_level(threat_result: Dict[str, Any]) -> int:
    """
    从威胁情报IOC Tags响应中提取level
    level表示威胁等级，>=30为中高危，<30为低危
    """
    if threat_result.get('code') != 200:
        return 0

    data = threat_result.get('data', {})
    if not data:
        return 0

    # 尝试从响应中提取level字段
    # 响应结构可能是 {"data": {...}, "code": 200} 形式
    # level可能在不同位置，需要根据实际返回结构调整
    if isinstance(data, dict):
        # 优先查找顶层level
        if 'level' in data:
            return int(data.get('level', 0))
        # 查找tags中的level
        tags = data.get('data', [])
        if isinstance(tags, list) and len(tags) > 0:
            for tag in tags:
                if isinstance(tag, dict) and 'level' in tag:
                    return int(tag.get('level', 0))
        # 查找anymous_tag或类似字段
        for key in ['level', 'threat_level', 'risk_level']:
            if key in data:
                return int(data.get(key, 0))

    return 0


async def query_mcp_async(ioc: str, ioc_type: str = "domain") -> Dict[str, Any]:
    """
    调用MCP的IOC多维分析接口（异步版本）
    """
    try:
        from MCP.mcp_client import query_ioc as mcp_query_ioc
        return await mcp_query_ioc(ioc, ioc_type)
    except Exception as e:
        return {"code": -1, "message": str(e), "data": None}


def query_mcp_sync(ioc: str, ioc_type: str = "domain") -> Dict[str, Any]:
    """调用MCP的IOC多维分析接口（同步版本）"""
    return asyncio.run(query_mcp_async(ioc, ioc_type))
