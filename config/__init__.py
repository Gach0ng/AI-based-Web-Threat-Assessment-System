"""配置文件模块"""
import json
import os
from pathlib import Path

CONFIG_DIR = Path(__file__).parent


def load_config():
    """加载API配置"""
    config_path = CONFIG_DIR / "api_keys.json"
    if config_path.exists():
        with open(config_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    return {}


def load_brand_keywords():
    """加载品牌关键词泛化字典"""
    keywords_dir = CONFIG_DIR / "brand_keywords"
    result = {}
    for f in keywords_dir.glob("*.json"):
        with open(f, 'r', encoding='utf-8') as fp:
            result.update(json.load(fp))
    return result


# API配置
API_CONFIG = load_config()

# 便捷访问
BLACKLIST_API_URL = API_CONFIG.get("wd_api_url", "http://10.16.20.11:8004/api/urlcloud")
BLACKLIST_API_KEY = API_CONFIG.get("wd_api_key", "")
MINIMAX_API_KEY = API_CONFIG.get("minimax_api_key", "")
MCP_SERVER_URL = API_CONFIG.get("sc_mcp_server_url", "https://mcp.example.com/mcp/dimensional")
THREAT_API_KEY = API_CONFIG.get("sc_api_key", "")
THREAT_SALT = API_CONFIG.get("sc_salt", "")
THREAT_USER = API_CONFIG.get("sc_user", "")