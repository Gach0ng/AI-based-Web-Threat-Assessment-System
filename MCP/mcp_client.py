"""
MCP客户端
调用MCP的IOC多维分析接口
"""

import asyncio
import json
from typing import Literal
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client
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


_config = _load_config()

# MCP服务器配置
MCP_SERVER_URL = _config.get("sc_mcp_server_url", "https://mcp.example.com/mcp/dimensional")
API_KEY = _config.get("sc_api_key", "572572d6c15d6e7edd29f63e922bd32f")
SALT = _config.get("sc_salt", "0996ea4c4863a7795d3b4bcd623a747d")
USER = _config.get("sc_user", "user_example_123")

API_HEADERS = {
    "X-API-Key": API_KEY,
    "X-Salt": SALT,
    "X-User": USER
}

IocType = Literal["domain", "ip", "url", "ip_port", "file"]


async def query_ioc(
    ioc: str,
    ioc_type: IocType = "domain"
) -> dict:
    """
    调用MCP的IOC多维分析接口。

    Args:
        ioc:      IOC值（域名/IP/URL/文件哈希等）
        ioc_type: IOC类型，支持 domain/ip/url/ip_port/file

    Returns:
        包含 code/message/data 的字典，data 内有6个维度的 summary 和 score
    """
    async with streamablehttp_client(MCP_SERVER_URL, headers=API_HEADERS) as (
        read_stream, write_stream, _
    ):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()

            result = await session.call_tool(
                name="IOC多维分析",
                arguments={"ioc": ioc, "ioc_type": ioc_type}
            )

            if not result or not result.content:
                return {"code": -1, "message": "no content returned", "data": None}

            return json.loads(result.content[0].text)


def query_ioc_sync(ioc: str, ioc_type: IocType = "domain") -> dict:
    """query_ioc 的同步封装。"""
    return asyncio.run(query_ioc(ioc, ioc_type))


# ── 便捷提取函数 ────────────────────────────────────────────

def extract_scores(data: dict) -> dict:
    """从IOC查询结果中提取所有维度的评分。"""
    if data.get("code") != 200 or not data.get("data"):
        return {}
    return {k: v["score"] for k, v in data["data"].items()}


def extract_overall_score(data: dict) -> int:
    """提取综合评分（overall_summary.score）。"""
    if data.get("code") != 200 or not data.get("data"):
        return -1
    return data["data"].get("overall_summary", {}).get("score", -1)


def is_malicious(data: dict, threshold: int = 60) -> bool:
    """综合评分超过阈值则判定为恶意。"""
    return extract_overall_score(data) >= threshold


# ── CLI 入口 ─────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="IOC 多维分析查询")
    parser.add_argument("ioc", help="IOC值（域名/IP/URL）")
    parser.add_argument("--type", "-t", dest="ioc_type", default="domain",
                        choices=["domain", "ip", "url", "ip_port", "file"],
                        help="IOC类型（默认 domain）")
    args = parser.parse_args()

    result = query_ioc_sync(args.ioc, args.ioc_type)

    if result.get("code") == 200:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(json.dumps(result, ensure_ascii=False, indent=2))
        exit(1)