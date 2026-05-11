"""
威胁分类集成程序
决策树 + 浏览器动态检测 + Skill研判
最终研判通过本地Gemma模型调用Skill完成
"""

import json
import asyncio
import sys
import os
from typing import Dict, Any, Optional
from pathlib import Path

# 添加项目路径
_current_dir = Path(__file__).parent.parent
sys.path.insert(0, str(_current_dir))
sys.path.insert(0, str(_current_dir / 'rules_engine'))
sys.path.insert(0, str(_current_dir / 'browser_crawling'))
sys.path.insert(0, str(_current_dir / 'WD'))
sys.path.insert(0, str(_current_dir / 'MCP'))

from integration.runtime import ThreatClassificationRuntime, DetectionResult, process_with_browser

# 黑数据客户端
from Blacklist.blacklist_client import query_single_url as query_wd
# MCP 客户端
from MCP.mcp_client import query_ioc as query_mcp_async

# Skill路径
SKILL_PROMPT_TEMPLATE_PATH = _current_dir / 'skill' / 'assets' / 'prompt_template.md'
SKILL_DEFINITION_PATH = _current_dir / 'skill' / 'references' / '威胁分类定义.txt'


def build_skill_input(result: DetectionResult, wd_result: Dict = None, mcp_result: Dict = None) -> Dict[str, Any]:
    """将DetectionResult转换为Skill输入格式"""
    ba = result.browser_analysis

    return {
        "decision_tree_result": {
            "category": result.decision_tree_category,
            "risk_level": result.decision_tree_risk_level,
            "decision_path": result.decision_path,
            "intermediate_nodes": result.intermediate_nodes,
        },
        "web_info": {
            "url": result.url,
            "title": "",
            "icp_subject": result.intermediate_nodes.get('icp_subject', ''),
            "domain": result.url,
            "content": {
                "current_html": ba.js_enabled_html[:2000] if ba and ba.js_enabled_html else "",
                "js_disabled_html": ba.js_disabled_html[:2000] if ba and ba.js_disabled_html else "",
            },
        },
        "browser_analysis": {
            "has_login_form": ba.has_login_form if ba else False,
            "login_form_count": ba.login_form_count if ba else 0,
            "form_types": ba.form_types if ba else [],
            "form_risk_level": ba.form_risk_level if ba else "unknown",
            "js_diff_ratio": ba.js_diff_ratio if ba else 0.0,
            "content_similarity": ba.content_similarity if ba else 1.0,
            "text_identical": ba.text_identical if ba else True,
            "link_count_diff": ba.link_count_diff if ba else 0,
            "form_count_diff": ba.form_count_diff if ba else 0,
        },
        "brand_owner": result.brand_owner,
        "brand_keywords_matched": result.brand_keywords_matched,
        "brand_match_confidence": result.brand_match_confidence if hasattr(result, 'brand_match_confidence') else "",
        "threat_intel": result.threat_intel,
        "wd_result": wd_result or {},
        "mcp_result": mcp_result or {},
    }


def build_skill_prompt(skill_input: Dict[str, Any]) -> str:
    """使用Skill的prompt_template.md构建prompt"""
    # 读取prompt模板
    if SKILL_PROMPT_TEMPLATE_PATH.exists():
        with open(SKILL_PROMPT_TEMPLATE_PATH, 'r', encoding='utf-8') as f:
            template = f.read()
    else:
        template = _get_default_template()

    # 读取分类定义
    classification_defs = ""
    if SKILL_DEFINITION_PATH.exists():
        with open(SKILL_DEFINITION_PATH, 'r', encoding='utf-8') as f:
            classification_defs = f.read()

    # 格式化决策树结果
    dt_result = skill_input['decision_tree_result']
    decision_tree_output = f"""
- 初步分类: {dt_result['category']}
- 风险级别: {dt_result['risk_level']}
- 决策路径: {' → '.join(dt_result['decision_path'])}
- 中间判断节点:
  - 威胁情报关联: {dt_result['intermediate_nodes'].get('threat_related', '未知')}
  - IP访问: {dt_result['intermediate_nodes'].get('is_ip_access', '未知')}
  - ICP备案为空: {dt_result['intermediate_nodes'].get('icp_empty', '未知')}
  - 含品牌关键词: {dt_result['intermediate_nodes'].get('has_brand_keywords', '未知')}
  - 灰黑产标签: {dt_result['intermediate_nodes'].get('has_gray_black_category', '未知')}
  - 登录表单检测: {dt_result['intermediate_nodes'].get('has_login_form', '未知')}
  - JS差异度: {dt_result['intermediate_nodes'].get('js_diff_ratio', 0):.1%}
  - YOLO/OCR为空: {dt_result['intermediate_nodes'].get('yolo_ocr_empty', '未知')}
"""

    # 浏览器分析结果
    ba = skill_input['browser_analysis']
    browser_analysis = f"""
- URL: {skill_input['web_info']['url']}
- 品牌主体: {skill_input['brand_owner']}
- 登录表单检测:
  - 是否有登录表单: {ba['has_login_form']}
  - 表单数量: {ba['login_form_count']}
  - 表单类型: {ba['form_types']}
  - 表单风险等级: {ba['form_risk_level']}
- JS差异度分析:
  - JS开关差异度: {ba['js_diff_ratio']:.1%}
  - 内容相似度: {ba['content_similarity']:.1%}
  - 文本是否相同: {ba['text_identical']}
  - 链接数量变化: {ba['link_count_diff']}
  - 表单数量变化: {ba['form_count_diff']}
"""

    # 关键词匹配
    keyword_info = f"""
- 品牌关键词匹配:
  - 命中的关键词: {skill_input['brand_keywords_matched']}
  - 匹配置信度: {skill_input['brand_match_confidence']}
"""

    # 黑数据结果
    wd_result = skill_input.get('wd_result', {})
    wd_info = f"""
### 云端黑数据
- 查询结果: {wd_result.get('category_name', '未检出') if wd_result else '无数据'}
- 建议级别: {wd_result.get('suggested_level', '未知') if wd_result else '未知'}
- 是否黑数据: {wd_result.get('is_wd_type', False) if wd_result else False}
- 原始数据:
  - Level: {wd_result.get('raw_data', {}).get('level', 'N/A') if wd_result else 'N/A'}
  - ST: {wd_result.get('raw_data', {}).get('st', 'N/A') if wd_result else 'N/A'}
  - SC: {wd_result.get('raw_data', {}).get('sc', 'N/A') if wd_result else 'N/A'}
  - SSC: {wd_result.get('raw_data', {}).get('ssc', 'N/A') if wd_result else 'N/A'}
  - IsBlack: {wd_result.get('raw_data', {}).get('is_black', False) if wd_result else False}
  - IsPhishing: {wd_result.get('raw_data', {}).get('is_phishing', False) if wd_result else False}
  - PhishingDetail: {wd_result.get('raw_data', {}).get('phishing_detail', 'N/A') if wd_result else 'N/A'}
""" if wd_result else "\n### 云端黑数据\n- 查询结果: 无数据或查询失败\n"

    # MCP 结果
    mcp_result = skill_input.get('mcp_result', {})
    mcp_info = ""
    if mcp_result and mcp_result.get('code') == 200:
        data = mcp_result.get('data', {})
        overall_score = data.get('overall_summary', {}).get('score', 'N/A')
        mcp_info = f"""
### 威胁情报（MCP）
- 综合评分: {overall_score}
- 详细评分:"""
        for key, value in data.items():
            if key != 'overall_summary' and isinstance(value, dict):
                score = value.get('score', 'N/A')
                summary = value.get('summary', '')[:50] if value.get('summary') else ''
                mcp_info += f"\n  - {key}: {score} ({summary})"
    else:
        mcp_info = "\n### 威胁情报（MCP）\n- 查询结果: 无数据或查询失败"

    # 构建完整prompt
    full_prompt = f"""# Web威胁分类研判任务

## 任务背景

你需要对以下网页进行威胁分类研判。决策树已输出初步分类结果，请结合云端黑数据和威胁情报进行复核和最终判决。

**权重说明**：
- 决策树分类结果：权重最高（主判断依据）
- 云端黑数据：辅助参考（如检出恶意类型可提升置信度）
- 威胁情报：辅助参考（综合评分和细分维度评分供参考）

## 输入信息

### 决策树输出结果
{decision_tree_output}

### 浏览器动态分析结果
{browser_analysis}

{keyword_info}

{wd_info}

{mcp_info}

### 分类定义参考
{classification_defs[:3000] if classification_defs else '（分类定义文件未找到）'}

## 研判要求

1. 以决策树分类结果为主，黑数据和威胁情报结果为辅进行综合研判
2. 对照上述分类定义
3. 分析决策树输出是否合理
4. 考虑判定边界和易混淆区分
5. 高危分类优先于低危分类
6. **重要：final_classification必须从以下标准分类中选择，不要自定义分类**：
   - 仿冒网站、钓鱼欺诈、商标滥用、品牌侵权
   - 疑似政务合作、疑似商务合作、其他、无害网站
   - ICP滥用、疑似暴露资产、舆论投诉

## 输出格式

请按以下JSON格式输出研判结果，**只能使用上述标准分类**：

```json
{{
  "final_classification": "标准分类名称",
  "confidence": "高/中/低",
  "risk_level": "高危/中危/低危",
  "reasoning": ["判断理由1", "判断理由2", ...],
  "alternative_classifications": ["备选分类"],
  "key_evidence": ["关键证据1", "关键证据2"]
}}
```
"""

    return full_prompt


def _get_default_template() -> str:
    """默认模板"""
    return """# Web威胁分类研判任务

## 任务背景
你需要对以下网页进行威胁分类研判。

## 研判要求
1. 高危分类优先于低危分类
2. 严格按照分类定义判定
3. 研判依据必须能关联到参考文档
4. 当信息不足时，置信度应为"低"

## 输出格式
请按以下JSON格式输出研判结果：
```json
{
  "final_classification": "分类名称",
  "confidence": "高/中/低",
  "risk_level": "高危/中危/低危",
  "reasoning": ["判断理由1", "判断理由2"],
  "alternative_classifications": ["备选分类"],
  "key_evidence": ["关键证据1", "关键证据2"]
}
```
"""


# ====================== Gemma本地模型配置 ======================
Gemma模型配置 = {
    "base_url": "http://10.177.125.115:8000/v1",
    "model_name": "gemma-local"
}


# ====================== MiniMax API（已注释） ======================
# async def call_minimax_api(prompt: str, api_key: str = None) -> str:
#     """调用MiniMax API进行Skill研判"""
#     import aiohttp
#     import json
#
#     if api_key is None:
#         api_key = os.environ.get('MINIMAX_API_KEY', '')
#
#     if not api_key:
#         config_path = _current_dir / 'config' / 'api_keys.json'
#         if config_path.exists():
#             with open(config_path, 'r', encoding='utf-8') as f:
#                 config = json.load(f)
#                 api_key = config.get('minimax_api_key', '')
#
#     if not api_key:
#         return '{"error": "No API key provided"}'
#
#     url = "https://api.minimax.chat/v1/text/chatcompletion_v2"
#
#     headers = {
#         "Authorization": f"Bearer {api_key}",
#         "Content-Type": "application/json"
#     }
#
#     payload = {
#         "model": "MiniMax-M2.7-highspeed",
#         "messages": [
#             {"role": "user", "content": prompt}
#         ],
#         "max_tokens": 2048
#     }
#
#     try:
#         async with aiohttp.ClientSession() as session:
#             async with session.post(url, headers=headers, json=payload) as resp:
#                 if resp.status != 200:
#                     error_text = await resp.text()
#                     return f'{{"error": "API error {resp.status}: {error_text}"}}'
#
#                 result = await resp.json()
#                 if 'choices' in result and len(result['choices']) > 0:
#                     return result['choices'][0]['message']['content']
#                 elif 'error' in result:
#                     return f'{{"error": "{result["error"]}"}}'
#                 else:
#                     return json.dumps(result)
#     except Exception as e:
#         return f'{{"error": "{str(e)}"}}'


# ====================== Gemma API ======================

async def call_gemma_api(prompt: str) -> str:
    """调用本地Gemma模型进行Skill研判"""
    import aiohttp
    import json

    url = f"{Gemma模型配置['base_url']}/chat/completions"
    headers = {"Content-Type": "application/json"}
    payload = {
        "model": Gemma模型配置['model_name'],
        "messages": [
            {"role": "system", "content": "你是一个Web威胁分类专家，只输出JSON格式结果。"},
            {"role": "user", "content": prompt}
        ],
        "temperature": 0.1,
        "max_tokens": 2048
    }

    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(url, headers=headers, json=payload, timeout=aiohttp.ClientTimeout(total=120)) as resp:
                if resp.status != 200:
                    error_text = await resp.text()
                    return f'{{"error": "API error {resp.status}: {error_text}"}}'

                result = await resp.json()
                if 'choices' in result and len(result['choices']) > 0:
                    return result['choices'][0]['message']['content']
                elif 'error' in result:
                    return f'{{"error": "{result["error"]}"}}'
                else:
                    return json.dumps(result)
    except Exception as e:
        return f'{{"error": "{str(e)}"}}'


async def call_claude_api(prompt: str, api_key: str = None) -> str:
    """调用本地Gemma模型进行Skill研判"""
    return await call_gemma_api(prompt)


async def process_with_skill(
    url: str,
    brand_owner: str,
    api_key: str = None,
    **kwargs
) -> Dict[str, Any]:
    """
    完整的威胁分类流程：决策树 + 浏览器检测 + Skill研判

    参数:
        url: 待检测URL
        brand_owner: 保护的品牌主体
        api_key: MiniMax API密钥（可选）
        **kwargs: 其他参数

    返回:
        包含决策树结果和Skill研判结果的字典
    """
    print(f"\n{'='*70}")
    print(f"开始检测: {url}")
    print(f"品牌主体: {brand_owner}")
    print('='*70)

    from urllib.parse import urlparse
    host = kwargs.get('仿冒网站host', '')
    if not host:
        parsed_url = urlparse(url)
        host = parsed_url.netloc or url

    # Step 0: 查询威胁情报API用于分流决策（需要在使用决策树之前）
    print("\n[0/6] 查询威胁情报用于分流决策...")
    from rules_engine.sc_api import get_threat_intel
    threat_intel = get_threat_intel(domain=host)
    threat_level = threat_intel.get('threat_level', 0)
    print(f"      威胁情报获取完成: level={threat_level}")

    # Step 1: 使用无头浏览器获取页面数据
    print("\n[1/6] 使用无头浏览器获取页面数据...")
    result = await process_with_browser(url=url, brand_owner=brand_owner, threat_intel=threat_intel, **kwargs)
    print(f"      浏览器分析完成 - 登录表单: {result.browser_analysis.has_login_form if result.browser_analysis else 'N/A'}")
    print(f"      JS差异度: {result.browser_analysis.js_diff_ratio:.1%}" if result.browser_analysis else "")

    # Step 2: 决策树分析（已在Step1中完成）
    print(f"\n[2/6] 决策树分析...")
    print(f"      初步分类: {result.decision_tree_category}")
    print(f"      风险级别: {result.decision_tree_risk_level}")
    print(f"      决策路径: {' → '.join(result.decision_path[-5:])}")

    # Step 3: 查询云端黑数据和威胁情报
    print(f"\n[3/6] 查询云端黑数据和威胁情报...")

    # WD查询
    try:
        wd_result = query_wd(host)
        print(f"      黑数据查询完成: {wd_result.get('category_name', '未检出') if wd_result else '无数据'}")
    except Exception as e:
        wd_result = {"error": str(e)}
        print(f"      黑数据查询失败: {e}")

    # MCP查询（异步）
    try:
        mcp_result = await query_mcp_async(host, "domain")
        if mcp_result and mcp_result.get('code') == 200:
            overall = mcp_result.get('data', {}).get('overall_summary', {}).get('score', 'N/A')
            print(f"      MCP查询完成: 综合评分={overall}")
        else:
            print(f"      MCP查询完成: 无数据")
    except Exception as e:
        mcp_result = {"error": str(e)}
        print(f"      MCP查询失败: {e}")

    # Step 4: 构建Skill输入
    print(f"\n[4/6] 构建Skill研判输入...")
    skill_input = build_skill_input(result, wd_result, mcp_result)
    skill_prompt = build_skill_prompt(skill_input)

    # Step 5: 调用Skill研判
    print(f"\n[5/6] 调用Skill进行最终研判...")
    try:
        skill_result = await call_claude_api(skill_prompt, api_key)
        print(f"      Skill研判完成")
    except Exception as e:
        skill_result = f'{{"error": "{str(e)}"}}'
        print(f"      Skill研判失败: {e}")

    # 解析Skill结果
    try:
        skill_json = json.loads(skill_result.replace('```json', '').replace('```', '').strip())
    except:
        skill_json = {"raw_output": skill_result}

    # 打印Skill研判结果
    print(f"      最终分类: {skill_json.get('final_classification', 'N/A')}")
    print(f"      置信度: {skill_json.get('confidence', 'N/A')}")
    print(f"      风险级别: {skill_json.get('risk_level', 'N/A')}")
    reasoning = skill_json.get('reasoning', [])
    if reasoning:
        for r in reasoning[:3]:
            print(f"        • {r[:80]}{'...' if len(r) > 80 else ''}")

    # 汇总结果
    final_result = {
        "url": url,
        "brand_owner": brand_owner,
        "detection_time": result.detection_time,

        # 决策树结果
        "decision_tree": {
            "category": result.decision_tree_category,
            "risk_level": result.decision_tree_risk_level,
            "decision_path": result.decision_path,
            "intermediate_nodes": result.intermediate_nodes,
        },

        # 浏览器分析结果
        "browser_analysis": {
            "has_login_form": result.browser_analysis.has_login_form if result.browser_analysis else False,
            "login_form_count": result.browser_analysis.login_form_count if result.browser_analysis else 0,
            "form_types": result.browser_analysis.form_types if result.browser_analysis else [],
            "js_diff_ratio": result.browser_analysis.js_diff_ratio if result.browser_analysis else 0,
            "content_similarity": result.browser_analysis.content_similarity if result.browser_analysis else 1.0,
        },

        # 云端黑数据
        "wd_result": wd_result,

        # 威胁情报
        "mcp_result": mcp_result,

        # Skill研判结果
        "skill_judgment": skill_json,

        # 原始数据
        "raw_data": {
            "threat_intel": result.threat_intel,
            "brand_keywords_matched": result.brand_keywords_matched,
            "form_detection_report": result.form_detection_report,
            "js_diff_report": result.js_diff_report,
        }
    }

    return final_result


async def process_batch_with_skill(
    items: list,
    api_key: str = None
) -> list:
    """批量处理URL"""
    results = []

    for i, item in enumerate(items):
        print(f"\n处理进度: {i+1}/{len(items)}")
        result = await process_with_skill(
            url=item.get('url', '') or item.get('URL', ''),
            brand_owner=item.get('brand_owner', '') or item.get('保护的品牌主体', ''),
            api_key=api_key,
            **{k: v for k, v in item.items()
               if k not in ['url', 'URL', 'brand_owner', '保护的品牌主体']}
        )
        results.append(result)

    return results


def main():
    """命令行入口"""
    import argparse

    parser = argparse.ArgumentParser(description='威胁分类 - 决策树 + Skill研判（Gemma本地模型）')
    parser.add_argument('url', help='待检测的URL')
    parser.add_argument('--brand', '-b', required=True, help='保护的品牌主体')
    parser.add_argument('--api-key', '-k', help='API密钥（已不使用，保留参数兼容性）')
    parser.add_argument('--output', '-o', help='输出文件路径（JSON格式）')
    parser.add_argument('--batch', help='批量处理文件路径（JSON数组）')

    args = parser.parse_args()

    async def run():
        if args.batch:
            # 批量处理
            with open(args.batch, 'r', encoding='utf-8') as f:
                items = json.load(f)
            results = await process_batch_with_skill(items, args.api_key)
        else:
            # 单个URL处理
            results = [await process_with_skill(args.url, args.brand, args.api_key)]

        # 输出结果
        output = json.dumps(results, indent=2, ensure_ascii=False)
        if args.output:
            with open(args.output, 'w', encoding='utf-8') as f:
                f.write(output)
            print(f"\n结果已保存到: {args.output}")
        else:
            print("\n" + "="*70)
            print("最终结果:")
            print("="*70)
            for r in results:
                print(f"\nURL: {r['url']}")
                print(f"品牌: {r['brand_owner']}")
                print(f"决策树: {r['decision_tree']['category']} ({r['decision_tree']['risk_level']})")
                skill_cat = r['skill_judgment'].get('final_classification', 'N/A')
                skill_conf = r['skill_judgment'].get('confidence', 'N/A')
                print(f"Skill研判: {skill_cat} (置信度: {skill_conf})")

    asyncio.run(run())


if __name__ == '__main__':
    main()