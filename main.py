#!/usr/bin/env python3
"""
Web威胁分类系统 - 主入口

用法：
    python main.py --mode full --url <URL> --brand <品牌> [--output-file <文件>]
    python main.py --mode tree --test-data <文件> [--output-file <文件>]
    python main.py --mode full --batch <文件> [--output-file <文件>]

两种运行模式：
    --mode tree    仅决策树（快速，无需API密钥）
    --mode full    决策树+黑数据+MCP+Skill研判（完整，需要API密钥）

两种输出模式：
    --output-mode accuracy    测试准确率（需要测试样本数据）
    --output-mode judgment   研判结论（真实生产环境，默认）

示例：
    # 完整模式研判单个URL（研判结论）
    python main.py -m full -u https://example.com -b "光大证券"

    # 仅决策树测试准确率
    python main.py -m tree -t test_data.json

    # 批量处理（研判结论）
    python main.py -m full --batch batch.json -o results.json
"""

import argparse
import asyncio
import json
import sys
import os
from pathlib import Path
from datetime import datetime

# 添加项目路径
_current_dir = Path(__file__).parent
sys.path.insert(0, str(_current_dir))

from rules_engine.engine import get_engine
from integration.run_with_skill import process_with_skill, process_batch_with_skill


def load_test_samples(file_path: str):
    """加载测试样本数据"""
    if not os.path.exists(file_path):
        print(f"错误: 测试数据文件不存在: {file_path}")
        return []

    import json

    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()

    # 找到JSON数组开始位置
    json_start = content.find('[')
    if json_start > 0:
        content = content[json_start:]

    # 尝试直接解析 (JSON)
    try:
        data = json.loads(content)
        if isinstance(data, list):
            return data
        elif isinstance(data, dict) and 'result_json' in data:
            return data['result_json']
    except json.JSONDecodeError:
        pass

    # 如果JSON解析失败，尝试 Python repr 格式 (更宽容)
    try:
        import ast
        data = ast.literal_eval(content)
        if isinstance(data, list):
            return data
    except Exception:
        pass

    print(f"错误: 无法解析测试数据文件格式")
    return []


def format_tree_output(result: dict) -> str:
    """格式化仅决策树输出"""
    lines = []
    lines.append("=" * 80)
    lines.append(f"检测URL: {result.get('检测URL', 'N/A')}")
    lines.append(f"关联品牌: {result.get('关联品牌主体', 'N/A')}")
    lines.append(f"风险级别初判: {result.get('风险级别初判', 'N/A')}")
    lines.append("-" * 80)
    lines.append("核心威胁特征:")
    for feat in result.get('引擎提取核心威胁特征', []):
        lines.append(f"  - {feat}")
    lines.append("-" * 80)
    lines.append(f"最终分类: {result.get('最终分类', 'N/A')}")
    lines.append(f"风险级别: {result.get('风险级别', 'N/A')}")
    lines.append("-" * 80)
    lines.append("决策路径:")
    for path in result.get('决策路径', []):
        lines.append(f"  → {path}")
    lines.append("-" * 80)
    lines.append("判定依据:")
    for reason in result.get('判定依据', {}).get('理由', []):
        lines.append(f"  • {reason}")
    lines.append("=" * 80)
    return '\n'.join(lines)


def format_judgment_output(result: dict) -> str:
    """格式化研判结论输出"""
    lines = []
    lines.append("=" * 80)
    lines.append(f"检测URL: {result.get('url', result.get('检测URL', 'N/A'))}")
    lines.append(f"关联品牌: {result.get('brand_owner', result.get('关联品牌主体', 'N/A'))}")
    lines.append("-" * 80)

    if 'decision_tree' in result:
        dt = result['decision_tree']
        lines.append("【决策树分析】")
        lines.append(f"  初步分类: {dt.get('category', 'N/A')}")
        lines.append(f"  风险级别: {dt.get('risk_level', 'N/A')}")
        lines.append(f"  决策路径: {' → '.join(dt.get('decision_path', [])[-5:])}")
    else:
        lines.append(f"  最终分类: {result.get('最终分类', 'N/A')}")
        lines.append(f"  风险级别: {result.get('风险级别', 'N/A')}")

    if 'wd_result' in result and result['wd_result']:
        wd = result['wd_result']
        lines.append("-" * 80)
        lines.append("【黑数据】")
        lines.append(f"  分类: {wd.get('category_name', 'N/A')}")
        lines.append(f"  级别: {wd.get('suggested_level', 'N/A')}")

    if 'mcp_result' in result and result['mcp_result']:
        sc = result['mcp_result']
        if sc.get('code') == 200:
            score = sc.get('data', {}).get('overall_summary', {}).get('score', 'N/A')
            lines.append("-" * 80)
            lines.append("【威胁情报】")
            lines.append(f"  综合评分: {score}")

    if 'skill_judgment' in result:
        sj = result['skill_judgment']
        lines.append("-" * 80)
        lines.append("【Skill研判】")
        lines.append(f"  最终分类: {sj.get('final_classification', 'N/A')}")
        lines.append(f"  置信度: {sj.get('confidence', 'N/A')}")
        lines.append(f"  风险级别: {sj.get('risk_level', 'N/A')}")
        lines.append("  理由:")
        for reason in sj.get('reasoning', []):
            lines.append(f"    • {reason}")

    lines.append("=" * 80)
    return '\n'.join(lines)


def validate_args(args):
    """校验命令行参数"""
    errors = []

    if args.mode == 'tree':
        # 仅决策树模式
        if args.output_mode == 'accuracy':
            if not args.test_data:
                errors.append("错误: --output-mode accuracy 需要配合 --test-data 参数使用")
            elif not os.path.exists(args.test_data):
                errors.append(f"错误: 测试数据文件不存在: {args.test_data}")
    else:
        # 完整模式
        if args.test_data:
            # 带测试数据时，走 accuracy 模式，不需要 url/batch
            if not os.path.exists(args.test_data):
                errors.append(f"错误: 测试数据文件不存在: {args.test_data}")
        else:
            if not args.url and not args.batch:
                errors.append("错误: 完整模式需要提供 --url 或 --batch 参数")
            if args.url and args.batch:
                errors.append("错误: --url 和 --batch 不能同时使用")
            if args.url and not args.brand:
                errors.append("错误: 使用 --url 时必须指定 --brand")

    return errors


async def run_tree_mode_accuracy(args):
    """仅决策树模式 - 测试准确率（含浏览器抓取）"""
    print("=" * 80)
    print("Web威胁分类 - 仅决策树模式 (测试准确率)")
    print("=" * 80)
    print(f"测试数据: {args.test_data}")
    print()

    samples = load_test_samples(args.test_data)
    print(f"加载测试样本: {len(samples)}条")
    print()

    if not samples:
        print("错误: 未找到有效的测试样本数据")
        return

    results = []

    for i, sample in enumerate(samples):
        url = sample.get('URL', 'N/A')[:60]
        print(f"[{i+1}/{len(samples)}] 处理: {url}...")

        try:
            from integration.runtime import process_with_browser
            runtime_result = await process_with_browser(
                url=sample.get('URL', ''),
                brand_owner=sample.get('保护的品牌主体', ''),
                **{k: v for k, v in sample.items()
                   if k not in ['URL', 'url', '保护的品牌主体', 'brand_owner']}
            )
            # 转换为与 engine.process() 一致的 dict 格式
            result = {
                '检测URL': runtime_result.url,
                '关联品牌主体': runtime_result.brand_owner,
                '最终分类': runtime_result.decision_tree_category,
                '风险级别': runtime_result.decision_tree_risk_level,
                '决策路径': runtime_result.decision_path,
            }
            results.append(result)

            expected = sample.get('威胁分类', 'N/A')
            top1 = runtime_result.decision_tree_category
            hit_mark = "✓" if top1 == expected else "✗"
            print(f"      预期: {expected} | Top1: {top1} {hit_mark}")

        except Exception as e:
            print(f"      错误: {e}")

    # 统计准确率
    print()
    print("=" * 80)
    total = len(results)
    if total > 0 and '威胁分类' in samples[0]:
        correct = sum(1 for r, s in zip(results, samples)
                      if r.get('最终分类') == s.get('威胁分类'))
        accuracy = correct / total * 100
        print(f"处理完成: {total}条 | Top1准确率: {correct}/{total} ({accuracy:.1f}%)")
    else:
        print(f"处理完成: {total}条")
    print("=" * 80)

    # 保存结果
    if args.output_file:
        output_dir = _current_dir / 'output'
        output_dir.mkdir(exist_ok=True)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_path = output_dir / f'tree_only_{timestamp}.json'
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(results, f, ensure_ascii=False, indent=2)
        print(f"\n结果已保存: {output_path}")


def get_default_output_path(prefix: str = "result") -> Path:
    """获取默认输出路径"""
    output_dir = _current_dir / 'output'
    output_dir.mkdir(exist_ok=True)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    return output_dir / f'{prefix}_{timestamp}.json'


async def run_full_mode(args):
    """完整模式 - 决策树+黑数据+MCP+Skill研判"""
    print("=" * 80)
    print("Web威胁分类 - 完整模式 (决策树+黑数据+MCP+Skill)")
    print("=" * 80)

    output_path = args.output_file or str(get_default_output_path('full'))

    # Accuracy 模式：使用测试数据文件
    if args.test_data:
        samples = load_test_samples(args.test_data)
        print(f"测试数据: {args.test_data}")
        print(f"加载测试样本: {len(samples)}条")
        print()

        if not samples:
            print("错误: 未找到有效的测试样本数据")
            return

        results = []
        for i, sample in enumerate(samples):
            url = sample.get('URL', 'N/A')[:60]
            print(f"[{i+1}/{len(samples)}] 处理: {url}...")

            try:
                result = await process_with_skill(
                    url=sample.get('URL', ''),
                    brand_owner=sample.get('保护的品牌主体', ''),
                    api_key=args.api_key,
                    **{k: v for k, v in sample.items()
                       if k not in ['URL', 'url', '保护的品牌主体', 'brand_owner']}
                )
                results.append(result)

                expected = sample.get('威胁分类', 'N/A')
                top1 = result.get('decision_tree', {}).get('category', 'N/A')
                hit_mark = "✓" if top1 == expected else "✗"
                print(f"      预期: {expected} | Top1: {top1} {hit_mark}")

            except Exception as e:
                print(f"      错误: {e}")

        # 统计准确率
        print()
        print("=" * 80)
        total = len(results)
        if total > 0 and '威胁分类' in samples[0]:
            correct = sum(1 for r, s in zip(results, samples)
                          if r.get('decision_tree', {}).get('category') == s.get('威胁分类'))
            accuracy = correct / total * 100
            print(f"处理完成: {total}条 | Top1准确率: {correct}/{total} ({accuracy:.1f}%)")
        else:
            print(f"处理完成: {total}条")
        print("=" * 80)

        if args.output_file:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(results, f, ensure_ascii=False, indent=2)
            print(f"\n结果已保存: {output_path}")
        return

    # Judgment 模式：正常研判
    if args.batch:
        print(f"批量处理: {args.batch}")
        with open(args.batch, 'r', encoding='utf-8') as f:
            items = json.load(f)
        print(f"共 {len(items)} 条数据")
        print()

        results = await process_batch_with_skill(items, args.api_key)

        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(results, f, ensure_ascii=False, indent=2)
        print(f"\n结果已保存: {output_path}")
        print("\n研判结论:")
        for r in results:
            print(format_judgment_output(r))

    elif args.url:
        print(f"URL: {args.url}")
        print(f"品牌: {args.brand}")
        print()

        result = await process_with_skill(args.url, args.brand, args.api_key)

        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(result, f, ensure_ascii=False, indent=2)
        print(f"\n结果已保存: {output_path}")
        print("\n研判结论:")
        print(format_judgment_output(result))


def create_parser():
    """创建命令行解析器"""
    parser = argparse.ArgumentParser(
        prog='main.py',
        description='Web威胁分类系统 - 网页数字风险研判平台',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
运行示例：

  # 仅决策树模式（快速，无需API密钥）
  python main.py -m tree -t test_data.json

  # 完整模式 - 单个URL研判
  python main.py -m full -u https://example.com -b "光大证券"

  # 完整模式 - 批量处理
  python main.py -m full --batch batch.json -o results.json

  # 完整模式 - 指定API密钥
  python main.py -m full -u https://example.com -b "光大证券" -k <API密钥>
"""
    )

    # 运行模式
    parser.add_argument(
        '-m', '--mode',
        choices=['tree', 'full'],
        default='full',
        help='运行模式: tree=仅决策树, full=完整模式 (默认: full)'
    )

    # 输出模式
    parser.add_argument(
        '-om', '--output-mode',
        choices=['accuracy', 'judgment'],
        default='judgment',
        help='输出模式: accuracy=测试准确率, judgment=研判结论 (默认: judgment)'
    )

    # 目标指定（互斥）
    target_group = parser.add_mutually_exclusive_group()
    target_group.add_argument(
        '-u', '--url',
        metavar='URL',
        help='待检测的单个URL'
    )
    target_group.add_argument(
        '-b', '--batch',
        metavar='FILE',
        help='批量处理文件路径 (JSON数组)'
    )

    # 品牌主体
    parser.add_argument(
        '-bnd', '--brand',
        metavar='品牌',
        help='保护的品牌主体 (使用 --url 时必填)'
    )

    # 测试数据
    parser.add_argument(
        '-t', '--test-data',
        metavar='FILE',
        help='测试数据文件路径 (tree/full 模式 + accuracy 输出模式)'
    )

    # API密钥
    parser.add_argument(
        '-k', '--api-key',
        metavar='KEY',
        help='API密钥（已迁移至本地Gemma模型，保留参数兼容性）'
    )

    # 输出文件
    parser.add_argument(
        '-o', '--output-file',
        metavar='FILE',
        help='输出结果到文件 (JSON格式)'
    )

    # 版本
    parser.add_argument(
        '-v', '--version',
        action='version',
        version='%(prog)s 1.2.0'
    )

    return parser


def main():
    parser = create_parser()
    args = parser.parse_args()

    # 参数校验
    errors = validate_args(args)
    if errors:
        for error in errors:
            print(error)
        print()
        parser.print_help()
        sys.exit(1)

    # 执行
    if args.mode == 'tree':
        asyncio.run(run_tree_mode_accuracy(args))
    else:
        asyncio.run(run_full_mode(args))


if __name__ == '__main__':
    main()