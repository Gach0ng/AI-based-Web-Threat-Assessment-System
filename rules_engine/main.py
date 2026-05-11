#!/usr/bin/env python3
"""
Web威胁分类规则引擎 - 主入口
加载测试样本数据，执行规则引擎，输出标准化结果
"""

import json
import sys
from pathlib import Path

# 添加父目录路径
sys.path.insert(0, str(Path(__file__).parent.parent))

from rules_engine.engine import get_engine


def load_test_samples(file_path: str = None):
    """加载测试样本数据"""
    if file_path is None:
        # 默认测试数据目录
        test_data_dir = Path(__file__).parent.parent / 'test_data'
        for f in test_data_dir.glob('*.json'):
            if '测试' in f.name or 'sample' in f.name.lower():
                file_path = str(f)
                break

    if not file_path:
        return []

    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()

    # 文件格式分析
    pos = content.find("]'")
    if pos != -1:
        content = content[:pos+1]
    else:
        json_end = content.rfind(']')
        content = content[:json_end+1]

    json_start = content.find('[')
    if json_start > 0:
        content = content[json_start:]

    content = content.replace('description=\\"', 'description="')
    content = content.replace('\\"', '"')

    try:
        data = json.loads(content)
    except json.JSONDecodeError as e:
        print(f"JSON解析失败: {e}")
        return []

    if isinstance(data, list):
        return data
    elif isinstance(data, dict) and 'result_json' in data:
        return data['result_json']

    return []


def format_output(result: dict) -> str:
    """格式化输出"""
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
    lines.append("10类威胁全量评分:")
    scores = result.get('10类威胁全量评分结果', {})
    for cat, score in sorted(scores.items(), key=lambda x: -x[1]):
        lines.append(f"  {cat}: {score}")
    lines.append("-" * 80)
    lines.append("剪枝后候选分类集:")
    for cand in result.get('剪枝后候选分类集', []):
        lines.append(f"  [{cand.get('风险级别', 'N/A')}] {cand.get('分类名称')}: {cand.get('评分')}")
        if cand.get('说明'):
            lines.append(f"    说明: {cand.get('说明')}")
    lines.append("-" * 80)
    lines.append(f"剪枝策略: {result.get('剪枝策略说明', 'N/A')}")
    lines.append("-" * 80)
    lines.append("扩展威胁情报:")
    for intel in result.get('扩展威胁情报', []):
        lines.append(f"  - 类型: {intel.get('情报类型')}, 关联: {intel.get('存在关联')}, 等级: {intel.get('威胁等级')}")
    lines.append("=" * 80)
    lines.append("")

    if '_验证信息' in result:
        verify = result['_验证信息']
        lines.append("【验证信息】")
        lines.append(f"  预期分类: {verify.get('预期分类')}")
        lines.append(f"  Top1候选: {verify.get('Top1候选')}")
        lines.append(f"  预期在Top3: {verify.get('预期是否在Top3')}")
        lines.append("=" * 80)
        lines.append("")

    return '\n'.join(lines)


def main():
    """主函数"""
    print("Web威胁分类规则引擎启动...")
    print()

    # 加载测试样本
    samples = load_test_samples()
    print(f"加载测试样本: {len(samples)}条")
    print()

    # 获取引擎
    engine = get_engine()

    # 处理每条样本
    results = []
    for i, sample in enumerate(samples):
        print(f"处理样本 {i+1}/{len(samples)}: {sample.get('URL', 'N/A')[:60]}...")

        try:
            result = engine.process(sample)
            results.append(result)

            # 打印验证信息
            if '_验证信息' in result:
                verify = result['_验证信息']
                top1 = verify.get('Top1候选', 'N/A')
                expected = verify.get('预期分类', 'N/A')
                in_top3 = verify.get('预期是否在Top3')

                hit_mark = "✓" if top1 == expected else "✗"
                top3_mark = "✓" if in_top3 else "✗"

                print(f"  预期: {expected} | Top1: {top1} {hit_mark} | Top3包含: {top3_mark}")

        except Exception as e:
            print(f"  处理失败: {e}")
            import traceback
            traceback.print_exc()

    print()
    print("=" * 80)
    print(f"处理完成: {len(results)}/{len(samples)}条")
    print("=" * 80)

    # 保存结果
    output_path = Path(__file__).parent / 'output' / 'results.json'
    output_path.parent.mkdir(exist_ok=True)

    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(results, f, ensure_ascii=False, indent=2)

    print(f"结果已保存: {output_path}")

    # 打印详细结果
    print()
    print("详细结果:")
    print()
    for result in results:
        print(format_output(result))


if __name__ == '__main__':
    main()