#!/usr/bin/env python3
"""
Skill研判效果校验脚本

对比Claude研判结果与样本标注，验证Skill有效性。
仅用于校验研判效果，不包含任何打分/剪枝/特征提取代码。
"""

import json
import sys
from pathlib import Path


def load_samples(samples_path: str) -> list:
    """加载测试样本数据"""
    with open(samples_path, 'r', encoding='utf-8') as f:
        return json.load(f)


def load_ground_truth(samples: list) -> dict:
    """从样本中提取标准答案"""
    ground_truth = {}
    for sample in samples:
        sample_id = sample.get('sample_id')
        if sample_id is None:
            sample_id = sample.get('url', 'unknown')
        ground_truth[sample_id] = {
            'final_classification': sample.get('ground_truth', {}).get('final_classification'),
            'confidence': sample.get('ground_truth', {}).get('confidence'),
            'risk_level': sample.get('ground_truth', {}).get('risk_level')
        }
    return ground_truth


def load_claude_results(results_path: str) -> dict:
    """加载Claude研判结果"""
    with open(results_path, 'r', encoding='utf-8') as f:
        return json.load(f)


def compare_results(ground_truth: dict, claude_results: dict) -> dict:
    """
    对比标准答案与Claude研判结果
    返回匹配情况和差异分析
    """
    comparison = {
        'total': len(ground_truth),
        'matched': 0,
        'mismatched': 0,
        'details': []
    }

    for sample_id, truth in ground_truth.items():
        if sample_id not in claude_results:
            comparison['details'].append({
                'sample_id': sample_id,
                'status': 'missing',
                'truth': truth,
                'result': None
            })
            comparison['mismatched'] += 1
            continue

        result = claude_results[sample_id]
        match = truth['final_classification'] == result.get('final_classification')

        detail = {
            'sample_id': sample_id,
            'status': 'matched' if match else 'mismatched',
            'truth': truth,
            'result': result,
            'match': match
        }

        if match:
            comparison['matched'] += 1
        else:
            comparison['mismatched'] += 1

        comparison['details'].append(detail)

    comparison['pass_rate'] = comparison['matched'] / comparison['total'] if comparison['total'] > 0 else 0

    return comparison


def print_comparison(comparison: dict):
    """打印对比结果"""
    print("=" * 60)
    print("Skill研判效果校验报告")
    print("=" * 60)
    print(f"总样本数: {comparison['total']}")
    print(f"匹配数: {comparison['matched']}")
    print(f"不匹配数: {comparison['mismatched']}")
    print(f"通过率: {comparison['pass_rate']:.2%}")
    print("=" * 60)

    for detail in comparison['details']:
        print(f"\n样本ID: {detail['sample_id']}")
        print(f"状态: {detail['status']}")
        if detail['truth']:
            print(f"标准答案: {detail['truth'].get('final_classification')} ({detail['truth'].get('risk_level')})")
        if detail['result']:
            print(f"研判结果: {detail['result'].get('final_classification')} ({detail['result'].get('risk_level')})")
            if detail['result'].get('reasoning'):
                print(f"研判依据: {detail['result'].get('reasoning')[:100]}...")