#!/usr/bin/env python3
"""
Skill导出打包脚本

将Skill完整保存至指定路径，确保Claude可正常加载。
"""

import json
import shutil
import sys
from pathlib import Path


SKILL_STRUCTURE = {
    'SKILL.md': '技能总纲',
    'agents/': '智能体配置',
    'agents/grader.md': '研判智能体',
    'assets/': '静态资源',
    'assets/prompt_template.md': '研判提示词模板',
    'assets/samples.json': '测试样本数据',
    'assets/classification_map.md': '分类图谱',
    'assets/README.md': '资源说明',
    'eval-viewer/': '评估可视化',
    'eval-viewer/README.md': '评估说明',
    'eval-viewer/viewer_config.json': '可视化配置',
    'references/': '参考文档',
    'references/威胁分类定义.txt': '威胁分类定义',
    'references/测试样本数据.json': '测试样本原始数据',
    'references/数字风险研判-判别分类_工作流报告.txt': '研判流程参考',
    'scripts/': '辅助脚本',
    'scripts/validate_skill.py': '校验脚本',
    'scripts/export_skill.py': '导出脚本',
    'LICENSE.txt': '开源许可证'
}


def verify_skill_structure(skill_path: Path) -> tuple:
    """
    验证Skill目录结构完整性
    返回 (is_valid, missing_files, extra_files)
    """
    missing_files = []
    extra_files = []

    expected_dirs = ['agents', 'assets', 'eval-viewer', 'references', 'scripts']

    for dir_name in expected_dirs:
        dir_path = skill_path / dir_name
        if not dir_path.exists():
            missing_files.append(f"{dir_name}/")
        elif not dir_path.is_dir():
            missing_files.append(f"{dir_name}/ (不是目录)")

    for file_path_str in SKILL_STRUCTURE.keys():
        if file_path_str.endswith('/'):
            continue
        file_path = skill_path / file_path_str
        if not file_path.exists():
            missing_files.append(file_path_str)

    for item in skill_path.rglob('*'):
        if item.is_file():
            rel_path = item.relative_to(skill_path)
            rel_path_str = str(rel_path).replace('\\', '/')
            if rel_path_str not in SKILL_STRUCTURE:
                extra_files.append(rel_path_str)

    is_valid = len(missing_files) == 0 and len(extra_files) == 0

    return is_valid, missing_files, extra_files


def export_skill(skill_path: Path, export_path: Path = None):
    """
    导出Skill到指定路径
    如果export_path为None，则在skill_path同级目录创建备份
    """
    if export_path is None:
        export_path = skill_path.parent / f"{skill_path.name}_export"

    if export_path.exists():
        print(f"警告: 导出路径已存在 {export_path}")
        response = input("是否覆盖? (y/n): ")
        if response.lower() != 'y':
            print("导出已取消")
            return False

    print(f"正在导出Skill至: {export_path}")

    try:
        if export_path.exists():
            shutil.rmtree(export_path)
        shutil.copytree(skill_path, export_path)
        print(f"导出成功: {export_path}")
        return True
    except Exception as e:
        print(f"导出失败: {e}")
        return False


def main():
    skill_path = Path(__file__).parent.parent

    print("=" * 60)
    print("Skill导出打包工具")
    print("=" * 60)
    print(f"Skill路径: {skill_path}")
    print()

    is_valid, missing_files, extra_files = verify_skill_structure(skill_path)

    print("目录结构验证:")
    if is_valid:
        print("  ✓ 目录结构完整")
    else:
        if missing_files:
            print(f"  ✗ 缺失文件/目录:")
            for f in missing_files:
                print(f"    - {f}")
        if extra_files:
            print(f"  ! 多余文件/目录:")
            for f in extra_files:
                print(f"    - {f}")

    print()

    export_path = None
    if len(sys.argv) > 1:
        export_path = Path(sys.argv[1])

    if export_skill(skill_path, export_path):
        print("\n导出完成!")
        return 0
    else:
        print("\n导出失败!")
        return 1


if __name__ == '__main__':
    sys.exit(main())
