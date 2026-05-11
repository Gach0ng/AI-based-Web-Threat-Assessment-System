# 评估可视化配置

## 目录说明

本目录用于评估可视化展示Claude的研判结果。

## 功能说明

eval-viewer用于展示：
- 候选类别及分数
- 最终分类结果
- 研判依据
- 风险等级
- 与标准样本的对比

## 文件说明

- `generate_review.py` - 评估结果生成脚本
- `viewer_config.json` - 可视化配置

## 使用说明

```bash
python generate_review.py <workspace>/iteration-N --skill-name "threat_classification"
```

## 配置说明

viewer_config.json包含以下配置项：
- skill_name: 技能名称
- display_fields: 需要展示的字段
- color_scheme: 风险等级颜色方案
