# 研判提示词模板

## 模板说明

本模板用于引导Claude按Skill标准进行威胁分类研判。

## 使用方式

当用户请求对网页进行威胁分类研判时，使用以下提示词模板：

```
# Web威胁分类研判任务

## 任务背景

你需要对以下网页进行威胁分类研判，基于硬编码规则输出的候选类别+分数，结合专家知识做出最终判决。

## 输入信息

### 候选类别及分数
{candidate_categories}

### 网页基础信息
- URL：{url}
- 网页标题：{title}
- ICP备案主体：{icp_subject}
- 域名信息：{domain_info}
- 网页内容摘要：{content}
- 保护的品牌主体：{brand_owner}

## 研判要求

1. 对照SKILL.md中的全分类研判标准
2. 分析每个候选类别是否符合定义
3. 考虑判定边界和易混淆区分
4. 参考辅助佐证依据
5. 输出结构化研判结果

## 输出格式

请按以下JSON格式输出研判结果：

```json
{
  "final_classification": "分类名称",
  "confidence": "高/中/低",
  "risk_level": "高危/中危/低危/未知",
  "reasoning": "研判依据说明",
  "alternative_classifications": ["备选分类"],
  "reference_sources": ["参考依据"]
}
```

## 研判原则

- 高危分类优先于低危分类
- 严格按照分类定义判定
- 研判依据必须能关联到参考文档
- 当信息不足时，置信度应为"低"
```

## 字段说明

| 占位符 | 说明 |
|--------|------|
| {candidate_categories} | 候选类别列表，格式为 [{"category":"名称","score":分数}] |
| {url} | 待研判网页的URL |
| {title} | 网页标题 |
| {icp_subject} | ICP备案主体 |
| {domain_info} | 域名注册信息 |
| {content} | 网页内容摘要（OCR/YOLO/源码等） |
| {brand_owner} | 被保护的品牌主体名称 |
