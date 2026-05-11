# Web威胁分类系统

网页数字风险研判平台

## 简介

Web威胁分类系统是一个综合性的网页数字风险研判平台，整合了以下模块：

| 模块 | 说明 |
|------|------|
| 决策树引擎 | 基于流程图的纯条件判断逻辑 |
| 云端黑数据 | 查询URL的黑类型数据 |
| 威胁情报(MCP) | IOC多维分析接口 |
| 浏览器动态检测 | JS渲染对比分析 |
| 品牌销售检测 | 识别冒用机构名义的违规金融销售 |
| Skill研判 | 基于本地Gemma模型的智能研判 |

---

## 安装

### 依赖安装

```bash
pip install -r requirements.txt
playwright install chromium
```

### 目录结构

```
/root/Project/WEB/
├── config/                    # 配置文件
│   ├── api_keys.json         # API密钥配置
│   ├── brand_keywords/       # 品牌关键词泛化字典
│   ├── gray_black_keywords/  # 灰黑产关键词字典
│   ├── sales_keywords/       # 品牌销售关键词
│   └── decision_tree/        # 决策树规则配置（热加载）
│       └── rule.json         # 决策树规则定义
├── rules_engine/             # 决策树规则引擎
├── browser_crawling/         # 动态渲染网页抓取
├── sales_detection/          # 品牌销售检测
├── Blacklist/                       # 云端黑数据
├── MCP/                   # MCP客户端
├── integration/              # 集成模块
├── test_data/               # 测试数据
├── output/                   # 输出结果
├── skill/                    # Skill定义
├── main.py                   # 主入口
└── requirements.txt          # 依赖
```

---

## 命令行用法

### 语法

```bash
python main.py [模式参数] [选项]
```

### 参数说明

| 短参数 | 长参数 | 必填 | 说明 |
|--------|--------|------|------|
| `-m` | `--mode` | 否 | 运行模式：`tree`(仅决策树) / `full`(完整模式)，默认：`full` |
| `-om` | `--output-mode` | 否 | 输出模式：`accuracy`(测试准确率) / `judgment`(研判结论)，默认：`judgment` |
| `-u` | `--url` | 选一 | 待检测的单个URL |
| `-b` | `--batch` | 选一 | 批量处理文件路径 (JSON数组) |
| `-bnd` | `--brand` | 当用`-u`时必填 | 保护的品牌主体 |
| `-t` | `--test-data` | 否 | 测试数据文件路径（带此参数则输出 accuracy 结果，否则 judgment） |
| `-k` | `--api-key` | 否 | MiniMax API密钥 |
| `-o` | `--output-file` | 否 | 输出结果文件路径 |
| `-v` | `--version` | 否 | 显示版本号 |
| `-h` | `--help` | 否 | 显示帮助信息 |

> **说明**：`-u/--url` 和 `-b/--batch` 互斥，不可同时使用

---

### 运行模式

| 模式 | 说明 | 所需参数 |
|------|------|----------|
| `tree` | 决策树+浏览器抓取+威胁情报分流（快速，无需API密钥） | `-t` 测试数据文件 |
| `full` | 决策树+浏览器抓取+威胁情报分流+黑数据+MCP+Skill（完整） | `-u URL -bnd 品牌` 或 `-b 批量文件` |

> **说明**：`tree` 模式和 `full` 模式在决策树之前的流程完全一致（威胁情报大类分流→浏览器抓取），差异仅在于 `full` 多了黑数据、MCP 情报和 Skill 研判。

---

### 输出模式

| 模式 | 说明 | 触发条件 |
|------|------|----------|
| `accuracy` | 测试准确率 | 带 `-t` 参数，对比 `威胁分类` 字段输出 Top1 准确率 |
| `judgment` | 研判结论（默认） | 不带 `-t` 参数，输出研判结论、置信度、关键证据 |

---

### 运行示例

#### 仅决策树模式（快速，无需API密钥）

```bash
# 测试准确率（对比威胁分类字段）
python main.py -m tree -t test_data/示例.json

# 研判结论（不带 -t 走 judgment 模式）
python main.py -m tree -t test_data/示例.json -om judgment
```

#### 完整模式（决策树+黑数据+MCP+Skill）

```bash
# 单个URL研判（judgment 模式）
python main.py -m full -u https://example.com -bnd "示例品牌"

# 批量处理
python main.py -m full -b batch.json -o results.json

# 测试准确率（对比威胁分类字段）
python main.py -m full -t test_data/示例.json

# 不指定输出文件时，结果默认保存到 output/full_<时间戳>.json
```

---

### 错误处理

参数缺失或冲突时，系统会给出中文错误提示：

```bash
# 缺少 brand 参数
$ python main.py -m full -u https://example.com
错误: 使用 --url 时必须指定 --brand

# url 和 batch 冲突
$ python main.py -m full -u https://example.com --batch batch.json
usage: error: argument -b/--batch: not allowed with argument -u/--url

# 缺少必要参数
$ python main.py -m tree -om accuracy
错误: --output-mode accuracy 需要配合 --test-data 参数使用
```

---

## 配置

### API密钥配置

编辑 `config/api_keys.json`：

```json
{
    "minimax_api_key": "your-minimax-key",
    "wd_api_url": "http://your-blacklist-api.example.com/api/urlcloud",
    "wd_api_key": "your-wd-key",
    "threat_mcp_server_url": "https://mcp.example.com/mcp/dimensional",
    "threat_api_key": "your-sc-key",
    "threat_salt": "your-salt",
    "threat_user": "your-user",
    "threat_api_test_url": "http://api.safe.example.com",
    "threat_api_test_appid": "your-sc-appid",
    "threat_api_test_secret": "your-sc-secret",
    "threat_level_threshold": 30
}
```

| 配置项 | 说明 |
|--------|------|
| `threat_api_test_url` | 威胁情报API接口地址 |
| `threat_api_test_appid` | 威胁情报API APPID |
| `threat_api_test_secret` | 威胁情报API密钥 |
| `threat_level_threshold` | 威胁等级阈值，>=此值走中高危研判路线 |

### 字典配置

| 目录 | 文件 | 说明 |
|------|------|------|
| `config/brand_keywords/` | `*.json` | 品牌关键词泛化字典 |
| `config/gray_black_keywords/` | `gray_black_categories.json` | 灰黑产关键词字典 |
| `config/sales_keywords/` | `financial_sales_keywords.txt` | 金融销售关键词 |
| `config/sales_keywords/` | `institution_keywords.txt` | 目标机构关键词 |
| `config/decision_tree/` | `rule.json` | **决策树规则配置（支持热加载）** |

### 决策树规则配置

决策树规则以 JSON 格式存储在 `config/decision_tree/rule.json`，支持**修改配置后无需重启程序，热加载自动生效**（约2秒延迟）。

#### 配置结构

| 字段 | 说明 |
|------|------|
| `conditions` | 条件函数注册表，定义所有可用的判断条件（bool/str/float 三种类型） |
| `nodes` | 决策树节点图，包含条件节点（condition/in_list/or_threshold）和结果节点（result） |
| `root` | 入口节点 ID |

#### 节点类型

| 类型 | 说明 |
|------|------|
| `condition` | 布尔条件判断，根据 `true_goto` / `false_goto` 跳转 |
| `in_list` | 值是否在列表中（如 `icp_subject_type in ["政府机构", "事业单位"]`） |
| `or_threshold` | 数值阈值或布尔条件的 OR 判断（如 JS差异度>50% OR 含娱乐博彩） |
| `result` | 最终结果节点，返回分类和风险级别 |

#### 增删改规则指南

**只改 `rule.json` 即可生效的**：
- 增删结果节点（改 `category` / `risk_level` / `reasons`）
- 修改跳转方向（改 `true_goto` / `false_goto`）
- 修改阈值（改 `threshold`）
- 增删 `in_list` 的 `values`
- 新增节点并接入现有跳转链

**需要同时改代码的**：
- 新增条件判断逻辑 → 在 `rules_engine/conditions.py` 中实现函数并注册到 `_CONDITION_FUNCTIONS`
- 修改现有条件函数的判断规则 → 修改 `conditions.py` 中对应函数

---

## 威胁情报接口分流逻辑

系统使用威胁情报API接口（IOC Tags）进行威胁等级查询，根据level值自动分流：

### 分流规则

| 威胁等级 | 分流路线 | 说明 |
|----------|----------|------|
| level >= 30 | 中高危研判路线 | 进入完整的高危威胁研判流程 |
| level < 30 | 低危研判路线 | 进入简化的低危威胁研判流程 |

### 分流入口

- **威胁情报关联=是** → 中高危研判路线：经过ICP空/非空、YOLO/OCR、登录表单、JS差异度等多维度判断
- **威胁情报关联=否** → 低危研判路线：基于域名年龄/IP、ICP备案、标题品牌关键词等基础判断

### 威胁等级阈值

阈值定义在 `rules_engine/conditions.py`：

```python
THREAT_LEVEL_THRESHOLD = 30
```

### 威胁情报接口配置

威胁情报接口配置统一管理在 `config/api_keys.json`，代码中读取配置使用：

| 配置项 | 默认值 | 说明 |
|--------|--------|------|
| `threat_api_test_url` | http://api.safe.example.com | 威胁情报API接口地址 |
| `threat_api_test_appid` | - | APPID（必填） |
| `threat_api_test_secret` | - | 密钥（必填） |
| `threat_level_threshold` | 30 | 威胁等级阈值 |

---

## 决策树分支

### 分支1：中高危研判路线（威胁情报关联=是，level >= 30）

当威胁情报接口返回level >= 30时，走完整的高危研判流程：

```
威胁情报关联=是 → ICP备案
    ├─ ICP非空 → 标题含品牌 → 政府/事业单位 → 疑似政务合作（低危）
    │                     └─ 企业 + YOLO空 → 疑似商务合作（低危）
    │                     └─ 企业 + YOLO非空 → 商标滥用（低危）
    └─ ICP为空 → 娱乐/博彩/色情 → 仿冒网站（高危）
             ├─ 登录/表单相关 → 钓鱼欺诈（高危）
             ├─ 白名单命中 → 疑似暴露资产（中危）
             └─ 动态登录表单 + JS差异度检测 → 仿冒网站/钓鱼欺诈（高危）
```

### 分支2：低危研判路线（威胁情报关联=否，level < 30）

当威胁情报接口返回level < 30时，走简化的低危研判流程：

```
威胁情报关联=否 → 域名年龄/IP判断
    ├─ 境内且满1年 → 无害网站（低危）
    └─ 新注册或境外 → 标题含品牌 → ICP非空 → 政府/事业单位 → 疑似政务合作（低危）
                                            └─ 企业 + YOLO空 → 疑似商务合作（低危）
                                            └─ 企业 + YOLO非空 → 商标滥用（低危）
```

---

## 分类体系

### 风险级别

| 级别 | 说明 | 分类 |
|------|------|------|
| 高危 | 严重威胁 | 仿冒网站、钓鱼欺诈 |
| 中危 | 中等威胁 | 品牌侵权、疑似暴露资产 |
| 低危 | 轻微威胁 | 商标滥用、ICP滥用、疑似政务合作、疑似商务合作、舆论投诉、其他、无害网站 |

### 分类定义

**仿冒网站（高危）**

模仿机构官网或其子系统的网站，用于欺诈、假承诺、数据收集。

**钓鱼欺诈（高危）**

通过冒充机构或其客服、理财平台登录框，诱导客户输入账号/密码/银行卡信息。

**品牌侵权（中危）**

未经授权使用机构名义从事金融服务/产品（如假投资产品、假保险合同）。

**商标滥用（低危）**

未授权第三方使用机构商标、Logo、官方名称，以假"官方合作""官方理财产品"诱导客户。

**ICP滥用（低危）**

在中国市场，网站未备案或滥用金融机构名义取得/使用ICP备案号，冒充机构服务。

**疑似暴露资产（中危）**

品牌或关联组织的数字资产（如IPv4）被意外或恶意暴露在公开/半公开网络。

**疑似商务合作（低危）**

解析记录含有用户关键词、部署平台关联企业资产，注册域具有企业备案记录。

**疑似政务合作（低危）**

网站页面含有用户关键字、LOGO等数据关联企业资产，备案属性为政府机构、科研院所等。

---

## 输出说明

### 输出文件

| 模式 | 默认路径 |
|------|----------|
| tree | `output/tree_only_<时间戳>.json` |
| full | `output/full_<时间戳>.json` |

### 输出格式（JSON）

```json
{
  "url": "https://example.com",
  "brand_owner": "示例品牌",
  "detection_time": "2024-01-01T00:00:00",

  "decision_tree": {
    "category": "仿冒网站",
    "risk_level": "高危",
    "decision_path": ["威胁情报关联判定→是", "ICP备案→空", "节点5→非娱乐/博彩/色情"],
    "intermediate_nodes": {}
  },

  "browser_analysis": {
    "has_login_form": true,
    "login_form_count": 1,
    "js_diff_ratio": 0.75
  },

  "wd_result": {
    "category_name": "仿冒网站",
    "suggested_level": "黑"
  },

  "mcp_result": {
    "code": 200,
    "data": {"overall_summary": {"score": 75}}
  },

  "skill_judgment": {
    "final_classification": "仿冒网站",
    "confidence": "高",
    "risk_level": "高危",
    "reasoning": ["决策树分类为仿冒网站", "黑数据检出仿冒网站"]
  }
}
```

---

## 版本

```
main.py 1.2.0  # tree/full 模式统一走 process_with_browser，支持 -t accuracy 模式
```
