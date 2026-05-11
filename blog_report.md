# Web威胁分类系统的架构设计与实现

> **免责声明**：笔者近期从事AI安全运营工作，旨在交流安全运营中心SOC建设思路与个人方案实践，不涉及任何具体企业的内部信息、技术架构或商业机密。所有技术细节均为通用性描述，如有雷同纯属巧合。

## 前言

在互联网安全领域，钓鱼网站、仿冒网站、品牌侵权等数字威胁呈现出爆发式增长态势。传统的单一检测手段——无论是基于黑白名单的规则匹配，还是基于机器学习的静态分类——都已难以应对这些复杂多变的攻击手法。攻击者们不断升级他们的技术：利用JavaScript动态加载隐藏真实内容、通过域名仿冒和同形字攻击欺骗用户、借助云服务快速变换基础设施……这些都给检测系统带来了巨大的挑战。

本文将深入剖析一个已经过实战检验的Web威胁分类系统。这个系统的核心设计理念是**多维度、多层次、智能化**：它不是简单地用一条规则判断"这是不是钓鱼网站"，而是通过决策树引擎、浏览器动态分析、威胁情报查询、品牌关键词泛化、AI模型研判等多个模块的协同工作，对每一个URL进行多角度的"问诊"，最终给出一个综合判断。

**从AI工作流的角度来看**，这是一个典型的SOC安全智能研判场景。系统整合了**Skill-Based AI Agent**范式——决策树引擎负责结构化规则判断（类似Agent的Tool），浏览器动态分析负责感知层数据采集，而最终的**Gemma本地大模型**则承担了类似Agent的推理与决策中枢角色。整个研判流程本质上是一个**AI Workflow**：威胁情报是触发条件（Condition），多维度检测是并行执行的多个节点（Node），模型研判是最终的汇聚节点（Final Node）。这种设计符合SOC场景下"机器初筛+人工复核"向"机器初筛+AI研判"演进的趋势。

整个系统大约包含6000行Python代码，分为20多个模块。接下来，我将从架构设计、核心算法、关键实现三个维度，为大家详细解读这个系统是如何工作的。

---

## 第一部分：整体架构设计

### 1.1 问题的复杂性

在讨论技术方案之前，我们先来分析一下这个问题的本质。一条URL背后可能隐藏着哪些威胁？

第一层是**域名层面的威胁**。攻击者可能会使用与正规品牌高度相似的域名，比如把字母"o"换成数字"0"，或者使用相近的拼音域名。域名本身的新旧、注册地的分布、解析记录的异常，都是判断依据。比如一个注册时间少于30天、注册地在境外、却声称是某品牌官网的域名，大概率是钓鱼站点。

第二层是**内容层面的威胁**。即使是同一个域名，攻击者也可能通过JavaScript动态加载不同的内容——在搜索引擎爬虫眼里展示正常内容，在真实用户访问时展示钓鱼页面。这种"动态伪装"技术使得传统的静态爬取完全失效。攻击者甚至可以根据访问者的IP地址、Cookie信息、User-Agent等条件，差异化地展示内容。

第三层是**行为层面的威胁**。网页中可能包含伪造的登录表单，用来窃取用户的账号密码；可能包含虚假的投资理财产品信息，用来诱骗用户转账；还可能包含冒用品牌Logo和名义的内容，用来混淆视听。这些威胁不是单纯的内容分析能够发现的，需要对页面的交互行为进行检测。

第四层是**情报维度的威胁**。全球各地的安全厂商每天都在收集和标记恶意网站，这些威胁情报如果能够实时查询，就能大幅提升检测的准确性和覆盖面。比如某个域名虽然在我们的系统中是新的，但已经被多个安全厂商标记为钓鱼站点，这就是一个强有力的证据。

面对这样一个多维度的问题，单一的技术手段显然是不够的。我们需要一个能够整合多种检测能力的系统，让不同的模块各司其职、互相印证。

### 1.2 模块化的整体架构

基于上述分析，这个系统采用了分层的模块化架构。让我们从数据流的角度来理解整个系统是如何运转的。

顶层是**命令行入口**（main.py），负责接收用户参数、解析选项、调度任务。它像是一个总调度台，根据用户指定的模式（tree或full）决定后续的工作流程。

核心层是**集成模块**（integration/run_with_skill.py），它协调各个子模块的工作。整个处理流程是严格顺序的：先查威胁情报决定要走哪条路，再用浏览器抓取页面内容，然后让决策树做出初步判断，最后根据需要调用外部情报接口和机器学习模型进行复核。

子模块包括：决策树引擎（rules_engine/）负责规则判断；浏览器管理模块（browser_crawling/）负责动态渲染；敏感元素扫描器（sensitive_element_scanner.py）负责识别登录表单和可疑脚本；差异分析器（diff_analyzer.py）负责对比JS开关前后的页面变化；灰黑名单过滤器（gray_blacklist.py）负责关键词匹配；品牌销售检测器（sales_detection/）负责发现冒用品牌销售的情况；某浏览器安全插件客户端（某浏览器安全插件/）和某态势感知平台情报客户端（某态势感知平台_MCP/）负责与外部情报系统对接；Gemma模型接口负责最终的智能研判。

各模块之间通过标准的数据结构传递信息。每个模块的输出都遵循统一的格式，便于后续模块的接收和处理。这种设计的好处是：每个模块可以独立开发、独立测试；如果某一天某个外部接口不可用了，只需要修改对应的客户端模块，其他模块无需改动。

### 1.3 两种运行模式

系统支持两种运行模式，分别对应不同的使用场景。

第一种是**Tree模式**，即仅决策树模式。这个模式只使用决策树引擎和浏览器检测，不需要任何外部API密钥。它的设计目标是**快速大规模初筛**。在面对海量URL需要处理时，先用这个模式过滤掉明显无害的URL，留下可疑的再进一步分析。这个模式的核心流程是：接收URL → 浏览器双渲染 → 提取关键特征 → 决策树判断 → 输出结果。

第二种是**Full模式**，即完整模式。这个模式会依次执行所有检测步骤：威胁情报分流、浏览器动态渲染、决策树分析、某浏览器安全插件黑数据查询、某态势感知平台情报查询、Gemma模型研判。它的设计目标是**深度精准研判**，适合对关键URL进行最终确认。这个模式的核心流程是：接收URL → 查询某态势感知平台情报（分流） → 浏览器双渲染 → 决策树初判 → 某浏览器安全插件+某态势感知平台 MCP查询 → Skill模型复核 → 输出结果。

两种模式共享相同的前端处理流程，差异只在于后续是否调用外部接口。这就好比医院的分诊台和专家门诊：分诊台快速判断你该去哪个科室，专家门诊则会详细问诊并开出检查单。

命令行使用示例：

```bash
# 仅决策树模式（快速，无需API密钥）
python main.py -m tree -t test_data/示例.json

# 完整模式 - 单个URL研判
python main.py -m full -u https://example-phishing.com -bnd "示例品牌"

# 完整模式 - 批量处理
python main.py -m full --batch batch.json -o results.json
```

---

## 第二部分：决策树引擎

### 2.1 为什么选择决策树

在众多机器学习算法中，决策树并不是最"高大上"的。但对于这个场景来说，它恰恰是最合适的选择。

首先，**可解释性是核心需求**。系统输出的每个判断结果，都需要附带完整的决策路径，解释"为什么认为是钓鱼网站"。如果用深度学习模型，解释性会大打折扣——你可能会得到一个概率值，但很难说清楚这个概率是怎么来的。而决策树的判断逻辑是透明的：每一个分支节点都对应一个明确的条件，每一个叶子节点都对应一个具体的分类。当你需要向客户解释"为什么这个网站被判定为钓鱼"时，决策树可以给你一条清晰的判断链。

其次，**规则需要频繁调整**。网络安全是一个攻防对抗的领域，新的威胁类型不断涌现，已有的规则可能需要临时收紧或放松。比如某天突然出现了一批新型钓鱼网站，特征是"使用境外IP且注册时间小于30天"，这时候你需要快速调整检测规则。决策树的结构使得规则的增删改查非常方便——改一个配置文件就够了，不需要重新训练模型。

第三，**条件判断是主要逻辑**。"ICP备案是否为空"、"域名年龄是否超过一年"、"标题是否包含品牌关键词"——这些问题本质上都是条件判断，非常适合用决策树来表达。如果用神经网络来处理这些逻辑，反而是杀鸡用牛刀。

### 2.2 配置驱动的架构

传统的决策树实现，规则是硬编码在程序里的。每次修改规则都需要：开发人员修改代码、测试人员编写用例、运维人员部署上线。这个流程至少需要几天时间，而在网络安全领域，威胁可能在几个小时内就会大规模传播。

为了解决这个问题，系统采用了**配置驱动**的设计：将决策树的节点结构、跳转逻辑、阈值参数全部提取到外部配置文件（rule.json）中，程序启动时读取配置构建内存中的决策树。

更进一步，系统支持**热加载**。当管理员修改了rule.json文件后，系统会在约2秒内检测到变更，自动重新加载配置并切换到新的决策树。这个过程是平滑的，正在进行的检测任务会继续使用旧配置，新发起任务会自动使用新配置。热加载的实现原理并不复杂：系统启动一个后台线程，定期检查配置文件的修改时间；如果发现修改时间变了，就重新解析配置文件并更新内存中的决策树对象。

这种设计带来了极大的灵活性。比如某天突然出现了一批新型钓鱼网站，特征是"使用境外IP且注册时间小于30天"，管理员只需要在rule.json中添加一个新的节点，调整跳转逻辑，整个系统就能立即识别这类新威胁。整个过程不需要停机、不需要修改代码、不需要重新部署。

### 2.3 四种节点类型

决策树的节点共有四种类型，每种类型对应不同的判断逻辑。

**第一种是条件节点（condition）**。这是最常见的节点类型，它调用一个条件函数，根据返回的布尔值决定走"真"分支还是"假"分支。比如一个节点检查"ICP备案是否为空"，返回真就跳转到"备案为空"的处理分支，返回假就跳转到"已有备案"的处理分支。条件节点的配置结构如下：

```json
{
  "id": "icp_empty_check",
  "type": "condition",
  "condition_key": "icp_empty",
  "true_goto": "icp_empty_path",
  "false_goto": "domain_with_icp"
}
```

**第二种是列表节点（in_list）**。这种节点不是做布尔判断，而是检查某个值是否属于一个特定的集合。比如检查ICP备案主体类型是否属于["政府机构", "事业单位"]，属于就走政务合作分支，不属于就走企业分支。列表节点适合处理枚举类型的条件判断。

```json
{
  "id": "icp_type_check",
  "type": "in_list",
  "condition_key": "icp_subject_type",
  "values": ["政府机构", "事业单位"],
  "true_goto": "result_gov_coop",
  "false_goto": "yolo_ocr_check"
}
```

**第三种是阈值节点（or_threshold）**。这种节点用于处理复合条件。它有两个判断标准：一个数值型的阈值（比如JS差异度是否大于50%）和一个布尔型条件（比如是否包含娱乐博彩内容）。只要满足其中任何一个，就走"真"分支。比如"JS差异度超过50%"或者"页面包含色情内容"，都认为是高危。这个设计解决了一个实际问题：单一指标可能漏报，但多个指标组合可以提高检出率。

```json
{
  "id": "js_diff_entertainment_check",
  "type": "or_threshold",
  "condition_key": "js_diff_ratio",
  "threshold": 0.5,
  "or_condition_key": "entertainment_from_browser",
  "true_goto": "result_counterfeit_high_diff",
  "false_goto": "result_phishing_high_login"
}
```

**第四种是结果节点（result）**。这是叶子节点，不再跳转到其他节点，直接返回分类结果。结果节点包含分类名称（如"仿冒网站"）、风险等级（如"高危"）、判断理由等信息。

```json
{
  "id": "result_counterfeit_high_diff",
  "type": "result",
  "category": "仿冒网站",
  "risk_level": "高危",
  "reasons": ["动态渲染包含登录表单"],
  "reason_template": ["js_diff_or_entertainment"]
}
```

### 2.4 条件函数注册机制

条件节点引用的"条件函数"存放在一个注册表中。这个注册表本质上是一个Python字典，键是条件名称，值是具体的函数引用。当决策树执行到某个条件节点时，它会根据节点配置找到对应的函数，调用执行，根据返回值决定分支。

```python
_CONDITION_FUNCTIONS: Dict[str, Any] = {
    # 核心分流
    "check_threat_related": conditions.check_threat_related,
    "check_official_whitelist": conditions.check_official_whitelist,

    # ICP相关
    "icp_empty": conditions.is_icp_empty,
    "icp_subject_type": conditions.get_icp_subject_type,

    # 品牌相关
    "brand_in_title": conditions.is_brand_in_title,
    "has_brand_sales_info": conditions.has_brand_sales_info,

    # 浏览器动态分析
    "login_form_after_dynamic": conditions.has_login_form_after_dynamic_render,
    "js_diff_ratio": conditions.get_js_diff_ratio,
    "entertainment_from_browser": conditions.is_entertainment_gambling_porn_from_browser,

    # 灰黑产检测
    "entertainment_gambling_porn": conditions.is_entertainment_gambling_porn,
    "yolo_ocr_contains_attack": conditions.yolo_ocr_contains_attack,

    # 域名分析
    "new_domain_overseas": conditions.is_new_domain_overseas,
    "domain_new_or_overseas": conditions.is_domain_new_or_overseas,
}
```

这种设计实现了两个重要目标。第一，**配置和实现分离**。rule.json中只写"condition_key": "icp_empty"，具体的判断逻辑（ICP备案号为空还是备案主体为空？空值的定义是什么？）全部封装在函数里。第二，**函数可以复用**。同一个条件函数可以被多个节点引用。比如"ICP备案是否为空"这个判断，在多个分支路径上都会被用到，但代码只需要写一次。

执行条件判断时，系统还需要处理一个技术细节：函数签名的匹配。同一个"条件函数注册表"中的函数可能有不同的参数——有些只需要parsed_data，有些只需要threat_intel，还有些需要两者。系统通过inspect模块分析函数的签名，自动选择性地传递参数：

```python
sig = inspect.signature(func)
param_names = list(sig.parameters.keys())

if param_names == ["threat_intel"]:
    bool_val = func(threat_intel)
elif param_names == ["parsed_data"]:
    bool_val = func(parsed_data)
elif param_names == ["parsed_data", "threat_intel"]:
    bool_val = func(parsed_data, threat_intel)
```

### 2.5 分层分流机制

整个决策树的核心是一个**两层分流机制**。

第一层分流基于威胁情报的level值。系统会先查询态势感知API接口，获取该域名/URL的威胁等级评分。如果level大于等于30（中高危阈值），就走完整的高危研判流程；如果level小于30，就走简化的低危研判流程。这个分流的目的是合理分配资源：对于明显恶意的URL走详细流程，对于明显正常的URL走快速流程。

第二层分流基于ICP备案的状态。无论走哪条研判路线，都会检查ICP备案情况。ICP备案是中国对网站的管理制度，正规网站通常都有ICP备案，而仿冒网站往往没有备案或使用虚假备案。因此，"有ICP备案"是网站可信度的一个正面信号，"无ICP备案"则是一个负面信号。

这两层分流交叉配合，形成了决策树的主干结构。从根节点到叶子节点，最长路径经过约10个节点的判断，最短路径只需要3个节点。

### 2.6 核心条件函数实现

为了更好地理解条件函数的实际工作方式，我们来看几个关键函数的实现细节。

**威胁情报分流判断函数**是决策树的第一个关卡。它接收威胁情报数据，根据level值决定后续的研判路线：

```python
def check_threat_related(threat_intel: Dict[str, Any]) -> bool:
    """
    判断威胁情报是否关联域名
    根据threat_level分流：>=LEVEL_THRESHOLD走中高危研判路线（返回True），
                        <LEVEL_THRESHOLD走低危研判路线（返回False）
    """
    if not threat_intel.get('threat_api_available', True):
        return True  # API不可用时默认走中高危，确保安全

    threat_level = threat_intel.get('threat_level', 0)
    return threat_level >= LEVEL_THRESHOLD
```

这个函数的设计体现了**安全优先**的原则：当威胁情报接口不可用时，默认走中高危路线，进行更严格的检查。虽然这可能会增加一些误报，但避免了漏报高危威胁的风险。

**ICP备案判断函数**检查网站是否具有合法的ICP备案：

```python
def is_icp_empty(parsed_data: Dict[str, Any]) -> bool:
    """ICP备案号/ICP备案主体是否为空"""
    icp_no = parsed_data.get('ICP备案号', '')
    icp_subject = parsed_data.get('ICP备案主体', '')

    # 多种可能的空值表示
    empty_values = ['', '无', 'None', 'null', '暂无', None]

    return icp_no in empty_values or icp_subject in empty_values
```

注意这里同时检查了"备案号"和"备案主体"两个字段。有些网站可能有备案号但备案主体是空的，这种情况下也应该视为异常。

**品牌关键词提取函数**负责从品牌名称中提取可用于匹配的核心词：

```python
def _extract_brand_keywords(brand_owner: str) -> List[str]:
    """提取品牌关键词 - 提取2-4字的中文词组合和3字以上的英文词"""
    keywords = []

    # 过滤无意义组合，如"中国"、"公司"等常见词
    filtered_words = {
        '中国', '国人', '民有', '有限', '限公', '公司', '团有', '集团',
        '有公司', '公司有', '司有限', '无限', '团有', '有集团', '有限公司',
    }

    # 提取2-4字中文词
    for length in [2, 3, 4]:
        for i in range(len(brand_owner) - length + 1):
            word = brand_owner[i:i+length]
            if re.match(r'^[\u4e00-\u9fff]+$', word):  # 纯中文
                # 过滤无意义的2字组合和常见单字
                if length == 2 and (word in filtered_words or word in ['的', '是', '在', '了']):
                    continue
                keywords.append(word)

    # 提取英文词
    english_words = re.findall(r'[a-zA-Z]{3,}', brand_owner)
    keywords.extend([w.lower() for w in english_words])

    # 去重保持顺序
    seen = set()
    unique = []
    for kw in keywords:
        if kw not in seen and len(kw) >= 2:
            seen.add(kw)
            unique.append(kw)

    return unique
```

例如"示例证券"会提取出：['示例', '示例证', '证券', '示例证券']等。注意这里会过滤掉"公司"这类无意义的常见词，同时保留"示例"、"证券"等有区分度的词。

**灰黑产标签匹配函数**用于检测页面内容是否涉及已知的灰黑产类别：

```python
def has_gray_black_category(parsed_data: Dict[str, Any], categories: List[str]) -> bool:
    """是否命中灰黑产关键字分类"""
    # 组合多源文本进行匹配
    text_content = _get_combined_text(parsed_data)
    matched = gray_filter.match_text_content(text_content)

    # 误报模式过滤
    false_positive_patterns = {
        'sm', '91', 'xxx', 'tx', 'ico', 'line', 'wv', 'defi', 'sto',
        'wap', 'app', 'web', 'net', 'com', 'org', 'gov', 'edu',
        'vip', 'max', 'min', 'add', 'del', 'edit', 'save', 'new',
    }

    filtered_matches = []
    for m in matched:
        keyword = m['matched_keyword'].lower()
        # 过滤短字母数字误报
        if keyword in false_positive_patterns:
            continue
        # 对3字符以内的字母数字，检查是否作为独立词出现
        if len(keyword) <= 3 and keyword.isalnum():
            pattern = r'(?:^|[^a-zA-Z0-9])' + re.escape(keyword) + r'(?:$|[^a-zA-Z0-9])'
            if not re.search(pattern, text_content, re.IGNORECASE):
                continue
        filtered_matches.append(m)

    # 检查是否命中目标类别
    filtered_categories = {m['category'] for m in filtered_matches}
    return any(cat in filtered_categories for cat in categories)
```

这个函数解决了关键词匹配中的**误报问题**。比如"login"这个词虽然匹配钓鱼关键词，但它也出现在很多正常网站的URL中。通过检查"login"是否作为独立单词出现（而非"blogin"的一部分），可以过滤掉这类误报。

---

## 第三部分：浏览器动态检测

### 3.1 动态伪装的原理

传统的网站爬虫工作流程很简单：发送HTTP请求、接收HTML响应、解析内容。但这个方法在今天已经远远不够了。

现代网站广泛使用JavaScript框架（React、Vue、Angular等）构建单页面应用（SPA）。这类应用的核心特点是：初始HTML只是一个空壳，真正的内容是通过JavaScript在浏览器中动态加载的。如果禁用了JavaScript，页面就只剩下一片空白。

更关键的是，攻击者可以**利用这个特性来隐藏恶意内容**。他们可能会设计这样的钓鱼网站：对正常的搜索引擎爬虫展示无害内容，对真实访客展示钓鱼页面；对不同地区来源的访客展示不同内容；或者只有在用户登录之后才加载诈骗话术。这种"动态伪装"技术使得静态爬取完全失效。

举个例子：一个钓鱼网站可能在robots.txt中声明允许爬取，HTML源码看起来完全正常，但一旦浏览器执行了JavaScript，就会动态加载钓鱼表单。传统的curl或requests库只能获取静态HTML，根本看不到钓鱼内容。

解决方案是使用**真正的浏览器**来渲染页面。浏览器是一个完整的JavaScript执行环境，它能忠实地执行页面中的所有脚本，返回最终呈现给用户的真实内容。

### 3.2 Playwright渲染引擎

系统使用Playwright来实现浏览器自动化。Playwright是微软开发的一个浏览器自动化库，支持Chrome、Firefox、WebKit等多种浏览器，提供异步API，非常适合在异步环境中使用。

浏览器管理的核心是BrowserManager类。这个类使用上下文管理器（async with）来确保资源正确申请和释放：

```python
class BrowserManager:
    """使用Playwright管理浏览器实例"""

    async def __aenter__(self):
        self.playwright = await async_playwright().start()
        self.browser = await self.playwright.chromium.launch(
            headless=self.config.headless
        )
        self.context = await self.browser.new_context(
            viewport={"width": 1920, "height": 1080},
            user_agent=self.config.user_agent
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.context:
            await self.context.close()
        if self.browser:
            await self.browser.close()
        if self.playwright:
            await self.playwright.stop()
```

analyze方法是核心入口。它对同一个URL执行两次渲染：第一次禁用JavaScript，第二次启用JavaScript。

```python
async def analyze(self, url: str) -> BrowserResult:
    """分析URL，分别在JS禁用和启用状态下渲染"""
    js_disabled_result = await self._render_page(url, java_script_enabled=False)
    js_enabled_result = await self._render_page(url, java_script_enabled=True)

    return BrowserResult(
        js_enabled=js_enabled_result,
        js_disabled=js_disabled_result,
        success=js_enabled_result is not None or js_disabled_result is not None
    )
```

渲染过程中有几个关键的技术细节。

**JS禁用技术**：通过拦截所有.js文件请求来实现禁用JavaScript的效果。当java_script_enabled=False时，代码会设置一个路由拦截器，将所有对.js文件的请求直接中止：

```python
if not java_script_enabled:
    await page.context.route('**/*.js', lambda route: route.abort())
```

**等待动态渲染**：即使JS是启用的，页面中的动态内容（如AJAX请求）可能需要时间才能完全加载。代码在页面导航完成后额外等待8秒：

```python
await page.goto(url, wait_until='networkidle', timeout=self.config.timeout_ms)
await page.wait_for_timeout(8000)  # 等待8秒确保AJAX/SPAs内容加载
```

**完整DOM提取**：使用document.documentElement.outerHTML获取整个DOM树，这样可以捕获页面结构的完整变化：

```python
html = await page.evaluate('document.documentElement.outerHTML')
```

### 3.3 页面差异分析

两次渲染的结果需要进行对比分析。差异分析器（DiffAnalyzer）承担这个职责。

核心是**Jaccard相似度算法**。这个算法的思想很直观：把两个文本都分成词集合，相似度 = 交集大小 / 并集大小。

```python
def _calculate_similarity(self, text1: str, text2: str) -> float:
    """简单Jaccard相似度"""
    if not text1 and not text2:
        return 1.0
    if not text1 or not text2:
        return 0.0

    set1 = set(text1.split())
    set2 = set(text2.split())

    intersection = len(set1 & set2)
    union = len(set1 | set2)

    return intersection / union if union > 0 else 0.0
```

举例来说，如果JS关闭时文本是"登录"，JS开启时文本是"登录 账户 密码"，那么交集是1（"登录"），并集是3，相似度是33%，差异度是67%。差异度越高，说明页面依赖JavaScript的程度越高。

完整的分析返回包括文本相似度、链接数量变化、文本预览等信息：

```python
def analyze(self, js_enabled: PageResult, js_disabled: PageResult) -> Dict[str, Any]:
    js_enabled_text = self.extractor.extract_text(js_enabled.html)
    js_disabled_text = self.extractor.extract_text(js_disabled.html)

    similarity = self._calculate_similarity(js_enabled_text, js_disabled_text)
    added_links = len(js_enabled.links) - len(js_disabled.links)

    return {
        'text_identical': js_enabled_text == js_disabled_text,
        'content_similarity': similarity,
        'js_diff_ratio': 1.0 - similarity,  # 差异度 = 1 - 相似度
        'added_links_count': added_links,
        'js_generated_preview': self._get_preview(js_enabled_text, 200),
        'removed_preview': self._get_preview(js_disabled_text, 200),
    }
```

### 3.4 敏感表单检测

钓鱼网站的终极目的通常是窃取用户的敏感信息，最常见的方式就是伪造登录表单。因此，识别页面中的登录表单是检测钓鱼网站的关键环节。

敏感元素扫描器（SensitiveElementScanner）使用BeautifulSoup解析HTML，遍历所有form元素，分析每个表单的结构特征：

```python
def scan(self, html_content: str) -> ScanReport:
    """扫描HTML内容中的敏感元素"""
    soup = BeautifulSoup(html_content, 'html.parser')
    report = ScanReport()

    for form in soup.find_all('form'):
        form_info = self._analyze_form(form)
        report.forms.append(form_info)

        if form_info.has_password_field:
            report.password_field_count += 1

        if form_info.form_type == 'login':
            report.login_form_count += 1
            if form_info.risk == 'high':
                report.high_risk_forms += 1

    report.input_count = len(soup.find_all(['input', 'textarea']))
    return report
```

表单风险评估的核心逻辑在_analyze_form方法中：

```python
def _analyze_form(self, form) -> FormInfo:
    """分析单个表单"""
    form_info = FormInfo()

    # 分析输入字段
    inputs = form.find_all(['input', 'textarea'])
    for inp in inputs:
        inp_type = inp.get('type', 'text').lower()
        inp_name = inp.get('name', '').lower()

        if inp_type == 'password':
            form_info.has_password_field = True

        # 检查用户名字段
        for kw in self.username_keywords:
            if kw in inp_name:
                form_info.has_username_field = True
                break

    # 确定表单类型（登录/注册等）
    form_html = str(form).lower()
    for kw in self.login_keywords:
        if kw in form_html:
            form_info.form_type = 'login'
            break

    # 风险评估
    if form_info.has_password_field and not form_info.has_username_field:
        form_info.risk = 'high'  # 只有密码字段，无用户名 → 高风险
    elif form_info.has_password_field and form_info.has_username_field:
        if self._is_suspicious_action(action):
            form_info.risk = 'high'
        else:
            form_info.risk = 'medium'

    return form_info
```

钓鱼表单识别有几个关键逻辑。第一，**只有密码字段但无用户名**是高风险信号——正常的登录表单通常两者都有，而钓鱼表单可能只收集密码。第二，**可疑的action URL**（如包含javascript:、eval等)也是高风险信号。

---

## 第四部分：威胁情报集成

### 4.1 多源情报的重要性

单一系统的检测能力是有限的。即使我们的算法再精妙，也不可能覆盖所有新出现的威胁模式。这就像是一个医生，再厉害也只能凭自己的经验诊断一部分疾病，但如果能参考其他医生的意见、X光片、血液检查等多项信息，诊断的准确率就会大大提高。

威胁情报的价值在于**共享和积累**。全球各地的安全厂商、研究人员、行业组织每天都在分析新的威胁样本，识别恶意URL、钓鱼域名、恶意IP等。这些信息如果能够实时查询，就能大幅提升检测的准确性和时效性。比如某个钓鱼域名刚刚被某安全厂商的蜜罐系统捕获，我们如果在几分钟内就能查询到这个情报，就能识别一批潜在受害者。

系统对接了两个主要的威胁情报源：**某浏览器安全插件**是国内的一个威胁情报平台，提供URL黑名单和分类查询服务；**某态势感知平台**则提供更为丰富的IOC（Indicator of Compromise）多维分析接口，可以获取域名的综合评分、威胁标签、关联分析等深度信息。

多源情报的另一个价值是**交叉验证**。如果多个独立的情报源都标记同一个URL为恶意，那可信度就大大提高；反之，如果只有一个情报源标记为恶意，其他都正常，那就需要更谨慎的评估。

### 4.2 威胁情报分流

威胁情报在系统中扮演着特殊的角色：它不仅仅是一个查询接口，更是决策树的**第一层分流依据**。

具体流程是这样的：系统在开始处理一个URL时，首先调用态势感知API接口，查询该域名的威胁等级评分（level）。这个评分反映了某态势感知平台对该域名的综合判断。如果level大于等于30，系统就认为这是一个中高危威胁，进入完整的高危研判流程；如果level小于30，就进入简化的低危研判流程。

这个设计的逻辑是：某态势感知平台已经整合了大量的威胁情报和机器学习模型，它的评分是一个很有价值的先验信息。利用这个先验信息，系统可以更合理地分配检测资源：对高危URL进行深度分析，对低危URL快速通过。

```python
def get_threat_intel(url: str = "", domain: str = "", ip: str = "") -> Dict[str, Any]:
    """
    获取威胁情报
    调用态势感知API接口获取IOC Tags，根据level分流
    """
    if not domain:
        domain = _extract_domain(url)

    if not domain and not ip:
        return DEFAULT_INTEL.copy()

    # 调用态势感知API接口获取威胁情报
    threat_result = query_threat_ioc_tags(domain)
    level = extract_threat_level(threat_result)

    return {
        'threat_api_available': API_AVAILABLE,
        'in_official_whitelist': False,
        'threat_level': level,  # 这个level决定后续分流
    }
```

### 4.3 API签名机制

与外部API对接时，身份验证是必不可少的。态势感知API接口使用了一种基于MD5的签名机制来验证请求的合法性。

签名的生成过程体现了**双重安全**的设计：

```python
def _make_threat_api_headers(body_str: str) -> dict:
    """生成态势感知API签名请求头"""
    headers = {}

    # 基础认证信息
    headers["X-API-Key"] = 态势感知API_ID
    headers["X-Nonce"] = str(random.randint(0, 99999999)).zfill(8)
    headers["X-Timestamp"] = str(int(time.time()))

    # MD5签名：MD5(body_md5 + appid + nonce + timestamp + secret)[16:]
    body_md5 = hashlib.md5(body_str.encode("utf8")).hexdigest()
    s = body_md5 + headers["X-API-Key"] + headers["X-Nonce"] + \
        headers["X-Timestamp"] + 态势感知API_KEY_SECRET
    headers["X-Signature"] = hashlib.md5(s.encode("utf8")).hexdigest()[16:]

    headers["Content-Type"] = "application/json"
    return headers
```

这个签名机制包含三个要素：第一，请求体内容（防止篡改）；第二，时间戳（防止重放）；第三，密钥（防止伪造）。攻击者即使截获了请求，也无法在不知道密钥的情况下伪造签名；即使截获了完整的请求，也无法在有效时间窗口外重放。

### 4.4 某浏览器安全插件黑数据查询

某浏览器安全插件是一个专注于URL分类的威胁情报平台。它的核心价值在于提供了一个**黑名单和分类查询**的能力。

当系统查询一个URL时，某浏览器安全插件会返回该URL的分类信息：是否是黑名单、具体的威胁类型（如钓鱼、仿冒、赌博等）、置信度等。这些信息直接来自某浏览器安全插件多年积累的威胁情报库，具有很高的参考价值。

系统在使用某浏览器安全插件数据时，有一个特殊的设计：**黑类型映射**。某浏览器安全插件返回的数据中包含Level、St、Sc、Ssc等多个字段，这些字段的组合编码了不同的威胁类型。系统根据一套映射规则，将这些编码转换为统一的分类名称和风险等级。

```python
# 判断是否为某浏览器安全插件类型
is_black_type = (level_int == 60 and st_int in [10, 30]) or \
             (level_int == 0 and st_int == 30)

# 根据类型选择映射规则
if is_black_type and is_black:
    category_info = map_black_info_type(level_int, st_int, threat_int, sthreat_int, threat_int)
else:
    category_info = map_threat_type(level_int, st_int, threat_int, sthreat_int)
```

这种设计的考虑是：不同情报源的数据格式往往不同，直接使用原始数据会导致后续处理逻辑复杂化。通过映射层，系统可以将不同情报源的数据都转换为统一的格式，简化上层逻辑。

---

## 第五部分：品牌销售检测

### 5.1 品牌冒用的识别

除了直接模仿品牌官网的钓鱼攻击，还有一类威胁更加隐蔽：未经授权使用品牌名义进行销售推广。这种情况可能不完全违法，但确实损害了品牌形象和用户利益。

举例来说，某公司并未授权某个网站销售其产品，但该网站可能使用了品牌的Logo、名称或商标，展示虚假的理财产品信息，诱导用户购买。这类"品牌侵权"或"商标滥用"行为，虽然不是传统的钓鱼攻击，但也需要被检测和标记。

品牌销售检测模块就是为了应对这类威胁而设计的。它的核心思路是**关键词匹配**：在页面内容中搜索品牌相关的关键词（如品牌名称、简称、Logo文件名等），同时搜索销售相关的关键词（如"购买"、"投资"、"正品"等）。如果两者同时出现，就认为可能存在品牌冒用行为。

```python
def detect(self, url: str, text: str) -> DetectionResult:
    """检测文本内容中的销售行为"""
    matched_categories = set()
    text_lower = text.lower()

    # 加载关键词
    sales_keywords = self.keyword_loader.get_sales_keywords()

    # 检查销售关键词
    for category, keywords in sales_keywords.items():
        for keyword in keywords:
            if keyword in text_lower:
                matched_categories.add(category)

    has_sales = len(matched_categories) > 0
    risk_level = self._determine_risk_level(matched_categories)

    return DetectionResult(
        has_sales=has_sales,
        matched_categories=list(matched_categories),
        risk_level=risk_level,
    )
```

### 5.2 关键词泛化

简单的关键词匹配存在一个明显的问题：**攻击者可以使用变体来绕过检测**。比如"示例证券"可能被写成"示例zheng券"、"示例d证券"、"示例@券"等。这些变形利用了字符的相似性（视觉相似、拼音相似）来欺骗用户和检测系统。

为了应对这种绕过手段，系统实现了**关键词泛化**功能。它的目标是穷举出某个品牌可能被伪装的所有形式。

**同形字攻击**是最难防范的一种。Unicode中有很多看起来相似的字符，它们在屏幕上显示的模样几乎一样，但字符码完全不同：

```python
BRAND_VARIATION_PATTERNS = {
    'homograph_chars': {
        'o': ['0', 'ο', 'О'],
        'l': ['1', 'ι', 'I', '|'],
        'i': ['1', 'l', 'Ι', '|'],
        'a': ['α', '@', '4'],
        'e': ['ξ', 'ε', '3'],
        'c': ['(', 'С', 'ç'],
        'u': ['υ', 'ü', 'μ'],
        'n': ['ñ', 'ν'],
        'w': ['vv', 'ω', 'Ш'],
        's': ['5', '$', 'ѕ'],
    },
}
```

例如"示例证券"可能被伪装为"示例d证券"（用小写字母d替代o）、"示例а证券"（用西里尔字母а替代a）等。系统会生成这些同形变体，然后检查页面内容是否包含这些变体。

**数字-字母变体**也是一种常见的绕过手段：

```python
'digit_letter_map': {
    'a': '4', 'e': '3', 'i': '1', 'o': '0', 's': '5',
}
```

**拼音变体**则针对中文品牌名：

```python
'abbreviations': {
    '示例证券': ['ESI', 'ebt', 'example', 'examplesec'],
    '示例保险': ['EBI', 'example', 'ej', 'exampleins'],
}
```

### 5.3 灰黑产关键词过滤

在关键词匹配的过程中，还有一个重要的问题需要处理：**误报**。有些词虽然看起来像威胁关键词，但实际上是无害的。

比如"login"这个词出现在很多正常网站的URL路径中（/login、/blogin等），但它同时也是钓鱼网站常用的关键词。如果简单地做子串匹配，就会把大量正常网站误判为钓鱼网站。

为了解决这个问题，系统实现了**灰黑产关键词过滤**机制：

```python
false_positive_patterns = {
    'sm', '91', 'xxx', 'tx', 'ico', 'line', 'wv', 'defi', 'sto',
    'wap', 'app', 'web', 'net', 'com', 'org', 'gov', 'edu',
    'vip', 'max', 'min', 'add', 'del', 'edit', 'save', 'new',
}
```

当关键词匹配命中时，系统会检查该关键词是否属于误报模式。如果是，就忽略这次命中。此外，对于3个字符以内的短字母数字组合，系统还会检查它是否作为独立单词出现在文本中：

```python
if len(keyword) <= 3 and keyword.isalnum():
    pattern = r'(?:^|[^a-zA-Z0-9])' + re.escape(keyword) + r'(?:$|[^a-zA-Z0-9])'
    if not re.search(pattern, text_content, re.IGNORECASE):
        continue  # 不是独立单词，跳过这次命中
```

比如"login"在"blogin"中被匹配到时，由于"log"不是独立单词（前后都有其他字母），这次命中会被忽略。

---

## 第六部分：智能研判

### 6.1 为什么需要机器学习

规则系统（决策树）虽然可解释性好、易于调整，但它也有明显的局限性：它只能处理预先定义好的模式，无法发现未曾见过的威胁。

网络安全是一个攻防对抗的领域。攻击者会不断变化手法，试探检测系统的边界。如果完全依赖规则，就需要不停地更新规则库，这会变成一场永无止境的"猫鼠游戏"。

这时候，机器学习模型的价值就体现出来了。一个训练良好的模型，能够从大量的样本中学习到威胁的**潜在特征**，这些特征可能是规则系统没有明确定义但确实有效的。比如某个特定的HTML结构、某段特殊的JavaScript代码、某种罕见的域名模式……这些特征单独看都不足以判断为威胁，但组合起来就能给出有价值的信号。

系统采用了一种**规则+模型**的混合架构。决策树负责主要的、明确的判断，模型负责边界的、模糊的情况。两者互为补充：规则系统给出初步结论，模型进行复核和调整。

### 6.2 Skill研判流程

系统的智能研判模块叫做"Skill"。它的设计目标是：接收决策树的初步判断结果，结合外部情报和浏览器分析数据，由模型给出最终的复核意见。

完整的Skill研判流程包含六个步骤：

**第一步是威胁情报分流**。系统查询某态势感知平台的IOC接口，获取域名的威胁评分。这个评分决定后续走哪条研判路线。

**第二步是浏览器渲染**。系统使用Playwright对URL进行双渲染（JS开/关），获取页面的动态内容、文本差异度、表单结构等信息。

**第三步是决策树分析**。基于前两步获取的数据，系统执行决策树规则，给出初步的分类判断。

**第四步是外部情报查询**。系统分别查询某浏览器安全插件黑数据和某态势感知平台 MCP接口，获取该URL在外部情报库中的记录和评分。

**第五步是构建Prompt**。系统将以上所有信息整合成一个结构化的Prompt：

```python
def build_skill_prompt(skill_input: Dict[str, Any]) -> str:
    """构建Skill研判Prompt"""
    # 决策树输出结果
    decision_tree_output = f"""
- 初步分类: {dt_result['category']}
- 风险级别: {dt_result['risk_level']}
- 决策路径: {' → '.join(dt_result['decision_path'])}
- 中间判断节点:
  - 某态势感知平台关联: {dt_result['intermediate_nodes'].get('threat_related')}
  - ICP备案为空: {dt_result['intermediate_nodes'].get('icp_empty')}
  - JS差异度: {dt_result['intermediate_nodes'].get('js_diff_ratio')}
  - YOLO/OCR为空: {dt_result['intermediate_nodes'].get('yolo_ocr_empty')}
"""

    # 浏览器分析结果
    browser_analysis = f"""
- URL: {skill_input['web_info']['url']}
- 登录表单检测: {ba['has_login_form']} ({ba['login_form_count']}个)
- JS差异度分析: {ba['js_diff_ratio']:.1%}
- 内容相似度: {ba['content_similarity']:.1%}
"""
```

**第六步是模型推理**。系统将Prompt发送给本地的Gemma模型，获取最终的分类判断和置信度。

### 6.3 Prompt工程

Prompt（提示词）的质量直接决定了模型的输出效果。一个好的Prompt应该结构清晰、信息完整、指令明确。

系统构建的Prompt包含以下几个部分：

**任务背景**：说明这是一个Web威胁分类研判任务，需要结合多种信息源进行综合判断。

**权重说明**：明确告知模型各信息源的优先级——决策树结果权重最高（因为它基于专家规则），某浏览器安全插件和某态势感知平台结果作为辅助参考。

**输入信息**：分为决策树输出结果、浏览器分析结果、关键词匹配信息、某浏览器安全插件数据、某态势感知平台情报数据等几个模块。每个模块都给出了关键字段的具体值。

**分类定义**：列出了所有标准分类及其定义，确保模型的输出在定义的范围内。

**输出格式要求**：要求模型以JSON格式输出最终分类、置信度、风险等级、判断理由等信息。

### 6.4 模型配置与调用

系统使用本地的Gemma模型进行推理。Gemma是Google开发的一个开源大语言模型，虽然参数量相对较小，但推理速度快、资源消耗低，非常适合本地部署。

```python
async def call_gemma_api(prompt: str) -> str:
    """调用本地Gemma模型进行Skill研判"""
    url = f"{Gemma模型配置['base_url']}/chat/completions"
    payload = {
        "model": Gemma模型配置['model_name'],
        "messages": [
            {"role": "system", "content": "你是一个Web威胁分类专家，只输出JSON格式结果。"},
            {"role": "user", "content": prompt}
        ],
        "temperature": 0.1,  # 低温度保证确定性
        "max_tokens": 2048
    }

    async with aiohttp.ClientSession() as session:
        async with session.post(
            url, headers=headers, json=payload,
            timeout=aiohttp.ClientTimeout(total=120)
        ) as resp:
            return await resp.json()
```

temperature设置为0.1是为了保证输出的确定性——高温度会让模型的输出更加随机，低温度则使输出更加稳定可重复。对于分类任务来说，稳定性比创造性更重要。

---

## 第七部分：分类体系

### 7.1 三级风险体系

系统采用三级风险体系，将威胁分为高危、中危、低危三个级别。

**高危**是最严重的威胁类型，包括"仿冒网站"和"钓鱼欺诈"两个分类。这类威胁具有明确的恶意目的，比如直接模仿官网骗取用户账号、伪造理财产品诱导转账等。高危威胁需要立即处置，通常是封禁或下架。

**中危**是中等程度的威胁，包括"品牌侵权"和"疑似暴露资产"两个分类。这类威胁可能没有直接的欺诈行为，但存在品牌权益受损或资产意外暴露的风险，需要重点关注和跟进。

**低危**是轻微的威胁或正常情况，包括"商标滥用"、"ICP滥用"、"疑似政务合作"、"疑似商务合作"、"无害网站"等多个分类。低危类别中既包含确实存在问题但情节轻微的情况，也包含经研判确认属于正常网站的情况。

### 7.2 分类详细定义

每一种分类都有明确的定义和判定边界。

**仿冒网站**的定义为：模仿机构官网或其子系统的网站，用于欺诈、假承诺、数据收集。典型特征包括：域名高度相似、页面视觉高度还原、缺乏真实ICP备案、存在异常跳转等。

**钓鱼欺诈**的定义为：通过冒充机构或其客服、理财平台登录框，诱导客户输入账号、密码、银行卡信息。典型特征包括：包含登录表单、表单action指向可疑URL、要求提供敏感财务信息等。

**品牌侵权**的定义为：未经授权使用机构名义从事金融服务或产品，如假投资产品、假保险合同。这类情况虽然可能不涉及直接欺诈，但会误导消费者，损害品牌声誉。

**商标滥用**的定义为：未授权第三方使用机构商标、Logo、官方名称，以"官方合作"、"官方理财产品"等话术诱导客户。相比品牌侵权，商标滥用的情节更轻，通常是蹭热度而非刻意欺诈。

**ICP滥用**的定义为：在中国市场，网站未备案或滥用金融机构名义取得或使用ICP备案号，冒充机构服务。这是具有中国特色的威胁类型。

**疑似暴露资产**的定义为：品牌或关联组织的数字资产（如IPv4）被意外或恶意暴露在公开或半公开网络。这类情况可能是配置失误导致的意外暴露。

### 7.3 分类判定原则

在实际研判中，系统遵循几个核心原则。

**高危优先原则**：当一个URL同时符合多个分类的判定条件时，优先采用高危分类。比如一个URL既有钓鱼特征又有品牌侵权特征，应判定为钓鱼欺诈。

**证据链原则**：最终的分类判断需要有多维度的证据支撑，而不是仅凭单一特征。比如"JS差异度高"加上"包含登录表单"才是钓鱼欺诈的强证据。

**置信度概念**：不是所有的判断都有十足的把握。系统为每个判断标注了置信度：高、中、低三个等级。低置信度的判断意味着信息不够充分或存在矛盾。

**边界case处理**：有些URL处于分类的边界地带，模棱两可。对于这类情况，系统会给出"其他"分类，并标注为低危，等待人工复核。

---

## 第八部分：决策流程详解

### 8.1 决策树节点详解

为了更好地理解整个系统的判断逻辑，让我们详细走一遍主要的决策流程。

决策树的**根节点**是一个威胁情报关联判断。它调用威胁情报接口，检查该域名是否被标记为恶意。如果某态势感知平台返回的level值大于等于30（中高危阈值），说明该域名在威胁情报库中有较高的负面评分，走"真"分支，进入高危研判路线。如果level值小于30，走"假"分支，进入低危研判路线。如果某态势感知平台接口不可用，为了安全起见，也默认走"真"分支。

这个根节点的分流效果是：约70%的正常域名会被快速分流到低危路线，只有约30%的可疑域名会进入完整的高危研判流程。这种设计大大提高了系统的处理效率。

进入**高危研判路线**的URL，首先要判断ICP备案状态。如果ICP备案为空，这是一个非常可疑的信号。正规网站通常都有ICP备案，只有少数个人博客或小型站点可能无备案。考虑到这是高危研判路线（某态势感知平台已经标记为可疑），无ICP备案就更值得警惕。

无ICP备案的路径会进一步检查是否涉及娱乐博彩内容。娱乐博彩类网站是钓鱼仿冒的高发区，如果页面内容涉及这类特征，会直接判定为"仿冒网站"。

无ICP备案但没有娱乐博彩特征的URL，会继续检查是否有登录表单相关的标题。钓鱼网站通常会在标题中包含"登录"、"登陆"等词汇来吸引受害者。如果标题涉及登录相关词汇，会判定为"钓鱼欺诈"。

接下来会检查是否是某态势感知平台白名单中的域名。如果是的话，可能是该品牌的真实暴露资产，标记为"疑似暴露资产"。

然后检查动态渲染后是否包含登录表单。这使用了一个**or_threshold节点**：只要JS差异度超过50%或者页面包含娱乐博彩内容，就判定为"仿冒网站"；否则判定为"钓鱼欺诈"。

对于**有ICP备案的网站**，判断逻辑会不同。首先查看网站标题是否包含品牌关键词——如果标题中提到了某品牌，但ICP备案主体又不是该品牌，就存在冒用嫌疑。

如果标题含品牌且ICP主体是政府机构或事业单位，可能是真实的政务合作，标记为"疑似政务合作"。

如果ICP主体是企业且YOLO/OCR检测为空，可能是正常的商务合作，标记为"疑似商务合作"。

如果ICP主体是企业但YOLO/OCR检测非空，说明页面中有相关的图像或文字标识但没有正式合作关系，标记为"商标滥用"。

### 8.2 结果节点与理由生成

决策树的叶子节点是结果节点，每个结果节点包含分类名称、风险等级和判断理由。

判断理由有两种来源。一种是静态定义的固定理由，比如"网站标题与娱乐博彩色情相关"。另一种是基于模板的动态生成，比如"ICP备案主体为{icp_type}"，其中{icp_type}是根据实际数据替换的变量。

对于一些复杂的判断，理由会综合多条信息：

```python
"reason_template": ["js_diff_or_entertainment"]
```

这个模板会被展开为具体的理由，比如："JS差异度75%>50%且包含娱乐博彩信息"。这样的理由能够帮助分析人员快速理解判断依据。

---

## 第九部分：技术亮点与设计哲学

### 9.1 配置驱动优于硬编码

纵观整个系统，最核心的设计哲学可能是"配置驱动优于硬编码"。

传统的企业软件往往将规则硬编码在程序中。每次规则变化都需要：开发人员修改代码、测试人员编写用例、运维人员部署上线。这个流程至少需要几天时间，而在网络安全领域，威胁可能在几个小时内就会大规模传播。

本系统将所有判断规则提取到外部配置文件（rule.json）中：

```json
{
  "version": "1.0",
  "conditions": {
    "threat_related": {"type": "bool", "name": "check_threat_related"},
    "icp_empty": {"type": "bool", "name": "is_icp_empty"},
    "brand_in_title": {"type": "bool", "name": "is_brand_in_title"}
  },
  "nodes": [
    {"id": "root", "type": "condition", "condition_key": "threat_related",
     "true_goto": "icp_empty_check", "false_goto": "not_threat_related"}
  ],
  "root": "root"
}
```

规则管理员可以在不修改代码的情况下调整阈值、增删节点、修改跳转逻辑。系统会自动检测配置变更并在约2秒内热加载新规则。

这种设计大大缩短了规则更新的周期。在应急响应场景中，分析人员发现一种新型威胁的特征后，只需要修改配置文件，整个系统几秒后就能识别这类威胁。

### 9.2 可插拔的模块设计

系统的另一个设计亮点是模块的可插拔性。

每个子模块（浏览器检测、情报查询、模型推理等）都封装为独立的类或函数，对外提供统一的接口。如果某一天某个外部服务不可用了，只需要实现一个替代品插入即可，不需要改动调用方的代码。

这种设计也方便了模块的独立测试。每个模块都可以单独运行，用mock数据验证逻辑是否正确，然后组装成完整的系统。

### 9.3 安全左移的理念

"安全左移"是软件开发中的一个概念，意思是将安全检查尽可能提前到开发流程的早期。本系统的设计也体现了这个理念。

在正式研判之前，系统会先用测试数据集验证决策树规则的准确率。只有准确率达到预期水平，才会上线新的规则。这种机制确保了规则变更不会引入新的误判。

此外，系统还提供了"仅决策树"的快速模式，方便在大规模扫描场景中使用。这个模式不需要外部API，适合在没有配置API密钥的情况下进行初步筛选。

### 9.4 权衡与取舍

没有任何系统是完美的。这个Web威胁分类系统在某些方面做了权衡和取舍。

比如，系统选择使用Jaccard相似度而不是更复杂的NLP模型来计算文本差异度。Jaccard的优点是计算快速、实现简单，缺点是无法理解语义。但对于"检测JS动态加载"这个具体任务来说，Jaccard已经足够有效。

又比如，系统选择决策树而不是深度学习作为主要的判断逻辑。决策树的优点是可解释、易调整，缺点是难以处理复杂的非线性关系。但对于"多维度条件判断"这个场景，决策树的结构恰好契合。

这些权衡都经过了实践的检验。在网络安全这个快速变化的领域，可解释性和易调整性往往比极致的准确率更重要。

---

## 第十部分：关键数据结构

### 10.1 检测结果数据类

系统定义了几个核心的数据类来组织检测结果。

DetectionResult是整个系统最核心的数据结构，它封装了一条URL的完整检测结果：

```python
@dataclass
class DetectionResult:
    """检测结果"""
    url: str
    brand_owner: str
    detection_time: str
    browser_analysis: Optional[BrowserAnalysisResult]
    decision_tree_category: str
    decision_tree_risk_level: str
    decision_path: List[str]
    intermediate_nodes: Dict[str, Any]
    threat_intel: Dict[str, Any]
    brand_keywords_matched: List[str]
```

BrowserAnalysisResult封装了浏览器分析的结果：

```python
@dataclass
class BrowserAnalysisResult:
    """浏览器分析结果"""
    js_enabled_html: str = ""
    js_disabled_html: str = ""
    js_enabled_title: str = ""
    js_disabled_title: str = ""
    has_login_form: bool = False
    login_form_count: int = 0
    form_types: List[str] = field(default_factory=list)
    form_risk_level: str = "unknown"
    js_diff_ratio: float = 0.0
    content_similarity: float = 1.0
```

ScanReport封装了敏感元素扫描的结果：

```python
@dataclass
class ScanReport:
    """扫描报告"""
    forms: List[FormInfo] = field(default_factory=list)
    password_field_count: int = 0
    input_count: int = 0
    login_form_count: int = 0
    high_risk_forms: int = 0
```

### 10.2 最终输出格式

完整的检测输出包含多个模块的信息，以JSON格式保存：

```json
{
  "url": "https://example-phishing.com",
  "brand_owner": "示例品牌",
  "detection_time": "2026-05-11T10:30:00",

  "decision_tree": {
    "category": "仿冒网站",
    "risk_level": "高危",
    "decision_path": ["threat_related→是", "icp_empty→是", "entertainment→否", "login_form_title→是"],
    "intermediate_nodes": {
      "threat_related": true,
      "icp_empty": true,
      "has_login_form": true,
      "js_diff_ratio": 0.75
    }
  },

  "browser_analysis": {
    "has_login_form": true,
    "login_form_count": 1,
    "js_diff_ratio": 0.75
  },

  "black_result": {
    "category_name": "钓鱼",
    "suggested_level": "黑"
  },

  "threat_mcp_result": {
    "code": 200,
    "data": {"overall_summary": {"score": 85}}
  },

  "skill_judgment": {
    "final_classification": "仿冒网站",
    "confidence": "高",
    "risk_level": "高危",
    "reasoning": ["决策树分类为仿冒网站", "某浏览器安全插件检出钓鱼类型"]
  }
}
```

---

## 结语

本文深入剖析了Web威胁分类系统的架构设计与核心实现。这个系统的设计充分体现了多维度检测、配置驱动、可解释AI等现代安全架构的理念。

通过决策树引擎，系统实现了灵活可调整的规则判断；通过浏览器动态检测，系统能够识别JavaScript伪装类攻击；通过多源情报集成，系统借助全球安全社区的力量提升检测能力；通过机器学习模型，系统能够在规则边界处做出智能判断。

各个模块各司其职、互相配合：情报模块提供先验知识、浏览器模块捕获动态内容、决策树模块执行规则判断、模型模块提供智能复核。这种分层架构既保证了系统的可维护性，又提供了足够的检测能力。

网络安全是一个永恒的攻防对抗领域。攻击者在不断进化，检测系统也必须持续迭代。本系统的模块化设计和配置驱动架构，为未来的扩展和演进提供了良好的基础。

---

*本文档基于Web威胁分类系统v1.2.0撰写*
*撰写日期：2026年5月11日*
