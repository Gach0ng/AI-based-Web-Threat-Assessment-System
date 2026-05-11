"""
条件判断函数库
提供决策树所需的所有条件判断函数
"""

import sys
import os
from typing import Dict, Any, List, Optional

# 添加browser_crawling路径
_current_dir = os.path.dirname(os.path.abspath(__file__))
_browser_crawling_path = os.path.normpath(os.path.join(_current_dir, '..', 'browser_crawling'))
if _browser_crawling_path not in sys.path:
    sys.path.insert(0, _browser_crawling_path)

# 添加sales_detection路径
_sales_detection_path = os.path.normpath(os.path.join(_current_dir, '..', 'sales_detection'))
if _sales_detection_path not in sys.path:
    sys.path.insert(0, _sales_detection_path)

try:
    from sensitive_element_scanner import SensitiveElementScanner
    from gray_blacklist import GrayBlackFilter
    from detector import Detector as SalesDetector
except ImportError:
    SensitiveElementScanner = None
    GrayBlackFilter = None
    SalesDetector = None


# 全局实例（延迟初始化）
_scanner = None
_gray_black_filter = None
_sales_detector = None


def _get_scanner():
    global _scanner
    if _scanner is None and SensitiveElementScanner is not None:
        _scanner = SensitiveElementScanner()
    return _scanner


def _get_gray_filter():
    global _gray_black_filter
    if _gray_black_filter is None and GrayBlackFilter is not None:
        _gray_black_filter = GrayBlackFilter()
    return _gray_black_filter


def _get_sales_detector():
    global _sales_detector
    if _sales_detector is None and SalesDetector is not None:
        _sales_detector = SalesDetector()
    return _sales_detector


# ==================== 核心分流节点 ====================

from rules_engine.sc_api import THREAT_LEVEL_THRESHOLD


def check_threat_related(threat_intel: Dict[str, Any]) -> bool:
    """
    判断威胁情报是否关联域名
    根据threat_level分流：>=THREAT_LEVEL_THRESHOLD走中高危研判路线（返回True），<THREAT_LEVEL_THRESHOLD走低危研判路线（返回False）
    """
    if not threat_intel.get('threat_api_available', True):
        return True

    # 获取threat_level，根据level >= THREAT_LEVEL_THRESHOLD决定是否走中高危研判路线
    threat_level = threat_intel.get('threat_level', 0)

    # level >= THREAT_LEVEL_THRESHOLD，走中高危研判路线（返回True）
    # level < THREAT_LEVEL_THRESHOLD，走低危研判路线（返回False）
    return threat_level >= THREAT_LEVEL_THRESHOLD


def check_official_whitelist(threat_intel: Dict[str, Any]) -> bool:
    """威胁情报反查是否包含官方域名白名单"""
    return threat_intel.get('in_official_whitelist', False)


# ==================== IP/域名判断 ====================

def is_ip_access(parsed_data: Dict[str, Any]) -> bool:
    """判断是否为IP直接访问"""
    url = parsed_data.get('URL', '')
    import re
    ip_pattern = r'^https?://(\d{1,3}\.){3}\d{1,3}'
    return bool(re.match(ip_pattern, url))


def is_icp_empty(parsed_data: Dict[str, Any]) -> bool:
    """ICP备案号/ICP备案主体是否为空"""
    icp_no = parsed_data.get('ICP备案号', '')
    icp_subject = parsed_data.get('ICP备案主体', '')

    empty_values = ['', '无', 'None', 'null', '暂无', None]

    return icp_no in empty_values or icp_subject in empty_values


# ==================== 表单相关 ====================

def has_login_form_after_dynamic_render(parsed_data: Dict[str, Any]) -> bool:
    """动态渲染后是否包含登录表单"""
    scanner = _get_scanner()
    if scanner is None:
        return False

    html_content = parsed_data.get('当前快照源码命中结果', '')

    if not html_content:
        html_content = parsed_data.get('当前页面HTML', '')

    if not html_content:
        return False

    report = scanner.scan(html_content)

    for form in report.forms:
        if form.form_type == 'login':
            return True
        if form.has_password_field and len(form.fields) >= 1:
            return True

    return report.password_field_count > 0 and report.input_count > 1


def get_js_diff_ratio(parsed_data: Dict[str, Any]) -> float:
    """JS开关前后页面差异度 (0.0-1.0)"""
    content_similarity = parsed_data.get('JS开关页面相似度', 1.0)

    if content_similarity is None:
        content_similarity = 1.0

    return 1.0 - content_similarity


# ==================== WD数据来源特殊判定 ====================

# 官方合作相关关键词
_OFFICIAL_COOPERATION_KEYWORDS = [
    '官方', '官网', '旗舰店', '授权', '正品', '授权店',
    '官方直营', '官方正品', '官方授权', '合作', '合作伙伴',
    'certified', 'official', 'authorized', 'genuine', '授权证明',
]


def has_official_cooperation_in_rendered_page(parsed_data: Dict[str, Any]) -> bool:
    """页面渲染后源码中是否包含官方合作相关字眼"""
    rendered_html = parsed_data.get('当前快照源码命中结果', '')
    if not rendered_html:
        return False

    rendered_lower = rendered_html.lower()
    matched = [kw for kw in _OFFICIAL_COOPERATION_KEYWORDS if kw.lower() in rendered_lower]
    return len(matched) > 0


def is_wd_brand_icon_cooperation(parsed_data: Dict[str, Any]) -> bool:
    """
    WD来源 + 网页图标非空 + 页面含官方合作字眼 → 商标滥用
    用于在"新注册境外域名"节点之前做预判
    """
    # 条件1: 数据来源是网盾
    data_source = parsed_data.get('数据来源', '')
    if data_source != '网盾':
        return False

    # 条件2: 当前快照网页图标非空
    icon_list = parsed_data.get('当前快照网页图标', [])
    if not icon_list or (isinstance(icon_list, list) and len(icon_list) == 0):
        return False

    # 条件3: 多字段内容含官方合作字眼（与灰黑产匹配一致的聚合逻辑）
    combined_text = _get_combined_text(parsed_data)
    matched_kws = [kw for kw in _OFFICIAL_COOPERATION_KEYWORDS if kw.lower() in combined_text.lower()]
    if not matched_kws:
        return False

    return True


# ==================== 灰黑产标签 ====================

def has_gray_black_category(
    parsed_data: Dict[str, Any],
    categories: List[str]
) -> bool:
    """是否命中灰黑产关键字分类"""
    gray_filter = _get_gray_filter()
    if gray_filter is None:
        return False

    text_content = _get_combined_text(parsed_data)
    matched = gray_filter.match_text_content(text_content)

    false_positive_patterns = {
        'sm', '91', 'xxx', 'tx', 'ico', 'line', 'wv', 'defi', 'sto',
        'wap', 'app', 'web', 'net', 'com', 'org', 'gov', 'edu',
        'vip', 'max', 'min', 'add', 'del', 'edit', 'save', 'new',
        'old', 'cur', 'pre', 'post', 'sub', 'pub', 'top', 'bot',
    }

    filtered_matches = []
    for m in matched:
        keyword = m['matched_keyword'].lower()
        if keyword in false_positive_patterns:
            continue
        if len(keyword) <= 3 and keyword.isalnum():
            import re
            pattern = r'(?:^|[^a-zA-Z0-9])' + re.escape(keyword) + r'(?:$|[^a-zA-Z0-9])'
            if not re.search(pattern, text_content, re.IGNORECASE):
                continue
        filtered_matches.append(m)

    filtered_categories = {m['category'] for m in filtered_matches}
    return any(cat in filtered_categories for cat in categories)


def yolo_ocr_contains_attack(parsed_data: Dict[str, Any]) -> bool:
    """YOLO/OCR是否包含AI攻击/仿冒品牌/售假"""
    attack_categories = [
        '钓鱼欺诈/仿冒',
        '仿冒品/假货',
        '黑客/黑产工具'
    ]

    return has_gray_black_category(parsed_data, attack_categories)


def _get_combined_text(parsed_data: Dict[str, Any]) -> str:
    """获取组合文本用于灰黑产匹配"""
    parts = [
        parsed_data.get('当前快照OCR命中结果', ''),
        parsed_data.get('历史快照OCR命中结果', ''),
        parsed_data.get('当前快照源码命中结果', ''),
        parsed_data.get('历史快照源码命中结果', ''),
        parsed_data.get('当前网站标题', ''),
        parsed_data.get('URL', '')
    ]
    return ' '.join(str(p) for p in parts if p)


# ==================== 品牌相关 ====================

def has_brand_keywords(parsed_data: Dict[str, Any]) -> bool:
    """是否包含品牌泛化关键词"""
    brand_owner = parsed_data.get('保护的品牌主体', '')
    if not brand_owner:
        return False

    text_content = _get_combined_text(parsed_data)

    brand_keywords = _extract_brand_keywords(brand_owner)

    for kw in brand_keywords:
        if len(kw) >= 2 and kw.lower() in text_content.lower():
            return True

    return False


def _extract_brand_keywords(brand_owner: str) -> List[str]:
    """提取品牌关键词 - 提取2-4字的中文词组合和3字以上的英文词"""
    import re
    if not brand_owner:
        return []

    # 需要过滤的无意义组合（太常见或无实际含义）
    filtered_words = {
        '中国', '国人', '民有', '有限', '限公', '公司', '团有', '集团',
        '有公司', '公司有', '司有限', '无限', '团有', '有集团', '有限公司',
        '国海', '海洋', '洋石', '石油', '油集', '团有', '团有限', '有限公',
    }

    keywords = []

    for length in [2, 3, 4]:
        for i in range(len(brand_owner) - length + 1):
            word = brand_owner[i:i+length]
            if re.match(r'^[\u4e00-\u9fff]+$', word):
                # 过滤无意义的2字组合
                if length == 2 and word in filtered_words:
                    continue
                # 过滤太常见的单字
                if length == 2 and word in ['的', '是', '在', '了', '和', '与', '或']:
                    continue
                keywords.append(word)

    english_words = re.findall(r'[a-zA-Z]{3,}', brand_owner)
    keywords.extend([w.lower() for w in english_words])

    seen = set()
    unique = []
    for kw in keywords:
        if kw not in seen and len(kw) >= 2:
            seen.add(kw)
            unique.append(kw)

    return unique


def yolo_ocr_empty(parsed_data: Dict[str, Any]) -> bool:
    """YOLO/OCR命中是否为空"""
    yolo_result = parsed_data.get('当前快照YOLO命中结果', '')
    ocr_result = parsed_data.get('当前快照OCR命中结果', '')

    empty_values = ['', '无', 'None', 'null', '暂无', None]

    return yolo_result in empty_values and ocr_result in empty_values


# ==================== 域名/IP相关 ====================

def is_new_domain_overseas(parsed_data: Dict[str, Any]) -> bool:
    """注册时间<365天 且 IP在中国大陆境外"""
    domain_age_days = parsed_data.get('域名注册天数', -1)

    if domain_age_days < 0:
        domain_age_days = _estimate_domain_age_days(parsed_data)

    if domain_age_days >= 365:
        return False

    return is_overseas_ip(parsed_data)


def _estimate_domain_age_days(parsed_data: Dict[str, Any]) -> int:
    """估算域名年龄天数"""
    import re
    timestamp = parsed_data.get('域名创建时间', '')

    if not timestamp:
        return -1

    try:
        if isinstance(timestamp, (int, float)):
            from datetime import datetime, timezone
            return (datetime.now(timezone.utc) - datetime.fromtimestamp(timestamp, timezone.utc)).days

        ts_match = re.search(r'\d{10}', str(timestamp))
        if ts_match:
            from datetime import datetime, timezone
            return (datetime.now(timezone.utc) - datetime.fromtimestamp(int(ts_match.group()), timezone.utc)).days
    except:
        pass

    return -1


def is_overseas_ip(parsed_data: Dict[str, Any]) -> bool:
    """IP所属地是否为中国大陆境外"""
    ip_location = parsed_data.get('IP所属地', '')

    if not ip_location:
        return True

    # 香港、澳门、台湾、海外等被视为境外（优先级高）
    overseas_keywords = ['香港', '澳门', '台湾', '海外', '美国', '日本', '韩国',
                       '新加坡', '马来西亚', '菲律宾', '泰国', '越南', '印度',
                       '欧洲', '德国', '法国', '英国', '俄罗斯', '加拿大',
                       '澳大利亚', '新西兰', '柬埔寨']

    ip_lower = ip_location.lower()

    # 优先检查境外关键词
    for kw in overseas_keywords:
        if kw in ip_lower:
            return True

    # 然后检查大陆城市关键词
    mainland_china_keywords = ['北京', '上海', '广东', '深圳', '浙江', '江苏', '四川',
                              '湖北', '湖南', '河南', '河北', '山东', '山西', '安徽',
                              '福建', '江西', '广西', '海南', '重庆', '天津', '辽宁',
                              '吉林', '黑龙江', '内蒙古', '新疆', '西藏', '青海', '甘肃',
                              '宁夏', '陕西', '云南', '贵州']

    for kw in mainland_china_keywords:
        if kw in ip_lower:
            return False

    # 如果IP信息中包含"中国"但不包含上述任何关键词，也视为境外（可能是香港）
    if '中国' in ip_lower:
        return True

    return True


# ==================== ICP备案相关 ====================

def get_icp_subject_type(parsed_data: Dict[str, Any]) -> str:
    """ICP备案主体属性: 企业/政府机构/事业单位/其他"""
    icp_subject = parsed_data.get('ICP备案主体', '')

    if not icp_subject:
        return '其他'

    government_keywords = ['政府', '公安局', '法院', '检察院', '税务局', '工商局',
                         '卫生局', '教育局', '民政局', '财政局', '人社局']
    institution_keywords = ['医院', '学校', '大学', '学院', '研究院', '研究所',
                           '博物馆', '图书馆', '医院', '卫生院', '中心']

    for kw in government_keywords:
        if kw in icp_subject:
            return '政府机构'

    for kw in institution_keywords:
        if kw in icp_subject:
            return '事业单位'

    if any(kw in icp_subject for kw in ['公司', '企业', '集团', '有限', '股份']):
        return '企业'

    return '其他'


# ==================== 政务合作相关 ====================

def is_suspicious_gov_coop(parsed_data: Dict[str, Any]) -> bool:
    """是否疑似政务合作"""
    text_content = _get_combined_text(parsed_data)

    gov_coop_keywords = [
        '政务', '政府合作', '政府采购', '政务服务',
        '事业单位', '公立', '官方合作',
        '教育局', '卫生局', '民政局'
    ]

    text_lower = text_content.lower()
    return any(kw in text_lower for kw in gov_coop_keywords)


# ==================== 风险级别映射 ====================

RISK_LEVEL_MAP = {
    '仿冒网站': '高危',
    '钓鱼欺诈': '高危',
    '钓鱼欺诈（含登录框）': '高危',
    '品牌侵权': '中危',
    '疑似暴露资产': '中危',
    '商标滥用': '低危',
    'ICP滥用': '低危',
    '疑似商务合作': '低危',
    '疑似政务合作': '低危',
    '舆论投诉': '低危',
    '其他': '低危',
    '无害网站': '低危',
    '疑似仿冒资产': '中危',
}


def get_risk_level(category: str) -> str:
    """获取分类对应的风险级别"""
    return RISK_LEVEL_MAP.get(category, '低危')


# ==================== 新增判断函数 ====================

def is_domain_new_or_overseas(parsed_data: Dict[str, Any]) -> bool:
    """域名注册时间<365天 或 IP所属地为中国大陆境外"""
    domain_age_days = parsed_data.get('域名注册天数', -1)

    if domain_age_days < 0:
        domain_age_days = _estimate_domain_age_days(parsed_data)

    is_new = domain_age_days >= 0 and domain_age_days < 365

    is_overseas = is_overseas_ip(parsed_data)

    return is_new or is_overseas


def is_brand_in_title(parsed_data: Dict[str, Any]) -> bool:
    """网站标题是否包含品牌泛化信息"""
    brand_owner = parsed_data.get('保护的品牌主体', '')
    web_title = parsed_data.get('当前网站标题', '')

    if not brand_owner or not web_title:
        return False

    title_lower = web_title.lower()
    brand_keywords = _extract_brand_keywords(brand_owner)

    for kw in brand_keywords:
        if len(kw) >= 2 and kw.lower() in title_lower:
            return True

    return False


def is_entertainment_gambling_porn(parsed_data: Dict[str, Any]) -> bool:
    """网站标题是否与娱乐、股票、博彩、色情等相关"""
    entertainment_categories = ['色情/裸聊', '赌博/博彩', '色情/低俗', '娱乐']

    return has_gray_black_category(parsed_data, entertainment_categories)


def is_entertainment_gambling_porn_from_browser(parsed_data: Dict[str, Any]) -> bool:
    """动态渲染后网页是否包含娱乐、博彩、色情等信息"""
    return parsed_data.get('_has_entertainment_gambling_porn', False)


def is_login_form_related_title(parsed_data: Dict[str, Any]) -> bool:
    """网站标题是否与登录、表单填写相关"""
    web_title = parsed_data.get('当前网站标题', '')
    if not web_title:
        return False

    title_lower = web_title.lower()
    login_title_keywords = [
        '登录', '登陆', 'login', '注册', 'signup',
        '表单', '填写', '验证', '认证'
    ]

    return any(kw in title_lower for kw in login_title_keywords)


def has_brand_sales_info(parsed_data: Dict[str, Any]) -> bool:
    """YOLO/OCR非空 且 动态渲染后网页包含客户品牌销售信息"""
    if yolo_ocr_empty(parsed_data):
        return False

    text_content = _get_combined_text(parsed_data)
    brand_owner = parsed_data.get('保护的品牌主体', '')

    if not brand_owner:
        return False

    detector = _get_sales_detector()
    if detector is None:
        return _has_brand_sales_info_simple(parsed_data, text_content, brand_owner)

    url = parsed_data.get('URL', '')

    result = detector.detect(url, text_content)

    brand_keywords = _extract_brand_keywords(brand_owner)
    text_lower = text_content.lower()

    has_brand_in_text = any(kw.lower() in text_lower for kw in brand_keywords if len(kw) >= 2)

    has_sales_in_text = result.has_sales

    return has_brand_in_text and has_sales_in_text


def _has_brand_sales_info_simple(parsed_data: Dict[str, Any], text_content: str, brand_owner: str) -> bool:
    """降级方案：使用简单关键词匹配检测品牌销售信息"""
    sales_keywords = [
        '购买', '购买渠道', '授权', '正品', '销售',
        '价格', '报价', '优惠', '折扣', '促销',
        '正品保证', '官方销售', '厂家直销'
    ]

    brand_keywords = _extract_brand_keywords(brand_owner)
    text_lower = text_content.lower()

    has_brand = any(kw.lower() in text_lower for kw in brand_keywords if len(kw) >= 2)
    has_sales = any(kw in text_lower for kw in sales_keywords)

    return has_brand and has_sales