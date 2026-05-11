"""
分类结果输出格式化
"""

from typing import Dict, Any, List
from .conditions import get_risk_level


def build_classification_output(
    parsed_data: Dict[str, Any],
    threat_intel: Dict[str, Any],
    category: str,
    risk_level: str,
    decision_path: List[str],
    reasoning: Dict[str, Any]
) -> Dict[str, Any]:
    """构建标准输出结构"""
    return {
        '检测URL': parsed_data.get('URL', ''),
        '关联品牌主体': parsed_data.get('保护的品牌主体', ''),
        '最终分类': category,
        '风险级别': risk_level,
        '决策路径': decision_path,
        '判定依据': {
            '分类': category,
            '理由': reasoning.get('理由', [])
        },
        '关键特征': _extract_key_features(parsed_data)
    }


def _extract_key_features(parsed_data: Dict[str, Any]) -> Dict[str, Any]:
    """提取关键特征"""
    features = {
        'is_ip_access': _check_ip_access(parsed_data),
        'has_icp_filing': not _is_icp_empty_fast(parsed_data),
        'has_login_form': _has_login_form_fast(parsed_data),
        'js_diff_ratio': parsed_data.get('JS开关页面相似度', 1.0),
    }

    icp_subject = parsed_data.get('ICP备案主体', '')
    if icp_subject and icp_subject not in ['', '无', 'None']:
        features['icp_subject_type'] = _get_icp_type_fast(icp_subject)

    return features


def _check_ip_access(parsed_data: Dict[str, Any]) -> bool:
    """快速检查IP访问"""
    import re
    url = parsed_data.get('URL', '')
    ip_pattern = r'^https?://(\d{1,3}\.){3}\d{1,3}'
    return bool(re.match(ip_pattern, url))


def _is_icp_empty_fast(parsed_data: Dict[str, Any]) -> bool:
    """快速检查ICP是否为空"""
    icp_no = parsed_data.get('ICP备案号', '')
    empty_values = ['', '无', 'None', 'null', '暂无', None]
    return icp_no in empty_values


def _has_login_form_fast(parsed_data: Dict[str, Any]) -> bool:
    """快速检查登录表单"""
    source = str(parsed_data.get('当前快照源码命中结果', '')).lower()
    return '<form' in source and 'password' in source


def _get_icp_type_fast(icp_subject: str) -> str:
    """快速获取ICP类型"""
    government_keywords = ['政府', '公安局', '法院', '检察院']
    institution_keywords = ['医院', '学校', '大学', '学院']

    for kw in government_keywords:
        if kw in icp_subject:
            return '政府机构'
    for kw in institution_keywords:
        if kw in icp_subject:
            return '事业单位'
    if any(kw in icp_subject for kw in ['公司', '企业', '集团']):
        return '企业'
    return '其他'