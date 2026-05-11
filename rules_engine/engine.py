"""
Web威胁分类 · 决策树引擎
基于流程图的纯条件判断逻辑
"""

from typing import Dict, List, Any

from .decision_tree import classify_threat, ThreatDecisionTree
from .classifier import build_classification_output
from .sc_api import get_threat_intel


class ThreatClassificationEngine:
    """
    Web威胁分类决策树引擎
    """

    def __init__(self):
        self.decision_tree = ThreatDecisionTree()

    def process(self, raw_data: Dict[str, Any], threat_intel: Dict[str, Any] = None) -> Dict[str, Any]:
        """处理单条数据"""
        parsed_data = self._parse_data(raw_data)

        if threat_intel is None:
            url = parsed_data.get('URL', '')
            domain = parsed_data.get('仿冒网站host', '')
            ip = parsed_data.get('A记录', '') or parsed_data.get('IP所属地', '')
            threat_intel = get_threat_intel(url, domain, ip)

        category, risk_level, decision_path, reasoning = self.decision_tree.classify(
            parsed_data, threat_intel
        )

        return build_classification_output(
            parsed_data, threat_intel, category, risk_level, decision_path, reasoning
        )

    def process_batch(self, data_list: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """批量处理"""
        return [self.process(data) for data in data_list]

    def _parse_data(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        """解析数据，处理缺失值和异常值"""
        if not raw_data:
            return {}

        parsed = raw_data.copy()

        bool_fields = ['是否包含登录表单', '是否包含可疑js脚本', '是否重定向']
        for field in bool_fields:
            if field in parsed:
                val = str(parsed[field]).strip()
                parsed[field] = '是' if val.lower() in ['true', 'yes', '1', '是'] else '否'

        if '当前是否存活' in parsed:
            val = str(parsed['当前是否存活']).strip()
            parsed['当前是否存活'] = '存活' if val in ['是', '存活', '活着', 'True'] else '否'

        return parsed


_engine = None


def get_engine() -> ThreatClassificationEngine:
    """获取引擎实例"""
    global _engine
    if _engine is None:
        _engine = ThreatClassificationEngine()
    return _engine


def process_threat(raw_data: Dict[str, Any], threat_intel: Dict[str, Any] = None) -> Dict[str, Any]:
    """便捷函数：处理威胁分类"""
    return get_engine().process(raw_data, threat_intel)