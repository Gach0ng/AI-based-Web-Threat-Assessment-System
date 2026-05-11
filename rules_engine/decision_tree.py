"""
Web威胁分类决策树

- 热加载版：读取 config/decision_tree/rule.json，配置变更自动生效
- 降级保障：配置加载失败时记录错误，继续使用上一次成功加载的配置
"""
import logging
from typing import Any, Dict, List, Tuple

from .decision_tree_engine import HotReloadDecisionTree

logger = logging.getLogger(__name__)

ThreatDecisionTree = HotReloadDecisionTree

_decision_tree = HotReloadDecisionTree()


def classify_threat(
    parsed_data: Dict[str, Any], threat_intel: Dict[str, Any]
) -> Tuple[str, str, List[str], Dict[str, Any]]:
    """执行威胁分类决策"""
    return _decision_tree.classify(parsed_data, threat_intel)
