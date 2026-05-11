"""
配置驱动的决策树引擎
"""
import logging
from typing import Any, Dict, List, Optional, Tuple

from . import conditions
from .decision_tree_config import DecisionTreeConfig, get_loader

logger = logging.getLogger(__name__)

# 条件函数注册表
_CONDITION_FUNCTIONS: Dict[str, Any] = {
    "check_threat_related": conditions.check_threat_related,
    "check_official_whitelist": conditions.check_official_whitelist,
    "is_ip_access": conditions.is_ip_access,
    "is_icp_empty": conditions.is_icp_empty,
    "has_login_form_after_dynamic_render": conditions.has_login_form_after_dynamic_render,
    "get_js_diff_ratio": conditions.get_js_diff_ratio,
    "has_gray_black_category": conditions.has_gray_black_category,
    "has_brand_keywords": conditions.has_brand_keywords,
    "yolo_ocr_empty": conditions.yolo_ocr_empty,
    "yolo_ocr_contains_attack": conditions.yolo_ocr_contains_attack,
    "is_new_domain_overseas": conditions.is_new_domain_overseas,
    "get_icp_subject_type": conditions.get_icp_subject_type,
    "is_suspicious_gov_coop": conditions.is_suspicious_gov_coop,
    "get_risk_level": conditions.get_risk_level,
    "is_domain_new_or_overseas": conditions.is_domain_new_or_overseas,
    "has_brand_sales_info": conditions.has_brand_sales_info,
    "is_brand_in_title": conditions.is_brand_in_title,
    "is_entertainment_gambling_porn": conditions.is_entertainment_gambling_porn,
    "is_entertainment_gambling_porn_from_browser": conditions.is_entertainment_gambling_porn_from_browser,
    "is_login_form_related_title": conditions.is_login_form_related_title,
    "is_wd_brand_icon_cooperation": conditions.is_wd_brand_icon_cooperation,
}


class HotReloadDecisionTree:
    """热加载决策树引擎，对外接口与旧 ThreatDecisionTree 兼容"""

    def __init__(self, config_path: Optional[str] = None):
        from .decision_tree_config import init_loader, DecisionTreeConfig

        self._loader = init_loader(config_path)
        self._loader.register_change_callback(self._on_config_changed)
        self._current_config: Optional[DecisionTreeConfig] = self._loader.get_config()

    def _on_config_changed(self):
        """配置变更回调"""
        new_config = self._loader.get_config()
        if new_config:
            self._current_config = new_config
            logger.info("决策树引擎已切换到新配置")

    def classify(
        self, parsed_data: Dict[str, Any], threat_intel: Dict[str, Any]
    ) -> Tuple[str, str, List[str], Dict[str, Any]]:
        """执行威胁分类决策"""
        self._loader.check_and_reload()

        config = self._current_config
        if config is None:
            logger.error("决策树配置未加载，使用默认分类")
            return "其他", "低危", [], {"理由": ["配置加载失败"]}

        decision_path: List[str] = []
        computed_values: Dict[str, Any] = {}
        try:
            result = self._traverse(config, config.root, parsed_data, threat_intel, decision_path, computed_values)
        except Exception as e:
            logger.error(f"决策树遍历异常: {e}", exc_info=True)
            return "其他", "低危", decision_path, {"理由": [f"决策树执行异常: {e}"]}

        category, risk_level, reasons = result
        return category, risk_level, decision_path, {"理由": reasons}

    def _traverse(
        self,
        config: DecisionTreeConfig,
        node_id: str,
        parsed_data: Dict[str, Any],
        threat_intel: Dict[str, Any],
        decision_path: List[str],
        computed_values: Dict[str, Any],
    ) -> Tuple[str, str, List[str]]:
        node = config.get_node(node_id)
        if node is None:
            logger.error(f"决策树节点不存在: {node_id}")
            return "其他", "低危", ["节点不存在"]

        node_type = node.get("type", "")

        if node_type == "result":
            return self._resolve_result(node, computed_values, decision_path)

        if node_type == "condition":
            return self._traverse_condition(config, node, parsed_data, threat_intel, decision_path, computed_values)

        if node_type == "in_list":
            return self._traverse_in_list(config, node, parsed_data, threat_intel, decision_path, computed_values)

        if node_type == "or_threshold":
            return self._traverse_or_threshold(config, node, parsed_data, threat_intel, decision_path, computed_values)

        logger.error(f"未知节点类型: {node_type}")
        return "其他", "低危", decision_path

    def _traverse_condition(
        self,
        config: DecisionTreeConfig,
        node: Dict[str, Any],
        parsed_data: Dict[str, Any],
        threat_intel: Dict[str, Any],
        decision_path: List[str],
        computed_values: Dict[str, Any],
    ) -> Tuple[str, str, List[str]]:
        cond_key = node["condition_key"]
        cond_def = config.conditions.get(cond_key, {})
        func = _CONDITION_FUNCTIONS.get(cond_def.get("name", ""))

        if func is None:
            logger.error(f"条件函数未注册: {cond_key}")
            decision_path.append(f"{cond_key}→函数未找到")
            return "其他", "低危", decision_path

        import inspect
        sig = inspect.signature(func)
        param_names = list(sig.parameters.keys())
        if param_names == ["threat_intel"]:
            bool_val = func(threat_intel)
        elif param_names == ["parsed_data"]:
            bool_val = func(parsed_data)
        elif param_names == ["parsed_data", "threat_intel"]:
            bool_val = func(parsed_data, threat_intel)
        else:
            bool_val = func(threat_intel) if "threat_intel" in param_names else func(parsed_data)

        computed_values[cond_key] = bool_val

        if bool_val:
            decision_path.append(f"{cond_key}→是")
            goto = node.get("true_goto", "")
        else:
            decision_path.append(f"{cond_key}→否")
            goto = node.get("false_goto", "")

        if not goto:
            logger.error(f"节点 {node['id']} 缺少跳转目标")
            return "其他", "低危", decision_path

        return self._traverse(config, goto, parsed_data, threat_intel, decision_path, computed_values)

    def _traverse_in_list(
        self,
        config: DecisionTreeConfig,
        node: Dict[str, Any],
        parsed_data: Dict[str, Any],
        threat_intel: Dict[str, Any],
        decision_path: List[str],
        computed_values: Dict[str, Any],
    ) -> Tuple[str, str, List[str]]:
        cond_key = node["condition_key"]
        cond_def = config.conditions.get(cond_key, {})
        func = _CONDITION_FUNCTIONS.get(cond_def.get("name", ""))

        if func is None:
            logger.error(f"条件函数未注册: {cond_key}")
            decision_path.append(f"{cond_key}→函数未找到")
            return "其他", "低危", decision_path

        import inspect
        sig = inspect.signature(func)
        param_names = list(sig.parameters.keys())
        # 根据参数名判断调用方式，不只是参数数量
        if param_names == ["threat_intel"]:
            value = func(threat_intel)
        elif param_names == ["parsed_data"]:
            value = func(parsed_data)
        elif param_names == ["parsed_data", "threat_intel"]:
            value = func(parsed_data, threat_intel)
        else:
            # fallback: 优先传 threat_intel
            value = func(threat_intel) if "threat_intel" in param_names else func(parsed_data)

        computed_values[cond_key] = value
        values_list = node.get("values", [])

        if value in values_list:
            decision_path.append(f"{cond_key}→{value}∈{values_list}")
            goto = node.get("true_goto", "")
        else:
            decision_path.append(f"{cond_key}→{value}∉{values_list}")
            goto = node.get("false_goto", "")

        if not goto:
            logger.error(f"节点 {node['id']} 缺少跳转目标")
            return "其他", "低危", decision_path

        return self._traverse(config, goto, parsed_data, threat_intel, decision_path, computed_values)

    def _traverse_or_threshold(
        self,
        config: DecisionTreeConfig,
        node: Dict[str, Any],
        parsed_data: Dict[str, Any],
        threat_intel: Dict[str, Any],
        decision_path: List[str],
        computed_values: Dict[str, Any],
    ) -> Tuple[str, str, List[str]]:
        cond_key = node["condition_key"]
        or_cond_key = node.get("or_condition_key", "")
        threshold = node.get("threshold", 0.5)
        cond_def = config.conditions.get(cond_key, {})
        or_cond_def = config.conditions.get(or_cond_key, {})

        func = _CONDITION_FUNCTIONS.get(cond_def.get("name", ""))
        or_func = _CONDITION_FUNCTIONS.get(or_cond_def.get("name", ""))

        # 获取主条件值（数值）
        if func:
            import inspect
            sig = inspect.signature(func)
            param_names = list(sig.parameters.keys())
            if param_names == ["threat_intel"]:
                main_val = func(threat_intel)
            elif param_names == ["parsed_data"]:
                main_val = func(parsed_data)
            else:
                main_val = func(parsed_data, threat_intel)
        else:
            main_val = 0.0

        computed_values[cond_key] = main_val

        # 获取 OR 条件值（布尔）
        or_bool = False
        if or_func and or_cond_key:
            import inspect
            sig = inspect.signature(or_func)
            param_names = list(sig.parameters.keys())
            if param_names == ["threat_intel"]:
                or_bool = or_func(threat_intel)
            elif param_names == ["parsed_data"]:
                or_bool = or_func(parsed_data)
            else:
                or_bool = or_func(parsed_data, threat_intel)
            computed_values[or_cond_key] = or_bool

        diff_ratio = computed_values.get("js_diff_ratio", 0.0)
        entertainment = computed_values.get("entertainment_from_browser", False)

        is_true = (diff_ratio > threshold) or entertainment

        if is_true:
            decision_path.append(f"js_diff={diff_ratio:.1%}>={threshold} or entertainment={entertainment}→是")
            goto = node.get("true_goto", "")
        else:
            decision_path.append(f"js_diff={diff_ratio:.1%}<{threshold} and entertainment={entertainment}→否")
            goto = node.get("false_goto", "")

        if not goto:
            logger.error(f"节点 {node['id']} 缺少跳转目标")
            return "其他", "低危", decision_path

        return self._traverse(config, goto, parsed_data, threat_intel, decision_path, computed_values)

    def _resolve_result(
        self,
        node: Dict[str, Any],
        computed_values: Dict[str, Any],
        decision_path: List[str],
    ) -> Tuple[str, str, List[str]]:
        category = node.get("category", "其他")
        risk_level = node.get("risk_level", "低危")

        reasons: List[str] = []

        # 静态 reasons
        for r in node.get("reasons", []):
            reasons.append(r)

        # 模板 reasons
        for tmpl in node.get("reason_template", []):
            if tmpl == "js_diff_or_entertainment":
                diff_ratio = computed_values.get("js_diff_ratio", 0.0)
                entertainment = computed_values.get("entertainment_from_browser", False)
                parts = []
                if diff_ratio > 0.5:
                    parts.append(f"JS差异度{diff_ratio:.1%}>50%")
                if entertainment:
                    parts.append("包含娱乐/博彩/色情信息")
                reasons.extend(parts if parts else ["满足高危条件"])
            elif tmpl == "js_diff_ratio_under_50":
                diff_ratio = computed_values.get("js_diff_ratio", 0.0)
                reasons.append(f"动态渲染包含登录表单，JS差异度{diff_ratio:.1%}≤50%")
            elif tmpl == "ICP备案主体为{icp_type}":
                icp_type = computed_values.get("icp_subject_type", "未知")
                reasons.append(f"ICP备案主体为{icp_type}")
            else:
                reasons.append(tmpl)

        return category, risk_level, reasons
