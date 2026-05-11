"""
决策树配置加载器 + 热加载
"""
import json
import logging
import os
import time
from pathlib import Path
from threading import Lock
from typing import Any, Callable, Dict, Optional

logger = logging.getLogger(__name__)

_config_dir = Path(__file__).parent.parent / "config" / "decision_tree"
DEFAULT_CONFIG_PATH = _config_dir / "rule.json"


class DecisionTreeConfig:
    """决策树配置对象"""

    def __init__(self, config_path: str):
        self.config_path = config_path
        self.version: str = ""
        self.metadata: Dict[str, str] = {}
        self.conditions: Dict[str, Dict[str, Any]] = {}
        self.nodes: list = []
        self.root: str = ""
        self._node_map: Dict[str, Dict[str, Any]] = {}
        self._last_mtime: float = 0.0

    def build_node_map(self):
        self._node_map = {node["id"]: node for node in self.nodes}

    def get_node(self, node_id: str) -> Optional[Dict[str, Any]]:
        return self._node_map.get(node_id)


class ConfigLoader:
    """配置加载器，支持热加载"""

    def __init__(self, config_path: Optional[str] = None):
        self._config_path = Path(config_path) if config_path else DEFAULT_CONFIG_PATH
        self._config: Optional[DecisionTreeConfig] = None
        self._lock = Lock()
        self._last_check: float = 0
        self._reload_interval: float = 2.0
        self._change_callbacks: list = []
        self._config = self._load()

    def _load(self) -> DecisionTreeConfig:
        """从文件加载配置"""
        with open(self._config_path, "r", encoding="utf-8") as f:
            raw = json.load(f)

        cfg = DecisionTreeConfig(str(self._config_path))
        cfg.version = raw.get("version", "1.0")
        cfg.metadata = raw.get("metadata", {})
        cfg.conditions = raw.get("conditions", {})
        cfg.nodes = raw.get("nodes", [])
        cfg.root = raw.get("root", "root")
        cfg._last_mtime = os.path.getmtime(self._config_path)
        cfg.build_node_map()
        return cfg

    def reload(self) -> bool:
        """主动重载配置，返回是否成功"""
        try:
            new_config = self._load()
            with self._lock:
                self._config = new_config
            self._notify_change()
            logger.info(f"决策树配置热重载成功: version={new_config.version}")
            return True
        except Exception as e:
            logger.error(f"决策树配置热重载失败: {e}")
            return False

    def check_and_reload(self) -> bool:
        """检查配置是否变更，若是则热重载，返回是否发生了重载"""
        if time.time() - self._last_check < self._reload_interval:
            return False
        self._last_check = time.time()

        try:
            current_mtime = os.path.getmtime(self._config_path)
        except OSError:
            return False

        config = self._get_config()
        if config is None or current_mtime != config._last_mtime:
            return self.reload()
        return False

    def _get_config(self) -> Optional[DecisionTreeConfig]:
        with self._lock:
            return self._config

    def get_config(self) -> Optional[DecisionTreeConfig]:
        """获取当前配置（可能是旧配置）"""
        with self._lock:
            return self._config

    def register_change_callback(self, callback: Callable[[], None]):
        """注册配置变更回调"""
        self._change_callbacks.append(callback)

    def _notify_change(self):
        for cb in self._change_callbacks:
            try:
                cb()
            except Exception as e:
                logger.error(f"配置变更回调执行失败: {e}")


# 全局加载器单例
_loader: Optional[ConfigLoader] = None


def init_loader(config_path: Optional[str] = None) -> ConfigLoader:
    global _loader
    _loader = ConfigLoader(config_path)
    return _loader


def get_loader() -> ConfigLoader:
    global _loader
    if _loader is None:
        _loader = init_loader()
    return _loader
