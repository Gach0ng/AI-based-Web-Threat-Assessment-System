"""Black type mapper for blacklist API results"""
from typing import Dict

# 黑类型映射表
BLACK_TYPE_MAP = {
    # Level 60 + ST 10/30 combinations
    (60, 10, 100): ("赌博", "灰"),
    (60, 10, 101): ("色情/低俗", "灰"),
    (60, 10, 102): ("虚假广告", "灰"),
    (60, 10, 103): ("违规药品", "灰"),
    (60, 10, 104): ("违规医疗器械", "灰"),
    (60, 10, 105): ("假冒商品", "灰"),
    (60, 10, 106): ("违规食品", "灰"),
    (60, 10, 107): ("网络诈骗", "黑"),
    (60, 10, 108): ("钓鱼网站", "黑"),
    (60, 10, 109): ("木马病毒", "黑"),
    (60, 10, 110): ("恶意插件", "黑"),
    (60, 10, 111): ("黑客站点", "黑"),
    (60, 10, 112): ("非法赌博", "黑"),
    (60, 10, 113): ("非法色情", "黑"),
    (60, 10, 151): ("仿冒网站", "黑"),

    # Level 60 + ST 30
    (60, 30, 100): ("博彩", "灰"),
    (60, 30, 101): ("色情", "灰"),
    (60, 30, 102): ("虚假广告", "灰"),
    (60, 30, 103): ("违规药品", "灰"),
    (60, 30, 104): ("违规医疗器械", "灰"),
    (60, 30, 105): ("假冒商品", "灰"),
    (60, 30, 106): ("违规食品", "灰"),
    (60, 30, 107): ("网络诈骗", "黑"),
    (60, 30, 108): ("钓鱼欺诈", "黑"),
    (60, 30, 109): ("木马病毒", "黑"),
    (60, 30, 110): ("恶意插件", "黑"),
    (60, 30, 111): ("黑客站点", "黑"),
    (60, 30, 151): ("仿冒网站", "黑"),

    # Level 0 + ST 30 (GwdInfo)
    (0, 30, 151): ("仿冒网站", "黑"),
    (0, 30, 152): ("品牌侵权", "中"),
    (0, 30, 153): ("商标滥用", "低"),
    (0, 30, 154): ("ICP滥用", "低"),
}


def map_black_type(level: int, st: int, sc: int, ssc: int) -> Dict[str, str]:
    """Map black type from blacklist API response values"""
    key = (level, st, sc)

    if key in BLACK_TYPE_MAP:
        category_name, suggested_level = BLACK_TYPE_MAP[key]
    else:
        # Fallback based on general patterns
        if sc == 151 or sc == 152:
            category_name = "仿冒网站"
            suggested_level = "黑"
        elif sc == 100:
            category_name = "赌博"
            suggested_level = "灰"
        elif sc == 101:
            category_name = "色情"
            suggested_level = "灰"
        elif sc >= 107 and sc <= 113:
            category_name = "网络诈骗"
            suggested_level = "黑"
        else:
            category_name = "其他"
            suggested_level = "灰"

    return {
        "category_name": category_name,
        "suggested_level": suggested_level
    }


def map_wd_info_type(level: int, st: int, sc: int, ssc: int, default_sc: int) -> Dict[str, str]:
    """Map info type from GwdInfo/WdInfo"""
    return map_black_type(level, st, sc, ssc)


# Quick lookup for common types
COMMON_TYPES = {
    "赌博": {"level": 60, "st": 10, "sc": 100},
    "色情": {"level": 60, "st": 10, "sc": 101},
    "钓鱼欺诈": {"level": 60, "st": 30, "sc": 108},
    "仿冒网站": {"level": 60, "st": 30, "sc": 151},
    "木马病毒": {"level": 60, "st": 10, "sc": 109},
}