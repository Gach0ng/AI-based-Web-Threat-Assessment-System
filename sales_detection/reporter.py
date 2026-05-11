#!/usr/bin/env python3
"""Reporter for sales detection results"""


class Reporter:
    """Generates reports for sales detection"""

    @staticmethod
    def generate(result) -> str:
        """Generate human-readable report"""
        lines = []
        lines.append("=" * 60)
        lines.append(f"URL: {result.url}")
        lines.append(f"文本长度: {result.text_length} 字符")
        lines.append("-" * 60)

        if result.has_sales:
            lines.append(f"[!] 检测到销售行为")
            lines.append(f"风险级别: {result.risk_level}")
            lines.append(f"匹配类别: {', '.join(result.matched_categories)}")
            lines.append(f"匹配关键词数: {len(result.matched_keywords)}")

            if result.details.get('institution_matches'):
                lines.append(f"机构关键词: {', '.join(result.details['institution_matches'])}")
        else:
            lines.append(f"[+] 未检测到销售行为")

        lines.append("=" * 60)
        return '\n'.join(lines)