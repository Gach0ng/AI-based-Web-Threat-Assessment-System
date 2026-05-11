"""Reporter for generating analysis reports"""
from typing import Dict, Any, List
import json
from datetime import datetime


def generate_report(
    url: str,
    browser_result,
    redirect_chain: Dict[str, Any],
    sensitive_report,
    link_report: Dict[str, Any],
    diff: Dict[str, Any],
    gray_black_report: Dict[str, Any]
) -> Dict[str, Any]:
    """Generate comprehensive analysis report"""
    report = {
        'url': url,
        'timestamp': datetime.now().isoformat(),
        'status': {
            'js_enabled_success': browser_result.js_enabled is not None,
            'js_disabled_success': browser_result.js_disabled is not None,
        },
        'sensitive_elements': {
            'login_form_count': sensitive_report.login_form_count,
            'high_risk_forms': sensitive_report.high_risk_forms,
            'password_field_count': sensitive_report.password_field_count,
            'input_count': sensitive_report.input_count,
            'forms': [
                {
                    'type': f.form_type,
                    'risk': f.risk,
                    'has_password_field': f.has_password_field,
                    'action_url': f.action_url,
                }
                for f in sensitive_report.forms
            ]
        },
        'link_analysis': link_report,
        'differences': diff,
        'gray_black_list': gray_black_report,
    }

    return report


def save_report(report: Dict[str, Any], output_path: str):
    """Save report to JSON file"""
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(report, f, ensure_ascii=False, indent=2)


def print_summary(report: Dict[str, Any]):
    """Print summary of report"""
    print(f"\nURL: {report['url']}")
    print(f"Timestamp: {report['timestamp']}")

    status = report.get('status', {})
    print(f"\nRendering Status:")
    print(f"  JS Enabled: {'OK' if status.get('js_enabled_success') else 'FAILED'}")
    print(f"  JS Disabled: {'OK' if status.get('js_disabled_success') else 'FAILED'}")

    sensitive = report.get('sensitive_elements', {})
    if sensitive.get('login_form_count', 0) > 0:
        print(f"\n[!] Login/Register Forms: {sensitive['login_form_count']} "
              f"(High Risk: {sensitive.get('high_risk_forms', 0)})")
    else:
        print(f"\n[+] Login/Register Forms: None detected")

    links = report.get('link_analysis', {})
    if links.get('suspicious_count', 0) > 0:
        print(f"\n[!] Suspicious Links: {links['suspicious_count']}")
    else:
        print(f"\n[+] Suspicious Links: None")

    diff = report.get('differences', {})
    if diff.get('text_identical', True):
        print(f"\n[+] JS On/Off Content: Identical")
    else:
        sim = diff.get('content_similarity', 0)
        print(f"\n[!] JS On/Off Content: Different (Similarity: {sim:.1%})")