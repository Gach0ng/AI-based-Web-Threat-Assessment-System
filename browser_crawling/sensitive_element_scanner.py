"""Sensitive element scanner for detecting forms, inputs, etc."""
from dataclasses import dataclass, field
from typing import List, Dict, Any
from bs4 import BeautifulSoup
import re


@dataclass
class FormInfo:
    """Form information"""
    form_type: str = "unknown"
    has_password_field: bool = False
    has_username_field: bool = False
    has_hidden_fields: bool = False
    action_url: str = ""
    risk: str = "low"
    fields: List[Dict[str, str]] = field(default_factory=list)


@dataclass
class ScanReport:
    """Scan report for sensitive elements"""
    forms: List[FormInfo] = field(default_factory=list)
    password_field_count: int = 0
    input_count: int = 0
    login_form_count: int = 0
    high_risk_forms: int = 0


class SensitiveElementScanner:
    """Scans HTML for sensitive elements like login forms"""

    def __init__(self):
        self.login_keywords = ['登录', '登陆', 'login', 'signin', '注册', 'signup', 'register']
        self.password_keywords = ['password', '密码', 'passwd', 'pwd']
        self.username_keywords = ['username', '用户名', 'account', '账号', 'email', 'phone', 'mobile']

    def scan(self, html_content: str) -> ScanReport:
        """Scan HTML content for sensitive elements"""
        if not html_content:
            return ScanReport()

        soup = BeautifulSoup(html_content, 'html.parser')
        report = ScanReport()

        # Find all forms
        for form in soup.find_all('form'):
            form_info = self._analyze_form(form)
            report.forms.append(form_info)

            if form_info.has_password_field:
                report.password_field_count += 1

            if form_info.form_type == 'login':
                report.login_form_count += 1
                if form_info.risk == 'high':
                    report.high_risk_forms += 1

        # Count inputs
        report.input_count = len(soup.find_all(['input', 'textarea']))

        return report

    def _analyze_form(self, form) -> FormInfo:
        """Analyze a single form"""
        form_info = FormInfo()

        # Get action URL
        action = form.get('action', '')
        form_info.action_url = action

        # Analyze inputs
        inputs = form.find_all(['input', 'textarea'])
        for inp in inputs:
            inp_type = inp.get('type', 'text').lower()
            inp_name = inp.get('name', '').lower()
            inp_id = inp.get('id', '').lower()

            field_info = {'type': inp_type, 'name': inp_name, 'id': inp_id}
            form_info.fields.append(field_info)

            if inp_type == 'password':
                form_info.has_password_field = True

            # Check for username fields
            for kw in self.username_keywords:
                if kw in inp_name or kw in inp_id:
                    form_info.has_username_field = True
                    break

        # Check for hidden fields
        hidden = form.find_all(['input'], type='hidden')
        if hidden:
            form_info.has_hidden_fields = True

        # Determine form type
        form_html = str(form).lower()
        for kw in self.login_keywords:
            if kw in form_html:
                form_info.form_type = 'login'
                break

        # Determine risk level
        if form_info.has_password_field and not form_info.has_username_field:
            form_info.risk = 'high'
        elif form_info.has_password_field and form_info.has_username_field:
            # Check if action URL is suspicious
            if self._is_suspicious_action(action):
                form_info.risk = 'high'
            else:
                form_info.risk = 'medium'

        return form_info

    def _is_suspicious_action(self, action: str) -> bool:
        """Check if form action URL is suspicious"""
        if not action:
            return True  # Empty action is suspicious

        action_lower = action.lower()

        # Suspicious patterns
        suspicious_patterns = [
            'eval', 'document.write', 'javascript:', 'void(',
            'onclick', 'onerror', 'onload'
        ]

        for pattern in suspicious_patterns:
            if pattern in action_lower:
                return True

        return False