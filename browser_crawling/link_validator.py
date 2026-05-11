"""Link validator"""
from typing import List, Dict, Any
from urllib.parse import urlparse
import re


class LinkValidator:
    """Validates links for suspicious patterns"""

    def __init__(self, config=None):
        self.config = config
        self.suspicious_patterns = [
            r'eval\s*\(',
            r'document\.write',
            r'javascript:',
            r'onclick\s*=',
            r'onerror\s*=',
            r'onload\s*=',
        ]

    def validate_links(self, links: List[Dict[str, str]], base_url: str) -> Dict[str, Any]:
        """Validate a list of links"""
        suspicious_links = []
        external_links = []
        internal_links = []

        base_domain = urlparse(base_url).netloc if base_url else ''

        for link in links:
            href = link.get('href', '')
            text = link.get('text', '')

            if not href:
                continue

            parsed = urlparse(href)

            # Check for suspicious patterns
            for pattern in self.suspicious_patterns:
                if re.search(pattern, href, re.IGNORECASE):
                    suspicious_links.append({
                        'url': href,
                        'text': text[:100],
                        'reason': f'Suspicious pattern: {pattern}',
                        'risk_score': 0.9
                    })
                    continue

            # Classify as internal or external
            if parsed.netloc == base_domain or not parsed.netloc:
                internal_links.append({'url': href, 'text': text[:100]})
            else:
                external_links.append({'url': href, 'text': text[:100]})

        return {
            'total_links': len(links),
            'internal_count': len(internal_links),
            'external_count': len(external_links),
            'suspicious_count': len(suspicious_links),
            'suspicious_links': suspicious_links[:20],
            'internal_links': internal_links[:50],
            'external_links': external_links[:50],
        }