"""Redirect detector"""
import asyncio
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse, parse_qs


class RedirectDetector:
    """Detects redirect chains in URLs"""

    def __init__(self):
        self.max_hops = 10

    async def detect(self, html_content: str, initial_url: str) -> Dict[str, Any]:
        """Detect redirect chain from HTML content"""
        redirect_chain = []

        # Simple meta refresh detection
        if html_content:
            import re
            meta_refresh = re.search(
                r'<meta[^>]*refresh[^>]*content=["\'](?:[^"\']*;)?\s*url=["\']?([^"\'>\s]+)',
                html_content,
                re.IGNORECASE
            )
            if meta_refresh:
                redirect_chain.append({
                    'type': 'meta_refresh',
                    'url': meta_refresh.group(1),
                    'source': 'meta_tag'
                })

        return {
            'has_redirect': len(redirect_chain) > 0,
            'redirect_chain': redirect_chain,
            'final_url': redirect_chain[-1]['url'] if redirect_chain else initial_url
        }

    def _is_suspicious_redirect(self, from_url: str, to_url: str) -> bool:
        """Check if redirect is suspicious"""
        if not to_url:
            return True

        parsed_from = urlparse(from_url)
        parsed_to = urlparse(to_url)

        # Cross-domain redirect
        if parsed_from.netloc != parsed_to.netloc:
            return True

        return False