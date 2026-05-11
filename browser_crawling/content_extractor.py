"""Content extractor for extracting text from HTML"""
import re
from typing import List, Dict, Any
from bs4 import BeautifulSoup


class ContentExtractor:
    """Extracts clean text content from HTML"""

    def extract_text(self, html: str) -> str:
        """Extract clean text from HTML"""
        if not html:
            return ""

        soup = BeautifulSoup(html, 'html.parser')

        # Remove script and style elements
        for script in soup(["script", "style", "noscript"]):
            script.decompose()

        # Get text
        text = soup.get_text(separator=' ', strip=True)

        # Clean up whitespace
        text = re.sub(r'\s+', ' ', text)

        return text

    def extract_links(self, html: str) -> List[Dict[str, str]]:
        """Extract links from HTML"""
        if not html:
            return []

        soup = BeautifulSoup(html, 'html.parser')
        links = []

        for a in soup.find_all('a', href=True):
            href = a.get('href', '')
            text = a.get_text(strip=True)
            links.append({
                'href': href,
                'text': text[:200]
            })

        return links

    def extract_forms(self, html: str) -> List[Dict[str, Any]]:
        """Extract forms from HTML"""
        if not html:
            return []

        soup = BeautifulSoup(html, 'html.parser')
        forms = []

        for form in soup.find_all('form'):
            form_info = {
                'action': form.get('action', ''),
                'method': form.get('method', 'get').upper(),
                'inputs': []
            }

            for inp in form.find_all(['input', 'textarea', 'select']):
                form_info['inputs'].append({
                    'name': inp.get('name', ''),
                    'type': inp.get('type', 'text'),
                    'id': inp.get('id', ''),
                })

            forms.append(form_info)

        return forms

    def extract_meta(self, html: str) -> Dict[str, str]:
        """Extract meta information from HTML"""
        if not html:
            return {}

        soup = BeautifulSoup(html, 'html.parser')
        meta = {}

        # Title
        title = soup.find('title')
        if title:
            meta['title'] = title.get_text(strip=True)

        # Meta tags
        for m in soup.find_all('meta'):
            name = m.get('name') or m.get('property', '')
            content = m.get('content', '')
            if name and content:
                meta[name] = content

        return meta