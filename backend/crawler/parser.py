from html.parser import HTMLParser
from typing import List

class SimpleHTMLLinkParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links: List[str] = []
        self.forms: List[dict] = []
        self.scripts: List[str] = []
        self.meta_refresh: List[str] = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "a" and attrs.get("href"):
            self.links.append(attrs["href"])
        elif tag == "form":
            self.forms.append({
                "action": attrs.get("action", ""),
                "method": attrs.get("method", "get").lower(),
                "inputs": [],
            })
        elif tag == "input" and self.forms:
            self.forms[-1]["inputs"].append({
                "name": attrs.get("name"),
                "type": attrs.get("type", "text"),
                "value": attrs.get("value", ""),
            })
        elif tag == "script" and attrs.get("src"):
            self.scripts.append(attrs["src"])
        elif tag == "meta" and attrs.get("http-equiv", "").lower() == "refresh":
            content = attrs.get("content", "")
            if "url=" in content.lower():
                self.meta_refresh.append(content)

    def error(self, message):
        pass
