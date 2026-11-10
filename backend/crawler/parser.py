from html.parser import HTMLParser
from typing import List

class SimpleHTMLLinkParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links: List[str] = []
        self.forms: List[dict] = []
        self.scripts: List[str] = []
        self.meta_refresh: List[str] = []
        self.current_form = None

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
            self.current_form = self.forms[-1]
        elif tag == "input" and self.current_form is not None:
            self.current_form["inputs"].append({
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

    def handle_endtag(self, tag):
        if tag == "form":
            self.current_form = None

    def error(self, message):
        pass
