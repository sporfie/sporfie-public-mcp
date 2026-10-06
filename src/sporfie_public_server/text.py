"""Plain-text rendering helpers shared by the Sporfie API and Help Center clients."""

from __future__ import annotations

import re
from html.parser import HTMLParser

_BLOCK_TAGS = {"p", "br", "li", "h1", "h2", "h3", "h4", "h5", "tr", "div", "section"}


class _TextExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self._chunks: list[str] = []
        self._skip_depth = 0

    def handle_starttag(self, tag: str, attrs: list) -> None:
        if tag in ("script", "style"):
            self._skip_depth += 1
        elif tag in _BLOCK_TAGS:
            self._chunks.append("\n")

    def handle_endtag(self, tag: str) -> None:
        if tag in ("script", "style") and self._skip_depth:
            self._skip_depth -= 1

    def handle_data(self, data: str) -> None:
        if not self._skip_depth:
            self._chunks.append(data)

    def text(self) -> str:
        collapsed = re.sub(r"[ \t]+", " ", "".join(self._chunks))
        return re.sub(r"\n\s*\n+", "\n\n", collapsed).strip()


def strip_html(html: str) -> str:
    """HTML to readable plain text (stdlib parser, no extra dependency)."""
    extractor = _TextExtractor()
    extractor.feed(html)
    extractor.close()
    return extractor.text()
