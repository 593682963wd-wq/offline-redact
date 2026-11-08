"""网络/代码相关敏感信息：IP/URL/Token/API Key/密码。"""
from __future__ import annotations

import re
import ipaddress
from typing import List

from .base import BaseRecognizer, Match


_IPV4 = re.compile(
    r"(?<![0-9.])(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)(?![0-9.])"
)
_IPV6 = re.compile(r"(?<![A-Za-z0-9:])(?:[A-Fa-f0-9]*:){2,}[A-Fa-f0-9:.]*(?![A-Za-z0-9:])")
_URL = re.compile(r"(?<![A-Za-z0-9])https?://[^\s'\"<>]+", re.IGNORECASE)
_MAC = re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b")

# Token/Key 模式（高熵长字符串 + 前缀）
# 引号值可以包含空格与转义引号，必须完整遮盖；不把剩余秘密当正文。
_SECRET_VALUE = r'"((?:\\.|[^"\\\r\n])+)"|\'((?:\\.|[^\'\\\r\n])+)\'|([^\s\'";,]{8,})'
_API_KEY = re.compile(
    r"(?i)(?:api[_-]?key|access[_-]?token|secret|password|passwd|pwd|bearer)\s*[:=]\s*(?:" + _SECRET_VALUE + ")"
)
_BEARER = re.compile(r"(?i)(?<![A-Za-z0-9_])bearer[ \t]+(?:" + _SECRET_VALUE + ")")

_AWS_KEY = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
_GH_TOKEN = re.compile(r"\bghp_[A-Za-z0-9]{36}\b")
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")
_DB_URL = re.compile(
    r"\b(?:mysql|postgres|postgresql|mongodb|redis|sqlite|mssql)://[^\s'\"<>]+",
    re.IGNORECASE,
)


class NetworkRecognizer(BaseRecognizer):
    name = "network"

    def analyze(self, text: str) -> List[Match]:
        out: List[Match] = []
        for m in _IPV4.finditer(text):
            out.append(Match("IPV4", m.start(), m.end(), m.group(0), 0.90, "regex"))
        for m in _IPV6.finditer(text):
            try:ipaddress.IPv6Address(m.group(0))
            except ValueError:continue
            out.append(Match("IPV6", m.start(), m.end(), m.group(0), 0.85, "regex"))
        for m in _URL.finditer(text):
            out.append(Match("URL", m.start(), m.end(), m.group(0), 0.80, "regex"))
        for m in _MAC.finditer(text):
            out.append(Match("MAC", m.start(), m.end(), m.group(0), 0.95, "regex"))
        for m in _AWS_KEY.finditer(text):
            out.append(Match("AWS_KEY", m.start(), m.end(), m.group(0), 0.99, "regex"))
        for m in _GH_TOKEN.finditer(text):
            out.append(Match("GITHUB_TOKEN", m.start(), m.end(), m.group(0), 0.99, "regex"))
        for m in _JWT.finditer(text):
            out.append(Match("JWT", m.start(), m.end(), m.group(0), 0.95, "regex"))
        for m in _DB_URL.finditer(text):
            out.append(Match("DB_URL", m.start(), m.end(), m.group(0), 0.95, "regex"))
        for pattern in (_API_KEY, _BEARER):
            for m in pattern.finditer(text):
                index = next(index for index in (1, 2, 3) if m.group(index) is not None)
                val = m.group(index); start = m.start(index)
                out.append(Match("API_SECRET", start, start + len(val), val, 0.95, "regex"))
        return out
