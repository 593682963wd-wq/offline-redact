"""识别器基类与通用数据结构。"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List


@dataclass(frozen=True)
class Match:
    entity_type: str   # 例如 "PHONE_CN", "ID_CARD", "NAME_CN"
    start: int
    end: int
    value: str
    score: float = 0.85
    source: str = "regex"   # regex | dict | jieba | presidio | user

    def overlaps(self, other: "Match") -> bool:
        return not (self.end <= other.start or other.end <= self.start)


class BaseRecognizer:
    name: str = "base"

    def analyze(self, text: str) -> List[Match]:  # pragma: no cover - 抽象
        raise NotImplementedError
