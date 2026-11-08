"""中文常见 PII 识别器。

实体类型：
    ID_CARD        — 18 位身份证（含校验位）
    PHONE_CN       — 中国大陆手机号
    BANK_CARD      — 银行卡（Luhn 校验）
    USCC           — 统一社会信用代码
    PASSPORT_CN    — 中国护照号
    PLATE_CN       — 中国车牌（普通+新能源）
    EMAIL          — 邮箱
    NAME_CN        — 中文姓名（基于"姓名/乘客/旅客：xxx" 上下文 + 常见姓氏，弱召回，需用户字典补充）
    ADDRESS_CN     — 中文地址（弱召回，依赖关键字：省/市/区/街道/号）
"""
from __future__ import annotations

import re

from ..validators import is_valid_id_card, is_valid_luhn, is_valid_uscc
from .base import BaseRecognizer, Match

_PATTERNS = {
    "ID_CARD":     re.compile(r"(?<!\d)[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx](?!\d)"),
    "PHONE_CN":    re.compile(r"(?<!\d)1[3-9]\d{9}(?!\d)"),
    "USCC":        re.compile(r"(?<![0-9A-Z])[0-9A-HJ-NPQRTUWXY]{2}\d{6}[0-9A-HJ-NPQRTUWXY]{10}(?![0-9A-Z])"),
    "PASSPORT_CN": re.compile(r"(?<![A-Za-z0-9])(?:[EeGg]\d{8}|[Ee][A-Za-z]\d{7})(?![A-Za-z0-9])"),
    "BANK_CARD":   re.compile(r"(?<!\d)\d{13,19}(?!\d)"),
    "PLATE_CN":    re.compile(r"[京津沪渝冀豫云辽黑湘皖鲁新苏浙赣鄂桂甘晋蒙陕吉闽贵粤青藏川宁琼使领][A-HJ-NP-Z][A-HJ-NP-Z0-9]{4,5}[A-HJ-NP-Z0-9挂学警港澳]"),
    # 不能使用 ``\b``：中文字符与 ASCII 字母在 Python 正则里都属于“单词字符”，
    # 因而“邮箱test@example.com”这类紧邻中文标签的常见输入会漏检。
    "EMAIL":       re.compile(
        r"(?<![A-Za-z0-9._%+-])"
        r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
        r"(?![A-Za-z0-9.-])"
    ),
}


# 中文姓名：上下文触发 + 1 个常见姓 + 1-2 汉字
_NAME_CONTEXT = re.compile(
    r"(?:姓名|乘客|旅客|联系人|签派员|机长|副驾|学员|教员|签字|申请人|经办人)\s*[:：]?\s*"
    r"([\u4e00-\u9fa5]{2,4})"
)
_ADDRESS_CTX = re.compile(
    r"[\u4e00-\u9fa5]{2,6}(?:省|自治区|市|地区|盟|州)"
    r"(?:[\u4e00-\u9fa5A-Za-z0-9]{1,10}(?:市|区|县|旗))?"
    r"(?:[\u4e00-\u9fa5A-Za-z0-9]{1,20}(?:街道|镇|乡|路|街|巷|大道|号楼|号|室|户))+"
)


class CnPiiRecognizer(BaseRecognizer):
    name = "cn_pii"

    def analyze(self, text: str) -> list[Match]:
        out: list[Match] = []
        for etype, pat in _PATTERNS.items():
            for m in pat.finditer(text):
                value = m.group(0)
                if etype == "ID_CARD" and not is_valid_id_card(value):
                    continue
                if etype == "USCC" and not is_valid_uscc(value):
                    continue
                if etype == "BANK_CARD":
                    if not is_valid_luhn(value):
                        continue
                    # 降权，避免吃掉所有长数字
                    out.append(Match(etype, m.start(), m.end(), value, 0.75, "regex"))
                    continue
                out.append(Match(etype, m.start(), m.end(), value, 0.95, "regex"))

        for m in _NAME_CONTEXT.finditer(text):
            name = m.group(1)
            start = m.start(1)
            out.append(Match("NAME_CN", start, start + len(name), name, 0.80, "regex"))

        for m in _ADDRESS_CTX.finditer(text):
            out.append(Match("ADDRESS_CN", m.start(), m.end(), m.group(0), 0.70, "regex"))

        return out
