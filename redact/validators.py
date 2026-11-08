"""校验函数：身份证、银行卡 Luhn、统一社会信用代码。

用于降低正则误报。
"""
from __future__ import annotations


# ---------------- 身份证 18 位 (GB 11643-1999) ----------------
_ID_WEIGHTS = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]
_ID_CHECK = "10X98765432"


def is_valid_id_card(s: str) -> bool:
    s = s.strip().upper()
    if len(s) != 18:
        return False
    if not s[:17].isdigit():
        return False
    total = sum(int(s[i]) * _ID_WEIGHTS[i] for i in range(17))
    return _ID_CHECK[total % 11] == s[17]


# ---------------- 银行卡 Luhn ----------------
def is_valid_luhn(card: str) -> bool:
    digits = [int(c) for c in card if c.isdigit()]
    if not (13 <= len(digits) <= 19):
        return False
    checksum = 0
    parity = len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


# ---------------- 统一社会信用代码 (GB 32100-2015) ----------------
_USCC_CHARS = "0123456789ABCDEFGHJKLMNPQRTUWXY"
_USCC_WEIGHTS = [1, 3, 9, 27, 19, 26, 16, 17, 20, 29, 25, 13, 8, 24, 10, 30, 28]


def is_valid_uscc(s: str) -> bool:
    s = s.strip().upper()
    if len(s) != 18:
        return False
    try:
        total = sum(_USCC_CHARS.index(s[i]) * _USCC_WEIGHTS[i] for i in range(17))
    except ValueError:
        return False
    remainder = 31 - (total % 31)
    if remainder == 31:
        remainder = 0
    return _USCC_CHARS[remainder] == s[17]
