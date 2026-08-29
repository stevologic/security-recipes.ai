#!/usr/bin/env python3
"""Deterministic cleanup for upstream CVE text encoding artifacts."""

from __future__ import annotations

import html
import re


CP1252_BYTE_BY_CODE_POINT = {
    0x0192: 0x83,
    0x0152: 0x8C,
    0x0153: 0x9C,
    0x0160: 0x8A,
    0x0161: 0x9A,
    0x0178: 0x9F,
    0x017D: 0x8E,
    0x017E: 0x9E,
    0x02C6: 0x88,
    0x02DC: 0x98,
    0x2013: 0x96,
    0x2014: 0x97,
    0x2018: 0x91,
    0x2019: 0x92,
    0x201A: 0x82,
    0x201C: 0x93,
    0x201D: 0x94,
    0x201E: 0x84,
    0x2020: 0x86,
    0x2021: 0x87,
    0x2022: 0x95,
    0x2026: 0x85,
    0x2030: 0x89,
    0x2039: 0x8B,
    0x203A: 0x9B,
    0x20AC: 0x80,
    0x2122: 0x99,
}

# The public site is English-only. Detect Han independently so kana-only text
# remains untouched, then remove the complete mixed CJK runs around detected
# ideographs. The Han ranges include Unicode 17's Extension J.
HAN_IDEOGRAPH_RE = re.compile(
    "[\u3400-\u4dbf\u4e00-\u9fff\uf900-\ufaff"
    "\U00020000-\U0002fa1f\U00030000-\U0003347f]"
)
MIXED_CJK_RUN_RE = re.compile(
    "[\u2e80-\u312f\u3190-\u33ff\u3400-\u4dbf\u4e00-\u9fff"
    "\uf900-\ufaff\uff01-\uff0f\uff1a-\uff20\uff3b-\uff40"
    "\uff5b-\uff9f\U00020000-\U0002fa1f\U00030000-\U0003347f]+"
)
EMPTY_ASCII_PAIR_RE = re.compile(r"\(\s*\)|\[\s*\]|\{\s*\}")


def _mojibake_byte(character: str) -> int:
    codepoint = ord(character)
    if codepoint <= 0xFF:
        return codepoint
    return CP1252_BYTE_BY_CODE_POINT.get(codepoint, -1)


def _utf8_sequence_length(first_byte: int) -> int:
    if 0xC2 <= first_byte <= 0xDF:
        return 2
    if 0xE0 <= first_byte <= 0xEF:
        return 3
    if 0xF0 <= first_byte <= 0xF4:
        return 4
    return 0


def _repair_mojibake_pass(value: str) -> str:
    repaired: list[str] = []
    index = 0
    while index < len(value):
        first_byte = _mojibake_byte(value[index])
        sequence_length = _utf8_sequence_length(first_byte)
        if sequence_length and index + sequence_length <= len(value):
            candidate = [
                _mojibake_byte(character)
                for character in value[index : index + sequence_length]
            ]
            if all(0x80 <= byte <= 0xBF for byte in candidate[1:]):
                try:
                    repaired.append(bytes(candidate).decode("utf-8", errors="strict"))
                    index += sequence_length
                    continue
                except UnicodeDecodeError:
                    pass
        repaired.append(value[index])
        index += 1
    return "".join(repaired)


def clean_catalog_text(value: object) -> str:
    """Return readable site text without Han ideographs or encoding artifacts."""
    text = str(value or "")
    for _ in range(3):
        decoded = html.unescape(text)
        if decoded == text:
            break
        text = decoded
    for _ in range(2):
        repaired = _repair_mojibake_pass(text)
        if repaired == text:
            break
        text = repaired
    text = re.sub(r"\u00c2+(?=\s|$)", "", text)
    text = re.sub(r"\ufffds\b", "'s", text)
    text = text.replace("\ufffd", " ")
    if HAN_IDEOGRAPH_RE.search(text):
        text = MIXED_CJK_RUN_RE.sub(" ", text)
        while True:
            unwrapped = EMPTY_ASCII_PAIR_RE.sub(" ", text)
            if unwrapped == text:
                break
            text = unwrapped
    return re.sub(r"\s+", " ", text).strip()


def catalog_text_has_artifact(value: object) -> bool:
    text = str(value or "")
    return clean_catalog_text(text) != re.sub(r"\s+", " ", text).strip()
