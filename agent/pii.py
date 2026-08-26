"""BƯỚC 3a — PII gate TRƯỚC KHI vào context/store (12').

Đọc Guide.md (§3a) trước khi bắt đầu: Presidio không có tiếng Việt
sẵn (AnalyzerEngine() mặc định chỉ hỗ trợ "en"). Đường an toàn cho 2h là
regex recognizer + deny-list cho PERSON — coi spaCy/transformers NER là
stretch goal, KHÔNG bắt buộc.

Interface bắt buộc (tests/test_pii.py gọi trực tiếp 2 hàm này):

    detect(text: str) -> list[dict]
        Mỗi entity: {"type": str, "start": int, "end": int}
        `type` là một trong: "VN_CCCD", "VN_PHONE", "VN_BANK_ACCOUNT", "EMAIL"
        `start`/`end` là offset ký tự trong `text` (offset đầu bao gồm,
        offset cuối KHÔNG bao gồm — giống slice Python text[start:end]).
        Format này khớp với tests/vn_pii_testset.jsonl.

    redact(text: str) -> str
        Trả về `text` sau khi mọi entity từ detect() bị thay bằng
        "[REDACTED_<TYPE>]". Phải xử lý overlap/thứ tự đúng khi có nhiều
        entity (gợi ý: thay từ cuối văn bản về đầu để offset không bị lệch).
"""
from __future__ import annotations

import re


def detect(text: str) -> list[dict]:
    """Phát hiện các entity PII tiếng Việt: VN_CCCD, VN_PHONE, VN_BANK_ACCOUNT, EMAIL."""
    entities: list[dict] = []

    # 1. Email (chuẩn RFC)
    for m in re.finditer(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", text):
        entities.append({"type": "EMAIL", "start": m.start(), "end": m.end()})

    # 2. Số tài khoản ngân hàng (8-16 chữ số kèm tiền tố STK / số tài khoản / TK / tài khoản)
    for m in re.finditer(r"(?:STK|số tài khoản|tài khoản|TK)\s*:?\s*(\d{8,16})\b", text, re.IGNORECASE):
        start = m.start(1)
        end = m.end(1)
        entities.append({"type": "VN_BANK_ACCOUNT", "start": start, "end": end})

    # 3. CCCD (12 chữ số liên tiếp) - tránh nhầm số tài khoản 12 số
    for m in re.finditer(r"\b\d{12}\b", text):
        if not any(e["start"] <= m.start() < e["end"] or m.start() <= e["start"] < m.end() for e in entities):
            entities.append({"type": "VN_CCCD", "start": m.start(), "end": m.end()})

    # 4. Số điện thoại VN (10 chữ số bắt đầu bằng 0 hoặc +84)
    for m in re.finditer(r"(?:\+84|0)\d{9}\b", text):
        if not any(e["start"] <= m.start() < e["end"] or m.start() <= e["start"] < m.end() for e in entities):
            entities.append({"type": "VN_PHONE", "start": m.start(), "end": m.end()})

    # Sắp xếp lại theo vị trí xuất hiện
    entities.sort(key=lambda x: x["start"])
    return entities


def redact(text: str) -> str:
    """Thay thế mọi PII entity trong text bằng [REDACTED_<TYPE>]."""
    entities = detect(text)
    if not entities:
        return text

    # Thay thế từ cuối về đầu để không làm thay đổi start/end offset của các entity trước
    result = text
    for e in reversed(entities):
        placeholder = f"[REDACTED_{e['type']}]"
        result = result[: e["start"]] + placeholder + result[e["end"] :]

    return result
