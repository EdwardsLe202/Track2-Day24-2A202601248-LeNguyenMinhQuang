"""BƯỚC 3d — audit ledger append-only, tamper-evident (10').

JSONL, mỗi tool call một dòng. Đọc Guide.md (§3d).

Interface bắt buộc (tests/test_ledger.py và agent/runner.py gọi trực tiếp):

    append(entry: dict, path: pathlib.Path) -> dict
        `entry` phải có tối thiểu các field:
            ts, agent_id, run_id, tool, args_hash, classification,
            decision, reason
        Hàm tự thêm 2 field:
            prev_hash  = hash của dòng ngay trước trong file này, hoặc
                         "0" * 64 nếu là dòng đầu tiên
            hash       = sha256 tính từ nội dung dòng NÀY (bao gồm cả
                         prev_hash, KHÔNG bao gồm field hash) — dùng
                         json.dumps(..., sort_keys=True) trước khi hash
                         để thứ tự field không ảnh hưởng kết quả.
        Append 1 dòng JSON (utf-8, ensure_ascii=False) vào cuối `path`,
        tạo file/thư mục cha nếu chưa có. Trả về dict đầy đủ đã ghi
        (bao gồm prev_hash/hash).

    verify(path: pathlib.Path) -> bool
        Đọc toàn bộ file, trả về True nếu TẤT CẢ đều đúng:
          - mọi dòng có `reason` non-empty
          - prev_hash của dòng n == hash đã lưu của dòng n-1 (dòng đầu so
            với "0" * 64)
          - hash lưu trong dòng n khớp lại khi tính lại từ nội dung dòng đó
        Trả về False nếu bất kỳ dòng nào bị sửa/xoá/chèn giữa file, hoặc
        thiếu reason.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path


def _compute_hash(record_without_hash: dict) -> str:
    canonical = json.dumps(record_without_hash, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def append(entry: dict, path: Path) -> dict:
    """Thêm một bản ghi vào ledger với prev_hash và hash bảo toàn tính toàn vẹn."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    prev_hash = "0" * 64
    if path.exists() and path.stat().st_size > 0:
        lines = [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
        if lines:
            last_record = json.loads(lines[-1])
            prev_hash = last_record.get("hash", "0" * 64)

    record = dict(entry)
    record["prev_hash"] = prev_hash

    # Tính hash của record (bao gồm prev_hash, không bao gồm field hash)
    record_for_hash = {k: v for k, v in record.items() if k != "hash"}
    record["hash"] = _compute_hash(record_for_hash)

    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")

    return record


def verify(path: Path) -> bool:
    """Xác thực toàn bộ ledger: kiểm tra reason, prev_hash chain và hash của từng bản ghi."""
    path = Path(path)
    if not path.exists() or path.stat().st_size == 0:
        return True

    lines = [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    if not lines:
        return True

    expected_prev = "0" * 64

    for line in lines:
        try:
            entry = json.loads(line)
        except Exception:
            return False

        # Kiểm tra non-empty reason
        reason = entry.get("reason")
        if not reason or not str(reason).strip():
            return False

        # Kiểm tra prev_hash nối chuỗi
        if entry.get("prev_hash") != expected_prev:
            return False

        # Kiểm tra hash tính lại
        stored_hash = entry.get("hash")
        if not stored_hash:
            return False

        record_for_hash = {k: v for k, v in entry.items() if k != "hash"}
        calculated_hash = _compute_hash(record_for_hash)
        if stored_hash != calculated_hash:
            return False

        expected_prev = stored_hash

    return True
