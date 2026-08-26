# Compliance mapping

Điền evidence là **đường dẫn file/dòng thật** trong repo của bạn — không
phải mô tả chung. Xem `Guide.md` Bước 4 và `Rubric.md`.

| Requirement | Control | Evidence |
|---|---|---|
| Luật 91/2025 — quyền yêu cầu xoá | Quyền yêu cầu xóa PII khỏi private data store (chưa implement delete cascade sang ledger, xem stretch #4) | `data/customers.json`, `agent/pii.py:L56-L68` |
| NĐ 356/2025 — hồ sơ xuyên biên giới 60 ngày | Data-flow inventory đánh giá rủi ro luồng chuyển dữ liệu PII ra bên ngoài qua LLM API & tool egress | `reports/dpia-lite.md` §3 |
| ASI03 — privilege abuse | Phân quyền theo context (per-agent identity, classification, delegation depth) và PEP chặn quyền vượt mức | `agent/policy.py:L39-L69`, `agent/ledger.py:L43-L65` |
| ASI01 — goal hijack | Kiến trúc Trifecta Split cô lập context untrusted (Run A) và private store (Run B), ngăn chặn chiếm quyền điều khiển agent | `agent/runner.py:L43-L124`, `reports/attack-after.log` (sink rỗng 0 byte), `reports/ledger.jsonl:L2` (`http_post` → `decision=deny`) |
| ISO 42001 Clause 5-6 | Quản trị chính sách AI Policy-as-Code có kiểm duyệt, lưu vết toàn vẹn bằng audit ledger hash-chain | `agent/policy.py:L39-L69`, `agent/ledger.py:L43-L107` |
