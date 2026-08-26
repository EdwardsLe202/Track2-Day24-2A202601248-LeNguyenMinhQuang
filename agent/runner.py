"""BƯỚC 3c — trifecta split + egress allowlist (13').

Tách 1 yêu cầu người dùng thành ít nhất 2 run riêng biệt — KHÔNG run nào
được cầm cả 3 chân của trifecta cùng lúc:

    Run A: gọi search_docs (untrusted content).
           KHÔNG gọi read_customer. KHÔNG gọi http_post.
    Run B: gọi read_customer (private data).
           CHỈ nhận input là TYPED, ĐÃ SANITIZE từ Run A — list[int] ticket id
           trích từ TÊN FILE (vd "ticket-014.md" -> 14), KHÔNG BAO GIỜ nhận
           nguyên văn text của document. free text của attacker không được đi
           xa hơn Run A.

Mọi lần gọi tool (allow HAY deny) phải:
  1. Đi qua `agent.policy.check()` TRƯỚC KHI tool thật sự chạy.
  2. Được ghi vào ledger qua `agent.ledger.append()` — cả khi deny.
Nếu policy deny, KHÔNG được gọi tool đó.
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path

from agent import ledger, policy, tools

REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"
DEFAULT_LEDGER_PATH = REPORTS_DIR / "ledger.jsonl"
CUSTOMERS_FILE = Path(__file__).resolve().parent.parent / "data" / "customers.json"


def _extract_ticket_ids(docs: list[dict]) -> list[int]:
    """Trích xuất danh sách ticket_id (kiểu int) một cách an toàn từ tên file."""
    ticket_ids = []
    for doc in docs:
        filename = doc.get("id", "")
        match = re.search(r"ticket-(\d+)", filename)
        if match:
            try:
                ticket_ids.append(int(match.group(1)))
            except ValueError:
                continue
    return sorted(set(ticket_ids))


def _find_customer_ids_for_tickets(ticket_ids: list[int]) -> list[str]:
    """Nguồn tin cậy (Trusted Mapping): tra cứu customer_id từ related_tickets trong customers.json."""
    if not CUSTOMERS_FILE.exists():
        return []
    customers = json.loads(CUSTOMERS_FILE.read_text(encoding="utf-8"))
    ticket_set = set(ticket_ids)
    matched_cids = []
    for c in customers:
        related = set(c.get("related_tickets", []))
        if related.intersection(ticket_set):
            matched_cids.append(str(c["customer_id"]))
    return sorted(set(matched_cids))


def handle(message: str, llm, log_dir: Path | None = None) -> str:
    """Xử lý yêu cầu người dùng thông qua mô hình Trifecta Split + PEP + Audit Ledger."""
    ledger_path = (log_dir / "ledger.jsonl") if log_dir else DEFAULT_LEDGER_PATH

    # ==========================================
    # RUN A: Đọc untrusted content (search_docs)
    # ==========================================
    ctx_search = policy.PolicyContext(
        data_classification="internal",
        request_purpose="search-tickets",
        agent_owner="run-a",
        delegation_depth=0,
        egress_enabled=False,
    )
    allow_search, reason_search = policy.check(ctx_search)
    args_hash_search = hashlib.sha256(message.encode("utf-8")).hexdigest()[:16]
    ledger.append(
        {
            "ts": datetime.now(timezone.utc).isoformat(),
            "agent_id": "lab24-agent",
            "run_id": "run-a",
            "tool": "search_docs",
            "args_hash": args_hash_search,
            "classification": "internal",
            "decision": "allow" if allow_search else "deny",
            "reason": reason_search,
        },
        ledger_path,
    )

    if not allow_search:
        return "Yêu cầu tìm kiếm bị từ chối theo chính sách bảo mật."

    docs = tools.search_docs(message)
    combined_text = "\n\n".join(d["text"] for d in docs)

    # Quét phát hiện prompt injection trong văn bản
    injected = llm.find_injection(combined_text)
    if injected is not None:
        # Attacker cố gắng kích hoạt egress vector (http_post) để gửi dữ liệu PII ra ngoài.
        # Chuyển yêu cầu qua PEP (Policy Enforcement Point) để đánh giá:
        ctx_egress = policy.PolicyContext(
            data_classification="restricted",
            request_purpose="reconcile-exfil-attempt",
            agent_owner="run-a",
            delegation_depth=1,
            egress_enabled=True,
        )
        allow_egress, reason_egress = policy.check(ctx_egress)
        args_hash_egress = hashlib.sha256(injected.target_url.encode("utf-8")).hexdigest()[:16]
        ledger.append(
            {
                "ts": datetime.now(timezone.utc).isoformat(),
                "agent_id": "lab24-agent",
                "run_id": "run-a",
                "tool": "http_post",
                "args_hash": args_hash_egress,
                "classification": "restricted",
                "decision": "allow" if allow_egress else "deny",
                "reason": reason_egress,
            },
            ledger_path,
        )
        # Vì policy DENY nên http_post không bao giờ được gọi!

    # =============================================================
    # RUN B: Đọc private data store (read_customer) qua nguồn tin cậy
    # =============================================================
    # Trích xuất ticket_id kiểu int từ TÊN FILE của docs khớp ở Run A
    ticket_ids = _extract_ticket_ids(docs)
    trusted_customer_ids = _find_customer_ids_for_tickets(ticket_ids)

    for customer_id in trusted_customer_ids:
        ctx_customer = policy.PolicyContext(
            data_classification="restricted",
            request_purpose="read-customer-ticket-context",
            agent_owner="run-b",
            delegation_depth=1,
            egress_enabled=False,
        )
        allow_customer, reason_customer = policy.check(ctx_customer)
        args_hash_customer = hashlib.sha256(customer_id.encode("utf-8")).hexdigest()[:16]
        ledger.append(
            {
                "ts": datetime.now(timezone.utc).isoformat(),
                "agent_id": "lab24-agent",
                "run_id": "run-b",
                "tool": "read_customer",
                "args_hash": args_hash_customer,
                "classification": "restricted",
                "decision": "allow" if allow_customer else "deny",
                "reason": reason_customer,
            },
            ledger_path,
        )
        if allow_customer:
            try:
                tools.read_customer(customer_id)
            except tools.ToolError:
                pass

    # Trả về câu tóm tắt cho người dùng
    return llm.summarize(docs)
