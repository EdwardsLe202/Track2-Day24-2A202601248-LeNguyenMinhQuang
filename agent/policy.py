"""BƯỚC 3b — PEP (Policy Enforcement Point) tại tool call (15').

Cổng chặn TRƯỚC KHI tool thật sự execute. Đọc Guide.md (§3b).

Interface bắt buộc (tests/test_policy.py và agent/runner.py gọi trực tiếp):

    check(context: PolicyContext) -> tuple[bool, str]
        Trả về (allow, reason).
        `reason` KHÔNG BAO GIỜ được để trống — cả khi allow=True và
        allow=False. Đây là evidence audit ở Bước 4 (rubric: "Audit
        completeness = 100%" — điều kiện trượt nếu có dòng thiếu reason).

PolicyContext — 5 input đúng slide §3.3 (đã định nghĩa sẵn, đừng đổi field):

    data_classification: str   "public" | "internal" | "restricted"
    request_purpose: str       tự do, ví dụ "reconciliation", "support-reply"
    agent_owner: str            định danh agent/run gọi tool này
    delegation_depth: int       0 = gọi trực tiếp bởi user, >0 = agent gọi agent
    egress_enabled: bool        run hiện tại có được phép gọi network không

Rule TỐI THIỂU bắt buộc (không được viết yếu hơn rule này):

    classification == "restricted" and egress_enabled is True  ->  DENY
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class PolicyContext:
    data_classification: str
    request_purpose: str
    agent_owner: str
    delegation_depth: int
    egress_enabled: bool


def check(context: PolicyContext) -> tuple[bool, str]:
    """Policy Enforcement Point: kiểm tra điều kiện truy cập và egress.
    
    Luôn trả về (allow: bool, reason: str) với reason không bao giờ rỗng.
    """
    # 1. Rule tối thiểu: Chặn egress khi dữ liệu là restricted / PII
    if context.data_classification == "restricted" and context.egress_enabled:
        return (
            False,
            f"DENY: Egress bị chặn đối với dữ liệu restricted/PII (agent={context.agent_owner}, purpose={context.request_purpose})"
        )

    # 2. Rule phân quyền theo agent_owner và data classification
    if context.data_classification == "restricted" and context.agent_owner == "run-a":
        return (
            False,
            f"DENY: Run A (untrusted context) không được phép truy cập dữ liệu restricted (agent={context.agent_owner})"
        )

    # 3. Rule độ sâu uỷ quyền (delegation depth)
    if context.delegation_depth > 3:
        return (
            False,
            f"DENY: Delegation depth={context.delegation_depth} vượt quá ngưỡng an toàn cho phép"
        )

    # 4. Cho phép các trường hợp hợp lệ kèm lý do rõ ràng
    return (
        True,
        f"ALLOW: Cho phép truy cập dữ liệu {context.data_classification} cho agent={context.agent_owner} với purpose={context.request_purpose}"
    )
