# DPIA-lite (Data Protection Impact Assessment)

## 1. Dữ liệu gì (Data Inventory & Classification)

Agent trong hệ thống tiếp cận và xử lý hai nhóm dữ liệu chính:

- **Dữ liệu tài liệu hỗ trợ / Ticket (`search_docs` - Internal/Public)**:
  - Danh mục: Nội dung trao đổi hỗ trợ khách hàng, câu hỏi thường gặp, báo cáo sự cố trong `corpus/*.md`.
  - Phân loại: Dữ liệu nội bộ (`internal`) hoặc công khai (`public`). Có thể bị cài cắm nội dung không đáng tin cậy (`untrusted content`) từ bên ngoài hoặc kẻ tấn công.
  - Các trường PII có thể xuất hiện trong nội dung ticket: Họ tên khách hàng, Email liên hệ, Số điện thoại, CCCD (12 số), Số tài khoản ngân hàng (STK).

- **Dữ liệu hồ sơ khách hàng (`read_customer` - Restricted / PII)**:
  - Danh mục: Dữ liệu cá nhân lưu trữ trong kho dữ liệu bảo mật `data/customers.json`.
  - Phân loại: Dữ liệu hạn chế tối mật (`restricted`).
  - Các trường nhạy cảm: `customer_id` (Mã định danh khách hàng), `name` (Họ và tên), `cccd` (Số CCCD/Căn cước công dân), `phone` (Số điện thoại), `bank_account` (Số tài khoản ngân hàng), `email` (Địa chỉ email), `related_tickets` (Danh sách ticket liên kết).

---

## 2. Mục đích gì (Purpose Limitation & Necessity)

- **Mục đích nghiệp vụ chính**:
  - Hỗ trợ nhân viên chăm sóc khách hàng tự động tổng hợp, tìm kiếm và tóm tắt tiến độ xử lý các ticket khiếu nại, yêu cầu hỗ trợ hoặc đối soát dịch vụ.
  - Tra cứu thông tin khách hàng chính chủ tương ứng với ticket đang được xử lý nhằm xác thực bối cảnh và nâng cao chất lượng phản hồi hỗ trợ.

- **Nguyên tắc giảm thiểu dữ liệu (Data Minimization)**:
  - Agent chỉ được phép truy vấn dữ liệu hồ sơ khách hàng dựa trên mối liên kết định danh tin cậy (`related_tickets`), tuyệt đối không cho phép truy xuất tự do theo chỉ định trong văn bản không được kiểm chứng.
  - Sử dụng cơ chế PII Gate (`agent/pii.py`) để phát hiện và ẩn danh (`redact`) các thông tin PII nhạy cảm trước khi đưa vào context lưu trữ dài hạn hoặc xử lý không cần thiết.

---

## 3. Chảy đi đâu (Data Flow & Cross-Border Transfer)

- **Luồng dữ liệu nội bộ (Local Boundaries)**:
  - **Context xử lý**: Dữ liệu đọc từ `search_docs` và `read_customer` được xử lý trong bộ nhớ tiến trình agent.
  - **Audit Ledger (`reports/ledger.jsonl`)**: Mọi tương tác gọi tool (bao gồm `search_docs`, `read_customer`, `http_post`) đều được ghi vết kèm hàm băm bảo vệ tính toàn vẹn (tamper-evident hash chain). Ledger chỉ lưu mã hash của tham số (`args_hash`), không ghi đè dữ liệu thô nhạy cảm.
  - **Local Sink (`sink/sink.py`)**: Đóng vai trò đích mô phỏng thu thập dữ liệu exfiltration trong môi trường lab an toàn (`localhost:9999`).

- **Luồng chuyển dữ liệu xuyên biên giới & Bên thứ ba (NĐ 356/2025 & Luật BV Dữ liệu cá nhân)**:
  - Khi chạy ở chế độ mặc định (`--mock`): Toàn bộ xử lý là deterministic tại chỗ, không có bất kỳ byte dữ liệu nào rời khỏi máy chủ nội bộ.
  - Khi kích hoạt model thương mại (`--model claude-...`): Context tổng hợp và nội dung ticket sẽ được gửi qua API tới hạ tầng của Anthropic (đặt tại Mỹ/quốc tế). Đây cấu thành hành vi **chuyển dữ liệu cá nhân ra nước ngoài** theo Nghị định 356/2025/NĐ-CP, đòi hỏi:
    1. Lập và lưu trữ hồ sơ đánh giá tác động chuyển dữ liệu ra nước ngoài trong vòng 60 ngày.
    2. Áp dụng PII redaction trước khi gửi context tới LLM API của nhà cung cấp mô hình.
    3. Thực thi chính sách **PEP (Policy Enforcement Point)** và kiến trúc **Trifecta Split** để ngăn chặn triệt để hành vi trích xuất trái phép (exfiltration) dữ liệu `restricted` sang bất kỳ đích mạng ngoài nào (`http_post`).
