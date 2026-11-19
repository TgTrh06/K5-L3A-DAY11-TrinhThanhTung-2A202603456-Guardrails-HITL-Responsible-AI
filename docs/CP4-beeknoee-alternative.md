# CP4 — Vì sao dùng Beeknoee cho Red Team

## Lý do thay đổi

Checkpoint 4 cần chạy năm prompt trên Red và Red Advance bằng model mặc định của
bài lab. OpenAI trực tiếp trả `429` vì tài khoản không còn credit. Gemini trực
tiếp trả `403` vì free tier không khả dụng cho project gắn với API key. Vì vậy,
hai đường gọi trực tiếp chưa thể tạo kết quả tấn công thực tế.

## Giải pháp thay thế

Beeknoee cung cấp endpoint Chat Completions tương thích OpenAI SDK và có model
ID `gemini-3.5-flash`. Chạy cả Red và Red Advance với model Gemini này qua
Beeknoee; NeMo self-check của Red Advance dùng cùng endpoint và key. Cấu hình
cho process CP4:

```powershell
$env:RED_TEAM_PROVIDER = "gemini"
$env:RED_TEAM_GATEWAY = "beeknoee"
$env:GEMINI_MODEL = "gemini-3.5-flash"
.\.venv\Scripts\python.exe src/main.py --part 4
```

Chỉ lưu `BEEKNOEE_API_KEY` trong `.env` local đã được Git ignore. Không đưa key
vào code, tài liệu hoặc artifact. `attack_results.json` ghi model nền là Gemini
và `llm_gateway=beeknoee` để thể hiện đúng đường gọi.

Lượt chạy đã tạo đủ ba file attack trong `outputs/`: Red leak 4/5, Red Advance
chặn 5/5 và không có lỗi API trong từng kết quả. Đây là kết quả của model thật,
không phải JSON tự điền.

## Giới hạn và đường quay lại

Beeknoee có thể trừ quota hoặc số dư. Dù model ID khớp yêu cầu bài lab, cần
xác nhận với coach rằng grader chấp nhận replay qua gateway bên thứ ba. Khi
OpenAI có credit hoặc Gemini trực tiếp được cấp quyền, đặt
`RED_TEAM_GATEWAY=direct`, dùng key tương ứng và chạy lại CP4 để sinh artifact
phù hợp với đường gọi mới.
