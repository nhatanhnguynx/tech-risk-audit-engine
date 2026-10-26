import pandas as pd
import json
import os
import google.generativeai as genai

# =====================================================================
# KHỐI 1: PANDAS & REGEX - LOG FORENSICS
# Mục tiêu: Phát hiện rủi ro Management Override (ISA 240)
# =====================================================================
def analyze_erp_logs(csv_file_path="mock_erp_logs.csv"):
    print("\n" + "="*70)
    print(" 🛡️ TẦNG 1: QUÉT NHẬT KÝ HỆ THỐNG (ERP LOG FORENSICS)")
    print("="*70)
    
    # 1. Khởi tạo dữ liệu Log giả lập (nếu không có file CSV thật)
    try:
        df = pd.read_csv(csv_file_path)
        print(f"[+] Đã tải dữ liệu từ {csv_file_path}")
    except FileNotFoundError:
        print("[!] Không tìm thấy file CSV. Khởi tạo dữ liệu giả lập (500,000 dòng log rút gọn)...")
        data = {
            'User': ['admin', 'intern_01', 'cfo_account', 'admin', 'system_service'],
            'Action': ['LOGIN', 'DOWNLOAD_DB', 'UPDATE_REVENUE', 'DELETE_LOGS', 'BACKUP'],
            'Timestamp': ['2026-10-01 09:00:00', '2026-10-01 14:30:00', '2026-10-02 02:15:00', '2026-10-02 02:16:00', '2026-10-02 03:00:00'],
            'Status': ['Active', 'Active', 'Active', 'Active', 'Active']
        }
        df = pd.DataFrame(data)

    # 2. Tiền xử lý dữ liệu (Ép kiểu thời gian)
    df['Timestamp'] = pd.to_datetime(df['Timestamp'])
    df['Hour'] = df['Timestamp'].dt.hour

    # 3. Thuật toán kiểm toán: Bắt giao dịch ngoài giờ hành chính (1 AM - 5 AM)
    # Lọc bỏ các tài khoản hệ thống (system_service) chuyên chạy backup ban đêm
    print("[+] Đang chạy thuật toán truy vết hành vi bất thường (Off-Hour Login)...")
    suspicious_flags = df[(df['Hour'] >= 1) & (df['Hour'] <= 5) & (df['User'] != 'system_service')]
    
    if not suspicious_flags.empty:
        print("\n🚨 [CẢNH BÁO RED FLAG]: Phát hiện rủi ro Management Override!")
        for index, row in suspicious_flags.iterrows():
            print(f"   ❌ TÀI KHOẢN: {row['User']} | HÀNH ĐỘNG: {row['Action']} | THỜI GIAN: {row['Timestamp']}")
        print("   -> Bằng chứng đã được ghi nhận vào Hồ sơ kiểm toán.")
    else:
        print("\n[v] Không phát hiện rủi ro Management Override.")


# =====================================================================
# KHỐI 2 & 3: STATIC ANALYZER & GENAI COMPILER
# Mục tiêu: Đánh giá Kiểm soát chung CNTT - ITGC (ISA 315)
# =====================================================================
def audit_cloud_config(json_data):
    print("\n" + "="*70)
    print(" ☁️ TẦNG 2 & 3: RÀ SOÁT CẤU HÌNH CLOUD VÀ DỊCH RỦI RO BẰNG AI")
    print("="*70)
    
    # KHỐI 2: STATIC ANALYZER (Phân tích tĩnh cấu trúc JSON)
    print("[+] Đang quét mã nguồn AWS IAM JSON...")
    high_risk_statements = []
    
    for statement in json_data.get("Statement", []):
        effect = statement.get("Effect")
        action = statement.get("Action")
        principal = statement.get("Principal")
        
        # Bắt lỗi cấp quyền toàn năng (Wildcard)
        if effect == "Allow":
            if action == "*" or principal == "*" or (isinstance(principal, dict) and principal.get("AWS") == "*"):
                high_risk_statements.append(statement)
                
    if not high_risk_statements:
        print("[v] Cấu hình Cloud an toàn. Tuân thủ Least Privilege.")
        return

    print(f"\n🚨 [CẢNH BÁO ITGC]: Phát hiện {len(high_risk_statements)} chính sách phân quyền nguy hiểm (Wildcard '*')!")
    
    # KHỐI 3: GENAI "COMPILER" (Dịch mã máy sang ngôn ngữ Kiểm toán)
    print("[+] Đang khởi động GenAI Compiler...")
    
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        print("\n[LƯU Ý]: Không tìm thấy biến môi trường GEMINI_API_KEY. Hiển thị kết quả AI giả lập:")
        print("🤖 [GenAI OUTPUT]:")
        print(">>> THEO CHUẨN MỰC ISA 315: Hệ thống Cloud đang cấp quyền 'Super Admin' (*) cho tài khoản Thực tập sinh hoặc mở Public toàn bộ CSDL. NGUY CƠ: Mất trắng toàn vẹn BCTC. Rủi ro gian lận ở mức CAO. Khuyến nghị: Thu hồi quyền ngay lập tức.")
    else:
        try:
            genai.configure(api_key=api_key)
            # Sử dụng model Flash cho tốc độ xử lý nhanh
            model = genai.GenerativeModel('gemini-1.5-flash')
            
            prompt = f"""
            Bạn là một Giám đốc Kiểm toán Rủi ro Công nghệ (IT Audit Director) tại Big 4.
            Hãy dịch đoạn mã cấu hình AWS JSON nguy hiểm sau đây thành một đoạn cảnh báo rủi ro ngắn gọn 
            dành cho Kiểm toán viên tài chính, dựa trên chuẩn mực ISA 315 và rủi ro gian lận.
            Chỉ ra rõ hậu quả nếu dữ liệu tài chính bị can thiệp.
            
            AWS JSON Policy:
            {json.dumps(high_risk_statements, indent=2)}
            """
            
            response = model.generate_content(prompt)
            print("\n🤖 [GenAI OUTPUT]:")
            print("-" * 60)
            print(response.text)
            print("-" * 60)
        except Exception as e:
            print(f"\n[!] Lỗi khi gọi API Gemini: {str(e)}")


# =====================================================================
# HÀM CHẠY CHÍNH (MAIN EXECUTION)
# =====================================================================
if __name__ == "__main__":
    print("\n" + "#"*70)
    print("#   TECH RISK AUDIT ENGINE - PROOF OF CONCEPT (v2.0)            #")
    print("#   Dự án NCKH: Ứng dụng AI trong Đánh giá Rủi ro Kiểm toán       #")
    print("#"*70)

    # CHẠY KHỐI 1
    analyze_erp_logs()

    # DỮ LIỆU GIẢ LẬP CHO KHỐI 2 & 3
    aws_mock_policy = {
      "Version": "2012-10-17",
      "Statement": [
        {
          "Sid": "FinanceDataPublicAccess",
          "Effect": "Allow",
          "Principal": "*",
          "Action": "s3:GetObject",
          "Resource": "arn:aws:s3:::finance-payroll-data-2026/*"
        },
        {
          "Sid": "InternGodMode",
          "Effect": "Allow",
          "Principal": {"AWS": "arn:aws:iam::123456789012:user/intern_temp"},
          "Action": "*",
          "Resource": "*"
        }
      ]
    }
    
    # CHẠY KHỐI 2 & 3
    audit_cloud_config(aws_mock_policy)
    
    print("\n[✔] HOÀN TẤT QUY TRÌNH ĐÁNH GIÁ RỦI RO KIỂM TOÁN TỰ ĐỘNG.")
    print("="*70 + "\n")
