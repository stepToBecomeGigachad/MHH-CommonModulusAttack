# RSA Attack Simulation

## Mô tả
Chương trình mô phỏng tấn công Common Modulus trong RSA với giao diện đồ họa.

## Thư viện sử dụng

### Thư viện chính
- `sympy`: Thư viện toán học cho các phép tính số học và đại số
  - `isprime`: Kiểm tra số nguyên tố
  - `gcdex`: Thuật toán Extended Euclidean
  - `mod_inverse`: Tính nghịch đảo modulo
  - `Integer`: Xử lý số nguyên lớn

### Thư viện GUI
- `tkinter`: Thư viện giao diện đồ họa mặc định của Python
  - `ttk`: Module chứa các widget được cải tiến của tkinter
  - `scrolledtext`: Widget hiển thị văn bản có thanh cuộn
  - `messagebox`: Hiển thị hộp thoại thông báo

### Thư viện khác
- `random`: Tạo số ngẫu nhiên
  - `getrandbits`: Tạo số ngẫu nhiên với số bit xác định

## Cài đặt
```bash
pip install sympy
```

## Cách sử dụng
1. Chạy file `rsa_attack_gui.py`
2. Giao diện sẽ hiển thị 3 tab:
   - Tab "Tạo khóa RSA": Tạo cặp khóa RSA mới
   - Tab "Mã hóa": Mã hóa bản rõ với hai khóa công khai
   - Tab "Tấn công": Thực hiện tấn công Common Modulus

## Tính năng
- Tạo khóa RSA với chung modulus
- Mã hóa bản rõ với hai khóa công khai khác nhau
- Mô phỏng tấn công Common Modulus
- Hiển thị chi tiết từng bước của quá trình tấn công
- Giao diện đồ họa trực quan, dễ sử dụng
