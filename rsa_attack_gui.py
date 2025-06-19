import random
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from sympy import isprime, gcdex, mod_inverse, Integer
import secrets

# Hàm sinh số nguyên tố với độ dài bits sử dụng secrets để an toàn hơn
# Đảm bảo MSB và LSB là 1 để số luôn có đúng độ dài và là số lẻ
def generate_prime(bits):
    while True:
        p = secrets.randbits(bits)
        p |= (1 << (bits - 1)) | 1
        if isprime(p):
            return p

# Hàm tạo cặp khóa RSA cùng modulus n maar hai e cố định e1, e2
def generate_rsa_keys(bits=512):
    # Sinh hai số nguyên tố p, q khác nhau
    p = generate_prime(bits)
    q = generate_prime(bits)
    while q == p:
        q = generate_prime(bits)
    # Tính n và phi(n)
    n = p * q
    phi = (p - 1) * (q - 1)
    # Chọn hai số mũ công khai phổ biến
    e1 = 65537
    e2 = 65539
    # Tính khóa bí mật d1, d2 = e^{-1} mod phi
    d1 = mod_inverse(e1, phi)
    d2 = mod_inverse(e2, phi)
    return (e1, n), (e2, n), d1, d2, p, q, phi

# Chuyển chuỗi thành số nguyên để mã hóa
def string_to_int(text):
    return int.from_bytes(text.encode('utf-8'), byteorder='big')

# Chuyển số nguyên trở lại chuỗi UTF-8 nếu khả thi
def int_to_string(num):
    try:
        num_bytes = (num.bit_length() + 7) // 8
        return num.to_bytes(num_bytes, byteorder='big').decode('utf-8')
    except:
        return str(num)

# Hàm mã hóa đơn giản: m^e mod n
def encrypt(m, e, n):
    return pow(m, e, n)

# Tấn công Common Modulus Attack
# Input: c1, c2 (ciphertexts), e1, e2, n
# Output: plaintext m và chi tiết các bước
def attack_common_modulus(c1, c2, e1, e2, n):
    steps = []
    steps.append("=== Bắt đầu tấn công ===")
    steps.append(f"Input: c1 = {c1}, c2 = {c2}, e1 = {e1}, e2 = {e2}, n = {n}")
    # Chuyển sang Integer để dùng gcdex và mod_inverse
    c1 = Integer(c1)
    c2 = Integer(c2)
    e1 = Integer(e1)
    e2 = Integer(e2)
    n  = Integer(n)

    # Bước 1: Tìm a, b, g sao cho a*e1 + b*e2 = g = gcd(e1, e2)
    steps.append("\nBước 1: Tính GCD(e1, e2) và hệ số")
    a, b, g = gcdex(e1, e2)
    steps.append(f"GCD({e1}, {e2}) = {g}")
    steps.append(f"Tìm được: {a}*{e1} + {b}*{e2} = {g}")
    # Nếu g != 1, không thể tấn công
    if g != 1:
        steps.append("Lỗi: e1 và e2 phải coprime!")
        return None, steps

    # Bước 2: Xử lý trường hợp a hoặc b âm (tính nghịch đảo)
    steps.append("\nBước 2: Xử lý nghịch đảo nếu cần")
    def mod_pow(x, y, n):
        # Nếu mũ âm, tính nghịch đảo trước
        if y < 0:
            steps.append(f"Tính nghịch đảo của {x} mod {n}")
            x = mod_inverse(x, n)
            steps.append(f"Nghịch đảo = {x}")
            y = -y
        return pow(int(x), int(y), int(n))

    # Bước 3: Tính m = c1^a * c2^b mod n
    steps.append("\nBước 3: Khôi phục bản rõ m = c1^a * c2^b mod n")
    m1 = mod_pow(c1, a, n)
    m2 = mod_pow(c2, b, n)
    steps.append(f"c1^{a} mod n = {m1}")
    steps.append(f"c2^{b} mod n = {m2}")
    m = (m1 * m2) % int(n)
    steps.append(f"Bản rõ (dạng số) = {m}")
    # Thử chuyển về chuỗi
    try:
        text = int_to_string(m)
        steps.append(f"Bản rõ (chuỗi) = {text}")
    except:
        steps.append("Không thể chuyển sang chuỗi.")
    return m, steps

# Lớp ứng dụng GUI sử dụng Tkinter
class RSAApp:
    def __init__(self, root):
        self.root = root
        self.root.title("RSA Attack Simulation")
        self.root.geometry("1000x800")
        self.keys = None  # Lưu khóa khi sinh
        self.create_widgets()

    def create_widgets(self):
        # Notebook để tách tab
        notebook = ttk.Notebook(self.root)
        notebook.pack(expand=True, fill='both', padx=10, pady=10)

        # --- Tab Tạo khóa ---
        key_frame = ttk.Frame(notebook)
        notebook.add(key_frame, text="Tạo khóa RSA")
        # Chọn độ dài khóa
        ttk.Label(key_frame, text="Chọn độ dài khóa (bits):").pack(pady=5)
        self.bits_var = tk.IntVar(value=512)
        ttk.OptionMenu(key_frame, self.bits_var, 512, 512, 1024, 2048).pack(pady=5)
        # Nút tạo khóa
        ttk.Button(key_frame, text="Tạo khóa mới", command=self.generate_keys).pack(pady=10)
        # Khu vực hiển thị thông tin khóa
        self.key_output = scrolledtext.ScrolledText(key_frame, height=15)
        self.key_output.pack(expand=True, fill='both', padx=10, pady=10)

        # --- Tab Mã hóa ---
        encrypt_frame = ttk.Frame(notebook)
        notebook.add(encrypt_frame, text="Mã hóa")
        ttk.Label(encrypt_frame, text="Nhập bản rõ (chuỗi):").pack(pady=5)
        self.plaintext_entry = ttk.Entry(encrypt_frame, width=50)
        self.plaintext_entry.pack(pady=5)
        ttk.Button(encrypt_frame, text="Mã hóa", command=self.encrypt).pack(pady=10)
        self.encrypt_output = scrolledtext.ScrolledText(encrypt_frame, height=15)
        self.encrypt_output.pack(expand=True, fill='both', padx=10, pady=10)

        # --- Tab Tấn công ---
        attack_frame = ttk.Frame(notebook)
        notebook.add(attack_frame, text="Tấn công")
        # Khung nhập dữ liệu
        input_frame = ttk.LabelFrame(attack_frame, text="Nhập thông tin")
        input_frame.pack(fill='x', padx=10, pady=5)
        labels = ["c1", "c2", "e1", "e2", "n"]
        self.entries = {}
        for i, lbl in enumerate(labels):
            ttk.Label(input_frame, text=f"Bản mã {lbl}:").grid(row=i, column=0, padx=5, pady=5, sticky="e")
            self.entries[lbl] = ttk.Entry(input_frame, width=60)
            self.entries[lbl].grid(row=i, column=1, padx=5, pady=5)
        # Nút tấn công
        ttk.Button(attack_frame, text="Thực hiện tấn công", command=self.attack).pack(pady=10)
        # Khu vực hiển thị kết quả và bước tấn công
        self.attack_output = scrolledtext.ScrolledText(attack_frame, height=20)
        self.attack_output.pack(expand=True, fill='both', padx=10, pady=10)

    # Hàm sinh khóa khi nhấn nút
    def generate_keys(self):
        bits = self.bits_var.get()
        try:
            self.keys = generate_rsa_keys(bits)
            (e1, n), (e2, n), d1, d2, p, q, phi = self.keys
            # Hiển thị chi tiết khóa
            out = []
            out.append("=== Thông tin khóa RSA ===\n")
            out.append(f"Độ dài khóa: {bits} bit\n")
            out.append(f"p = {p}\nq = {q}\n")
            out.append(f"n = p*q = {n}\nφ(n) = {phi}\n\n")
            out.append(f"Khóa công khai 1: (e1, n) = ({e1}, {n})\nKhóa bí mật 1: d1 = {d1}\n\n")
            out.append(f"Khóa công khai 2: (e2, n) = ({e2}, {n})\nKhóa bí mật 2: d2 = {d2}\n")
            self.key_output.delete(1.0, tk.END)
            self.key_output.insert(tk.END, "".join(out))

            # Auto-fill thông tin tấn công
            self.entries['e1'].delete(0, tk.END); self.entries['e1'].insert(0, str(e1))
            self.entries['e2'].delete(0, tk.END); self.entries['e2'].insert(0, str(e2))
            self.entries['n' ].delete(0, tk.END); self.entries['n' ].insert(0, str(n))
        except Exception as ex:
            messagebox.showerror("Lỗi tạo khóa", str(ex))

    # Hàm mã hóa khi nhấn nút
    def encrypt(self):
        if not self.keys:
            messagebox.showerror("Lỗi", "Vui lòng tạo khóa trước!")
            return
        try:
            plaintext = self.plaintext_entry.get()
            m = string_to_int(plaintext)
            (e1, n), (e2, n), _, _, _, _, _ = self.keys
            c1 = encrypt(m, e1, n)
            c2 = encrypt(m, e2, n)
            # Hiển thị kết quả mã hóa
            out = []
            out.append("=== Mã hóa bản rõ ===\n\n")
            out.append(f"Bản rõ (chuỗi): {plaintext}\n")
            out.append(f"Bản rõ (số): {m}\n\n")
            out.append(f"c1 = m^{e1} mod n = {c1}\n")
            out.append(f"c2 = m^{e2} mod n = {c2}\n")
            self.encrypt_output.delete(1.0, tk.END)
            self.encrypt_output.insert(tk.END, "".join(out))
            # Auto-fill ciphertext cho tab tấn công
            self.entries['c1'].delete(0, tk.END); self.entries['c1'].insert(0, str(c1))
            self.entries['c2'].delete(0, tk.END); self.entries['c2'].insert(0, str(c2))
        except Exception as e:
            messagebox.showerror("Lỗi khi mã hóa", str(e))

    # Hàm tấn công khi nhấn nút
    def attack(self):
        try:
            vals = {k: int(v.get()) for k, v in self.entries.items()}
            recovered_m, steps = attack_common_modulus(
                vals['c1'], vals['c2'], vals['e1'], vals['e2'], vals['n']
            )
            # Hiển thị các bước tấn công
            self.attack_output.delete(1.0, tk.END)
            for line in steps:
                self.attack_output.insert(tk.END, line + "\n")
            # Hiển thị kết quả cuối
            if recovered_m is not None:
                self.attack_output.insert(tk.END, "\n=== Kết quả tấn công ===\n")
                self.attack_output.insert(tk.END, f"Bản rõ (số): {recovered_m}\n")
                try:
                    text = int_to_string(recovered_m)
                    self.attack_output.insert(tk.END, f"Bản rõ (chuỗi): {text}\n")
                except:
                    self.attack_output.insert(tk.END, "Không thể chuyển sang chuỗi\n")
        except ValueError:
            messagebox.showerror("Lỗi", "Vui lòng nhập giá trị số nguyên hợp lệ!")

if __name__ == "__main__":
    root = tk.Tk()
    app = RSAApp(root)
    root.mainloop()
