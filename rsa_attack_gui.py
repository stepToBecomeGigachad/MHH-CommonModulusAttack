import random
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from sympy import isprime, gcdex, mod_inverse, Integer

def generate_prime(bits):
    while True:
        p = random.getrandbits(bits)
        if isprime(p):
            return p

def generate_rsa_keys(bits=512):
    p = generate_prime(bits)
    q = generate_prime(bits)
    n = p * q
    phi = (p - 1) * (q - 1)
    e1 = 65537
    e2 = 65539
    d1 = mod_inverse(e1, phi)
    d2 = mod_inverse(e2, phi)
    return (e1, n), (e2, n), d1, d2, p, q, phi

def string_to_int(text):
    return int.from_bytes(text.encode('utf-8'), byteorder='big')

def int_to_string(num):
    try:
        num_bytes = (num.bit_length() + 7) // 8
        return num.to_bytes(num_bytes, byteorder='big').decode('utf-8')
    except:
        return str(num)

def encrypt(m, e, n):
    return pow(m, e, n)

def attack_common_modulus(c1, c2, e1, e2, n):
    steps = []
    steps.append("=== Bắt đầu tấn công ===")
    steps.append(f"Input: c1 = {c1}, c2 = {c2}, e1 = {e1}, e2 = {e2}, n = {n}")
    
    # Convert inputs to sympy Integer
    c1 = Integer(c1)
    c2 = Integer(c2)
    e1 = Integer(e1)
    e2 = Integer(e2)
    n = Integer(n)
    
    #Find GCD of e1 and e2
    steps.append("\nBước 1: Tính GCD(e1, e2)")
    a, b, g = gcdex(e1, e2)
    steps.append(f"GCD({e1}, {e2}) = {g}")
    steps.append(f"Tìm được: {a}*{e1} + {b}*{e2} = {g}")
    
    if g != 1:
        steps.append("Lỗi: e1 và e2 phải nguyên tố cùng nhau!")
        return None, steps
    
    #Compute modular inverse if needed
    steps.append("\nBước 2: Xử lý nghịch đảo modulo")
    def mod_pow(x, y, n):
        if y < 0:
            steps.append(f"Tính nghịch đảo modulo của {x} theo modulo {n}")
            x = mod_inverse(x, n)
            steps.append(f"Nghịch đảo modulo = {x}")
            y = -y
        return pow(int(x), int(y), int(n))
    
    #Recover plaintext
    steps.append("\nBước 3: Khôi phục bản rõ")
    steps.append(f"Tính: (c1^{a} * c2^{b}) mod n")
    m1 = mod_pow(c1, a, n)
    m2 = mod_pow(c2, b, n)
    steps.append(f"c1^{a} mod n = {m1}")
    steps.append(f"c2^{b} mod n = {m2}")
    
    m = (m1 * m2) % int(n)
    steps.append(f"Bản rõ khôi phục (dạng số) = {m}")
    try:
        text = int_to_string(m)
        steps.append(f"Bản rõ khôi phục (dạng chuỗi) = {text}")
    except:
        steps.append("Không thể chuyển đổi bản rõ về dạng chuỗi")
    return m, steps

class RSAApp:
    def __init__(self, root):
        self.root = root
        self.root.title("RSA Attack Simulation")
        self.root.geometry("1000x800")
        self.create_widgets()
        self.keys = None

    def create_widgets(self):
        # Create notebook for tabs
        notebook = ttk.Notebook(self.root)
        notebook.pack(expand=True, fill='both', padx=10, pady=10)

        # Tab 1: Key Generation
        key_frame = ttk.Frame(notebook)
        notebook.add(key_frame, text="Tạo khóa RSA")
        ttk.Button(key_frame, text="Tạo khóa mới", command=self.generate_keys).pack(pady=10)
        self.key_output = scrolledtext.ScrolledText(key_frame, height=15)
        self.key_output.pack(expand=True, fill='both', padx=10, pady=10)

        # Tab 2: Encryption
        encrypt_frame = ttk.Frame(notebook)
        notebook.add(encrypt_frame, text="Mã hóa")
        ttk.Label(encrypt_frame, text="Nhập bản rõ (chuỗi):").pack(pady=5)
        self.plaintext_entry = ttk.Entry(encrypt_frame)
        self.plaintext_entry.pack(pady=5)
        ttk.Button(encrypt_frame, text="Mã hóa", command=self.encrypt).pack(pady=10)
        self.encrypt_output = scrolledtext.ScrolledText(encrypt_frame, height=15)
        self.encrypt_output.pack(expand=True, fill='both', padx=10, pady=10)

        # Tab 3: Attack
        attack_frame = ttk.Frame(notebook)
        notebook.add(attack_frame, text="Tấn công")
        
        # Input frame
        input_frame = ttk.LabelFrame(attack_frame, text="Nhập thông tin")
        input_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Label(input_frame, text="Bản mã c1:").grid(row=0, column=0, padx=5, pady=5)
        self.c1_entry = ttk.Entry(input_frame)
        self.c1_entry.grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Label(input_frame, text="Bản mã c2:").grid(row=1, column=0, padx=5, pady=5)
        self.c2_entry = ttk.Entry(input_frame)
        self.c2_entry.grid(row=1, column=1, padx=5, pady=5)
        
        ttk.Label(input_frame, text="Khóa công khai e1:").grid(row=2, column=0, padx=5, pady=5)
        self.e1_entry = ttk.Entry(input_frame)
        self.e1_entry.grid(row=2, column=1, padx=5, pady=5)
        
        ttk.Label(input_frame, text="Khóa công khai e2:").grid(row=3, column=0, padx=5, pady=5)
        self.e2_entry = ttk.Entry(input_frame)
        self.e2_entry.grid(row=3, column=1, padx=5, pady=5)
        
        ttk.Label(input_frame, text="Modulus n:").grid(row=4, column=0, padx=5, pady=5)
        self.n_entry = ttk.Entry(input_frame)
        self.n_entry.grid(row=4, column=1, padx=5, pady=5)
        
        ttk.Button(attack_frame, text="Thực hiện tấn công", command=self.attack).pack(pady=10)
        
        self.attack_output = scrolledtext.ScrolledText(attack_frame, height=20)
        self.attack_output.pack(expand=True, fill='both', padx=10, pady=10)

    def generate_keys(self):
        self.keys = generate_rsa_keys()
        (e1, n), (e2, n), d1, d2, p, q, phi = self.keys
        
        self.key_output.delete(1.0, tk.END)
        self.key_output.insert(tk.END, "=== Thông tin khóa RSA ===\n\n")
        self.key_output.insert(tk.END, f"p = {p}\n")
        self.key_output.insert(tk.END, f"q = {q}\n")
        self.key_output.insert(tk.END, f"n = p*q = {n}\n")
        self.key_output.insert(tk.END, f"φ(n) = (p-1)*(q-1) = {phi}\n\n")
        self.key_output.insert(tk.END, f"Khóa công khai 1: (e1, n) = ({e1}, {n})\n")
        self.key_output.insert(tk.END, f"Khóa bí mật 1: d1 = {d1}\n\n")
        self.key_output.insert(tk.END, f"Khóa công khai 2: (e2, n) = ({e2}, {n})\n")
        self.key_output.insert(tk.END, f"Khóa bí mật 2: d2 = {d2}\n")
        
        # Auto-fill attack tab
        self.e1_entry.delete(0, tk.END)
        self.e1_entry.insert(0, str(e1))
        self.e2_entry.delete(0, tk.END)
        self.e2_entry.insert(0, str(e2))
        self.n_entry.delete(0, tk.END)
        self.n_entry.insert(0, str(n))

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
            
            self.encrypt_output.delete(1.0, tk.END)
            self.encrypt_output.insert(tk.END, "=== Mã hóa bản rõ ===\n\n")
            self.encrypt_output.insert(tk.END, f"Bản rõ (chuỗi): {plaintext}\n")
            self.encrypt_output.insert(tk.END, f"Bản rõ (số): {m}\n\n")
            self.encrypt_output.insert(tk.END, f"Mã hóa với khóa 1: c1 = {m}^{e1} mod {n} = {c1}\n")
            self.encrypt_output.insert(tk.END, f"Mã hóa với khóa 2: c2 = {m}^{e2} mod {n} = {c2}\n")
            
            # Auto-fill attack tab
            self.c1_entry.delete(0, tk.END)
            self.c1_entry.insert(0, str(c1))
            self.c2_entry.delete(0, tk.END)
            self.c2_entry.insert(0, str(c2))
            
        except Exception as e:
            messagebox.showerror("Lỗi", f"Lỗi khi mã hóa: {str(e)}")

    def attack(self):
        try:
            c1 = int(self.c1_entry.get())
            c2 = int(self.c2_entry.get())
            e1 = int(self.e1_entry.get())
            e2 = int(self.e2_entry.get())
            n = int(self.n_entry.get())
            
            recovered_m, steps = attack_common_modulus(c1, c2, e1, e2, n)
            
            self.attack_output.delete(1.0, tk.END)
            for step in steps:
                self.attack_output.insert(tk.END, step + "\n")
                
            if recovered_m is not None:
                self.attack_output.insert(tk.END, "\n=== Kết quả tấn công ===\n")
                self.attack_output.insert(tk.END, f"Bản rõ khôi phục (dạng số): {recovered_m}\n")
                try:
                    text = int_to_string(recovered_m)
                    self.attack_output.insert(tk.END, f"Bản rõ khôi phục (dạng chuỗi): {text}\n")
                except:
                    self.attack_output.insert(tk.END, "Không thể chuyển đổi bản rõ về dạng chuỗi\n")
                
        except ValueError:
            messagebox.showerror("Lỗi", "Vui lòng nhập các giá trị số nguyên hợp lệ!")

if __name__ == "__main__":
    root = tk.Tk()
    app = RSAApp(root)
    root.mainloop() 