import time
import secrets
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
from sympy import isprime, gcdex, mod_inverse, Integer
import ttkbootstrap as tb  # pip install ttkbootstrap

# —— Utils RSA ——
def generate_prime(bits):
    while True:
        p = secrets.randbits(bits)
        p |= (1 << (bits - 1)) | 1
        if isprime(p):
            return p

def generate_rsa_keys(bits=512):
    p = generate_prime(bits)
    q = generate_prime(bits)
    while q == p:
        q = generate_prime(bits)
    n = p * q
    phi = (p-1)*(q-1)
    e1, e2 = 65537, 65539
    d1 = mod_inverse(e1, phi)
    d2 = mod_inverse(e2, phi)
    return (e1,n),(e2,n),d1,d2,p,q,phi

def string_to_int(text):
    return int.from_bytes(text.encode('utf-8'),'big')

def int_to_string(num):
    try:
        L = (num.bit_length()+7)//8
        return num.to_bytes(L,'big').decode('utf-8')
    except:
        return str(num)

def encrypt(m,e,n):
    return pow(m,e,n)

def attack_common_modulus(c1, c2, e1, e2, n):
    steps = []
    # Step 1
    from sympy import gcd
    g0 = gcd(e1, e2)
    cond = (g0 == 1)
    steps.append(
        "BƯỚC 1: Kiểm tra điều kiện tấn công\n"
        f"  - gcd(e1,e2) = gcd({e1},{e2}) = {g0}\n"
        f"  - Chung n? (đang dùng chung n={n})\n"
        f"  => Điều kiện {'thỏa mãn' if cond else 'không thỏa mãn'}"
    )
    if not cond:
        return None, steps

    # Step 2
    a, b, g = gcdex(e1, e2)
    steps.append(
        "BƯỚC 2: Tính hệ số Bézout\n"
        f"  - Tìm a,b sao cho a*e1 + b*e2 = 1\n"
        f"  - Kết quả: {a}*{e1} + {b}*{e2} = {g}"
    )

    # Step 3
    def mod_pow(x, exp, mod):
        if exp < 0:
            x = mod_inverse(x, mod)
            exp = -exp
        return pow(int(x), int(exp), int(mod))

    m1 = mod_pow(c1, a, n)
    m2 = mod_pow(c2, b, n)
    m  = (m1 * m2) % n
    steps.append(
        "BƯỚC 3: Khôi phục bản rõ\n"
        f"  - c1^{a} mod n = {m1}\n"
        f"  - c2^{b} mod n = {m2}\n"
        f"  => m = ({m1}*{m2}) mod {n} = {m}"
    )

    return m, steps

# —— GUI Windows ——
class KeyGenWindow(tk.Toplevel):
    def __init__(self, master, shared):
        super().__init__(master)
        self.shared = shared
        self.title("🔑 Sinh khóa RSA")
        self.configure(bg="#23272b")
        tk.Label(self, text="Sinh khóa RSA", font=("Arial",22,"bold"),
                 bg="#23272b", fg="#f8f9fa").pack(pady=(20,10))
        frm = ttk.Frame(self); frm.pack(pady=5)
        ttk.Label(frm, text="Độ dài (bits):", font=("Arial",14),
                  background="#23272b", foreground="#f8f9fa")\
            .grid(row=0, column=0, sticky="e", padx=8, pady=6)
        self.bits = tk.IntVar(value=512)
        ttk.OptionMenu(frm, self.bits, 512, 512, 1024, 2048)\
            .grid(row=0, column=1, sticky="w", padx=8, pady=6)
        ttk.Button(self, text="Tạo khóa", style="success.Outline.TButton",
                   command=self.generate_keys).pack(pady=12)
        self.txt = scrolledtext.ScrolledText(self, height=8,
                                             font=("Consolas",12),
                                             bg="#181a1b", fg="#e0e0e0",
                                             bd=0, relief="flat")
        self.txt.pack(expand=True, fill="both", padx=20, pady=10)
    def generate_keys(self):
        bits = self.bits.get()
        try:
            keys = generate_rsa_keys(bits)
            (e1,n),(e2,_),d1,d2,p,q,phi = keys
            out = (
                f"=== Thông tin khóa ===\n"
                f"bits: {bits}\n"
                f"p={p}\nq={q}\n"
                f"n={n}\nφ(n)={phi}\n\n"
                f"Public1=(e1,n)=({e1},{n})\nPrivate1=d1={d1}\n\n"
                f"Public2=(e2,n)=({e2},{n})\nPrivate2=d2={d2}\n"
            )
            self.txt.delete(1.0,tk.END)
            self.txt.insert(tk.END,out)
            self.shared.update({
                'e1': e1, 'e2': e2, 'n': n,
                'c1': None, 'c2': None
            })
        except Exception as ex:
            messagebox.showerror("Lỗi", str(ex))

class EncryptWindow(tk.Toplevel):
    def __init__(self, master, shared):
        super().__init__(master)
        self.shared = shared
        self.title("🔒 Mã hóa RSA")
        self.configure(bg="#23272b")
        tk.Label(self, text="Mã hóa bản rõ", font=("Arial",22,"bold"),
                 bg="#23272b", fg="#f8f9fa").pack(pady=(20,10))
        frm = ttk.Frame(self); frm.pack(pady=5)
        ttk.Label(frm, text="Nhập bản rõ:", font=("Arial",14),
                  background="#23272b", foreground="#f8f9fa")\
            .grid(row=0,column=0,sticky="e",padx=8,pady=6)
        self.ent = ttk.Entry(frm, width=40, font=("Arial",13))
        self.ent.grid(row=0,column=1,sticky="w",padx=8,pady=6)
        ttk.Button(self, text="Mã hóa", style="info.Outline.TButton",
                   command=self.encrypt).pack(pady=12)
        self.txt = scrolledtext.ScrolledText(self, height=8,
                                             font=("Consolas",12),
                                             bg="#181a1b", fg="#e0e0e0",
                                             bd=0, relief="flat")
        self.txt.pack(expand=True, fill="both", padx=20, pady=10)
    def encrypt(self):
        e1 = self.shared.get('e1')
        e2 = self.shared.get('e2')
        n  = self.shared.get('n')
        if not e1:
            messagebox.showerror("Lỗi","Chưa sinh hoặc nhập khóa!")
            return
        pt = self.ent.get()
        m  = string_to_int(pt)
        c1 = encrypt(m,e1,n)
        c2 = encrypt(m,e2,n)
        out = (
            "=== Mã hóa ===\n\n"
            f"Plain: '{pt}'\n m={m}\n\n"
            f"c1 = m^{e1} mod n = {c1}\n"
            f"c2 = m^{e2} mod n = {c2}\n"
        )
        self.txt.delete(1.0,tk.END)
        self.txt.insert(tk.END,out)
        self.shared.update({'c1':c1,'c2':c2})

class AttackWindow(tk.Toplevel):
    def __init__(self, master, shared):
        super().__init__(master)
        self.shared = shared
        self.title("⚔️ Tấn công Common Modulus")
        self.configure(bg="#23272b")
        tk.Label(self, text="Common Modulus Attack", font=("Arial",22,"bold"),
                 bg="#23272b", fg="#f8f9fa").pack(pady=(20,10))
        frm = ttk.LabelFrame(self, text="C1, C2, E1, E2, N", style="info.TLabelframe")
        frm.pack(fill="x", padx=20, pady=8)
        self.entries = {}
        for i, lbl in enumerate(("c1","c2","e1","e2","n")):
            ttk.Label(frm, text=lbl+":", font=("Arial",13),
                      background="#23272b", foreground="#f8f9fa")\
             .grid(row=i,column=0,sticky="e",padx=6,pady=4)
            ent = ttk.Entry(frm, width=45, font=("Arial",12))
            ent.grid(row=i,column=1,sticky="w",padx=6,pady=4)
            # auto-fill
            val = self.shared.get(lbl)
            if val is not None:
                ent.insert(0,str(val))
            self.entries[lbl] = ent

        ttk.Button(self, text="Tấn công", style="danger.Outline.TButton",
                   command=self.start_attack).pack(pady=12)

        self.txt = scrolledtext.ScrolledText(self, height=10,
                                             font=("Consolas",12),
                                             bg="#181a1b", fg="#e0e0e0",
                                             bd=0, relief="flat")
        self.txt.pack(expand=True, fill="both", padx=20, pady=6)

        nav = ttk.Frame(self); nav.pack(pady=(0,16))
        self.btn_prev = ttk.Button(nav, text="← Bước trước", command=self.prev_step, state="disabled")
        self.btn_prev.grid(row=0,column=0,padx=8)
        self.lbl_ctr  = ttk.Label(nav, text="0/0", font=("Arial",12),
                                  background="#23272b", foreground="#f8f9fa")
        self.lbl_ctr.grid(row=0,column=1,padx=8)
        self.btn_next = ttk.Button(nav, text="Bước sau →", command=self.next_step, state="disabled")
        self.btn_next.grid(row=0,column=2,padx=8)

        self.steps = []
        self.current = 0

    def start_attack(self):
        # đọc input
        try:
            vals = {k:int(v.get()) for k,v in self.entries.items()}
        except:
            messagebox.showerror("Lỗi","Giá trị phải là số nguyên hợp lệ!")
            return
        t0 = time.perf_counter()
        m, steps = attack_common_modulus(
            vals['c1'], vals['c2'],
            vals['e1'], vals['e2'],
            vals['n']
        )
        t1 = time.perf_counter()
        # thêm dòng thời gian & kết quả
        steps.append(f"⏱️ Thời gian: {(t1-t0)*1000:.2f} ms")
        if m is not None:
            steps.append(f"Kết quả số: {m}")
            try:
                steps.append(f"Kết quả chuỗi: {int_to_string(m)}")
            except: pass

        self.steps = steps
        self.current = 0
        self.btn_prev.config(state="disabled")
        self.btn_next.config(state="normal" if len(steps)>1 else "disabled")
        self.show_step()

    def show_step(self):
        self.txt.delete(1.0, tk.END)
        self.txt.insert(tk.END, self.steps[self.current])
        total = len(self.steps)
        self.lbl_ctr.config(text=f"{self.current+1}/{total}")
        self.btn_prev.config(state="normal" if self.current>0 else "disabled")
        self.btn_next.config(state="normal" if self.current<total-1 else "disabled")

    def prev_step(self):
        if self.current>0:
            self.current -= 1
            self.show_step()

    def next_step(self):
        if self.current < len(self.steps)-1:
            self.current += 1
            self.show_step()

# —— Main Menu ——
class MainMenu(tb.Window):
    def __init__(self):
        super().__init__(themename="superhero")
        self.title("🔐 RSA Attack Simulator")
        self.state('zoomed')
        self.configure(bg="#23272b")
        self.shared = {}
        tk.Label(self, text="RSA Attack Simulator", font=("Arial",36,"bold"),
                 bg="#23272b", fg="#f8f9fa").pack(pady=(40,20))
        btnf = ttk.Frame(self); btnf.pack(pady=20)
        ttk.Button(btnf, text="🔑 Sinh khóa", style="success.TButton", width=20,
                   command=lambda: KeyGenWindow(self, self.shared)).grid(row=0,column=0,padx=20)
        ttk.Button(btnf, text="🔒 Mã hóa", style="info.TButton",    width=20,
                   command=lambda: EncryptWindow(self, self.shared)).grid(row=0,column=1,padx=20)
        ttk.Button(btnf, text="⚔️ Tấn công", style="danger.TButton", width=20,
                   command=lambda: AttackWindow(self, self.shared)).grid(row=0,column=2,padx=20)
        tk.Label(self, text="by MHH", font=("Arial",12,"italic"),
                 bg="#23272b", fg="#adb5bd").pack(pady=(40,10))

if __name__ == "__main__":
    app = MainMenu()
    app.mainloop()
