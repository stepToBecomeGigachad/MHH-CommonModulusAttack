import os
import time
import secrets
import random
import json
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
    phi = (p - 1) * (q - 1)
    e1, e2 = 65537, 65539
    d1 = mod_inverse(e1, phi)
    d2 = mod_inverse(e2, phi)
    return (e1, n), (e2, n), d1, d2, p, q, phi

def generate_shared_modulus(bits=512, count=5):
    p = generate_prime(bits)
    q = generate_prime(bits)
    while q == p:
        q = generate_prime(bits)
    n = p * q
    phi = (p - 1) * (q - 1)

    es = []
    candidates = [65537, 65539, 257, 17, 5, 3]
    i = 0
    while len(es) < count:
        e = candidates[i] if i < len(candidates) else secrets.randbelow(phi - 2) + 2
        i += 1
        if e >= phi: continue
        try:
            _ = mod_inverse(e, phi)
        except:
            continue
        if e not in es:
            es.append(e)

    return [(e, n) for e in es], (p, q, phi)

def string_to_int(text):
    return int.from_bytes(text.encode('utf-8'), 'big')

def int_to_string(num):
    try:
        L = (num.bit_length() + 7) // 8
        return num.to_bytes(L, 'big').decode('utf-8')
    except:
        return str(num)

def encrypt(m, e, n):
    return pow(m, e, n)

def attack_common_modulus(c1, c2, e1, e2, n):
    steps = []
    from sympy import gcd
    g0 = gcd(e1, e2)
    steps.append(
        "BƯỚC 1: Kiểm tra điều kiện\n"
        f"  gcd(e1,e2) = {g0}, chung n = {n}\n"
        f"  => {'OK' if g0==1 else 'FAIL'}"
    )
    if g0 != 1:
        return None, steps

    a, b, g = gcdex(e1, e2)
    steps.append(f"BƯỚC 2: Bézout: a={a}, b={b}, a*e1+b*e2={g}")

    def mod_pow(x, exp, mod):
        if exp < 0:
            x = mod_inverse(x, mod)
            exp = -exp
        return pow(int(x), int(exp), int(mod))

    m1 = mod_pow(c1, a, n)
    m2 = mod_pow(c2, b, n)
    m = (m1 * m2) % n
    steps.append(f"BƯỚC 3: Khôi phục: m1={m1}, m2={m2}, m={m}")

    return m, steps

# —— GUI Windows ——
class KeyGenWindow(tk.Toplevel):
    def __init__(self, master, shared):
        super().__init__(master)
        self.shared = shared
        self.title("🔑 Quản lý khóa RSA")
        self.configure(bg="#23272b")

        tk.Label(self, text="Quản lý khóa RSA", font=("Arial",22,"bold"),
                 bg="#23272b", fg="#f8f9fa").pack(pady=(20,10))

        # 1) Sinh khóa tự động
        auto_fr = ttk.LabelFrame(self, text="1. Sinh khóa tự động")
        auto_fr.pack(fill="x", padx=20, pady=6)
        self.bits = tk.IntVar(value=512)
        ttk.Label(auto_fr, text="Bits:", background="#23272b", foreground="#f8f9fa")\
            .grid(row=0, column=0, padx=5, pady=5)
        ttk.OptionMenu(auto_fr, self.bits, 512, 512, 1024, 2048)\
            .grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(auto_fr, text="Sinh khóa", style="success.Outline.TButton",
                   command=self.generate_keys)\
            .grid(row=0, column=2, padx=10)

        # 2) Nhập thủ công
        manual_fr = ttk.LabelFrame(self, text="2. Nhập khóa thủ công")
        manual_fr.pack(fill="x", padx=20, pady=6)
        for idx, lbl in enumerate(("e1","e2","n")):
            ttk.Label(manual_fr, text=lbl+":", background="#23272b", foreground="#f8f9fa")\
                .grid(row=0, column=idx*2, padx=4, pady=4)
            entry = ttk.Entry(manual_fr, width=20 if lbl!="n" else 30)
            entry.grid(row=0, column=idx*2+1, padx=4, pady=4)
            setattr(self, f"ent_{lbl}", entry)
        ttk.Button(manual_fr, text="Nhập", style="info.Outline.TButton",
                   command=self.load_manual)\
            .grid(row=0, column=6, padx=8)

        # 3) Show chi tiết
        self.txt = scrolledtext.ScrolledText(self, height=8, font=("Consolas",12),
                                             bg="#181a1b", fg="#e0e0e0", bd=0, relief="flat")
        self.txt.configure(highlightbackground="#343a40", highlightcolor="#343a40")
        self.txt.pack(expand=True, fill="both", padx=20, pady=10)

        # 4) Scenario chung modulus
        scen_fr = ttk.LabelFrame(self, text="4. Scenario chung modulus")
        scen_fr.pack(fill="x", padx=20, pady=6)
        ttk.Label(scen_fr, text="Số lượng key:", background="#23272b", foreground="#f8f9fa")\
            .grid(row=0, column=0, padx=5, pady=5)
        self.num_multi = tk.IntVar(value=6)
        ttk.Entry(scen_fr, textvariable=self.num_multi, width=5)\
            .grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(scen_fr, text="Tạo scenario", style="primary.Outline.TButton",
                   command=self.generate_multi)\
            .grid(row=0, column=2, padx=10)
        self.lst_multi = tk.Listbox(self, width=80, height=6)
        self.lst_multi.pack(padx=20, pady=4)

        ttk.Button(self, text="5. Phát hiện cặp share n",
                   style="danger.Outline.TButton",
                   command=self.detect_common_modulus)\
            .pack(pady=6)
        self.lst_common = tk.Listbox(self, width=80, height=4)
        self.lst_common.pack(padx=20, pady=4)

        ttk.Button(self, text="6. Chọn cặp để tấn công",
                   style="info.Outline.TButton",
                   command=self.select_for_attack)\
            .pack(pady=(4,12))

        self.multi_keys = []
        self.common_pairs = []

    def generate_keys(self):
        bits = self.bits.get()
        try:
            (e1, n), (e2, _), d1, d2, p, q, phi = generate_rsa_keys(bits)
            self.shared.update({'e1': e1, 'e2': e2, 'n': n})
            out = (
                f"=== Khóa RSA ===\n"
                f"p = {p}\nq = {q}\n"
                f"n = {n}\nφ(n) = {phi}\n\n"
                f"Public1: e1={e1}\nPrivate1: d1={d1}\n\n"
                f"Public2: e2={e2}\nPrivate2: d2={d2}\n"
            )
            self.txt.delete(1.0, tk.END)
            self.txt.insert(tk.END, out)
        except Exception as e:
            messagebox.showerror("Lỗi", str(e))

    def load_manual(self):
        try:
            e1 = int(self.ent_e1.get())
            e2 = int(self.ent_e2.get())
            n  = int(self.ent_n.get())
            self.shared.update({'e1': e1, 'e2': e2, 'n': n})
            out = f"Đã nhập thủ công:\ne1={e1}\ne2={e2}\nn={n}\n"
            self.txt.delete(1.0, tk.END)
            self.txt.insert(tk.END, out)
        except Exception as e:
            messagebox.showerror("Lỗi", str(e))

    def generate_multi(self):
        cnt = max(2, int(self.num_multi.get()))
        half = cnt // 2
        shared_keys, _ = generate_shared_modulus(512, half)
        random_keys = []
        for _ in range(cnt - half):
            (e1, n1), *_ = generate_rsa_keys(512)
            random_keys.append({'e': e1, 'n': n1})

        self.multi_keys = [{'e': e, 'n': n} for e, n in shared_keys] + random_keys
        random.shuffle(self.multi_keys)

        # Ghi ra JSON
        with open("scenario_keys.json", "w", encoding="utf-8") as f:
            json.dump(self.multi_keys, f, indent=2)

        self.lst_multi.delete(0, tk.END)
        for i, k in enumerate(self.multi_keys):
            self.lst_multi.insert(
                tk.END,
                f"{i+1}. e={k['e']}, len(n)={k['n'].bit_length()} bits"
            )
        self.lst_common.delete(0, tk.END)
        self.common_pairs = []

    def detect_common_modulus(self):
        self.lst_common.delete(0, tk.END)
        self.common_pairs = []
        buckets = {}
        for i, k in enumerate(self.multi_keys):
            buckets.setdefault(k['n'], []).append(i)
        for n, idxs in buckets.items():
            if len(idxs) > 1:
                for a in range(len(idxs)):
                    for b in range(a+1, len(idxs)):
                        i1, i2 = idxs[a], idxs[b]
                        self.lst_common.insert(
                            tk.END,
                            f"Cặp {i1+1} & {i2+1}, len(n)={n.bit_length()} bits"
                        )
                        self.common_pairs.append((i1, i2))
        if not self.common_pairs:
            self.lst_common.insert(tk.END, "Không tìm thấy cặp share modulus")
    def select_for_attack(self):
        sel = self.lst_common.curselection()
        if not sel:
            messagebox.showerror("Lỗi", "Chọn một cặp!")
            return
        i1, i2 = self.common_pairs[sel[0]]
        k1, k2 = self.multi_keys[i1], self.multi_keys[i2]
        # CHỈNH LẠI Ở ĐÂY: xóa space trước 'e1'
        self.shared.update({
            'e1': k1['e'],
            'e2': k2['e'],
            'n':  k1['n']
        })
        messagebox.showinfo("OK", f"Chọn cặp {i1+1} & {i2+1} để tấn công!")

    

# EncryptWindow, AttackWindow, MainMenu unchanged; as in previous code.



class EncryptWindow(tk.Toplevel):
    def __init__(self, master, shared):
        super().__init__(master)
        self.shared = shared
        self.title("🔒 Mã hóa RSA")
        self.configure(bg="#23272b")
        tk.Label(self, text="Mã hóa", font=("Arial",22,"bold"),
                 bg="#23272b", fg="#f8f9fa").pack(pady=(20,10))

        frm = ttk.Frame(self); frm.pack(pady=5)
        ttk.Label(frm, text="Nhập plaintext:", font=("Arial",14),
                  background="#23272b", foreground="#f8f9fa")\
            .grid(row=0, column=0, sticky="e", padx=8, pady=6)
        self.ent_pt = ttk.Entry(frm, width=40, font=("Arial",13))
        self.ent_pt.grid(row=0, column=1, sticky="w", padx=8, pady=6)
        ttk.Button(frm, text="Mã hóa", style="info.Outline.TButton",
                   command=self.encrypt).grid(row=0, column=2, padx=10)

        self.txt = scrolledtext.ScrolledText(self, height=8, font=("Consolas",12),
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
        pt = self.ent_pt.get()
        if not pt:
            messagebox.showerror("Lỗi", "Vui lòng nhập bản rõ!")
            return
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
        self.title("⚔️ Common Modulus Attack")
        self.configure(bg="#23272b")
        tk.Label(self, text="Tấn công Common Modulus",
                 font=("Arial",22,"bold"),
                 bg="#23272b", fg="#f8f9fa").pack(pady=(20,10))

        frm = ttk.LabelFrame(self, text="Inputs", style="info.TLabelframe")
        frm.pack(fill="x", padx=20, pady=8)
        self.entries = {}
        for i, lbl in enumerate(("c1","c2","e1","e2","n")):
            ttk.Label(frm, text=lbl+":", font=("Arial",13),
                      background="#23272b", foreground="#f8f9fa")\
             .grid(row=i, column=0, sticky="e", padx=6, pady=4)
            ent = ttk.Entry(frm, width=45, font=("Arial",12))
            ent.grid(row=i, column=1, sticky="w", padx=6, pady=4)
            val = self.shared.get(lbl)
            if val is not None:
                ent.insert(0, str(val))
            self.entries[lbl] = ent

        ttk.Button(self, text="Tấn công", style="danger.Outline.TButton",
                   command=self.start_attack).pack(pady=8)

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
        try:
            vals = {k: int(v.get()) for k, v in self.entries.items()}
        except:
            messagebox.showerror("Lỗi", "Giá trị nhập không hợp lệ!")
            return
        t0 = time.perf_counter()
        m, steps = attack_common_modulus(
            vals['c1'], vals['c2'], vals['e1'], vals['e2'], vals['n']
        )
        t1 = time.perf_counter()
        steps.append(f"⏱️ Time: {(t1 - t0)*1000:.2f} ms")
        if m is not None:
            steps.append(f"Result m = {m}")
            try:
                steps.append(f"Plaintext = {int_to_string(m)}")
            except:
                pass

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

class MainMenu(tb.Window):
    def __init__(self):
        super().__init__(themename="superhero")
        self.title("🔐 RSA Attack Simulator")
        self.state('zoomed')
        self.configure(bg="#23272b")
        self.shared = {}

        tk.Label(self, text="RSA Attack Simulator",
                 font=("Arial",36,"bold"),
                 bg="#23272b", fg="#f8f9fa").pack(pady=(40,20))
        btnf = ttk.Frame(self); btnf.pack(pady=20)
        ttk.Button(btnf, text="🔑 Quản lý khóa", style="success.TButton", width=20,
                   command=lambda: KeyGenWindow(self, self.shared))\
            .grid(row=0, column=0, padx=20)
        ttk.Button(btnf, text="🔒 Mã hóa", style="info.TButton", width=20,
                   command=lambda: EncryptWindow(self, self.shared))\
            .grid(row=0, column=1, padx=20)
        ttk.Button(btnf, text="⚔️ Tấn Công", style="danger.TButton", width=20,
                   command=lambda: AttackWindow(self, self.shared))\
            .grid(row=0, column=2, padx=20)
        tk.Label(self, text="by MHH", font=("Arial",12,"italic"),
                 bg="#23272b", fg="#adb5bd").pack(pady=(40,10))

if __name__ == "__main__":
    app = MainMenu()
    app.mainloop()
