#!/usr/bin/env python3
"""
Universal .so Patcher: Plain Text, XOR, Oxorany, Combined Scan.
Yêu cầu: numpy, numba (tùy chọn)
"""
import os, sys, re, shutil, argparse
import numpy as np
from pathlib import Path
from typing import List, Tuple, Dict

# ─── Cấu hình ──────────────────────────────────────────────
STEP = 16                # align 0x10 của oxorany
WIN_SIZE = 2048          # cửa sổ giải mã oxorany
DEFAULT_XOR_KEY = 0x2E
MIN_STR_LEN = 5

# Tập ký tự an toàn cho URL (tránh rác)
URL_SAFE = set(b'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_~:/?#[]@!$&\'()*+,;=%')
def is_url_safe(b): return b in URL_SAFE

# ─── Tăng tốc Numba (nếu có) ──────────────────────────────
try:
    from numba import njit
    USE_NUMBA = True
    print("[*] Numba enabled – tốc độ oxorany tối đa.")
except ImportError:
    USE_NUMBA = False
    print("[*] Numba không có, dùng pure Python (vẫn nhanh).")

if USE_NUMBA:
    @njit
    def is_url_safe_numba(b):
        if 0x61 <= b <= 0x7A: return True
        if 0x41 <= b <= 0x5A: return True
        if 0x30 <= b <= 0x39: return True
        if b in (0x2D,0x2E,0x5F,0x7E,0x3A,0x2F,0x3F,0x23,0x5B,0x5D,0x40,0x21,0x24,0x26,0x27,0x28,0x29,0x2A,0x2B,0x2C,0x3B,0x3D,0x25):
            return True
        return False

    @njit
    def decrypt_byte_numba(enc, idx, key):
        return ((enc ^ ((idx + key) & 0xFF)) - (key * 7)) & 0xFF

    @njit
    def scan_window_numba(enc_data, key, pattern, pat_len):
        n = len(enc_data)
        K7 = (key * 7) & 0xFF
        dec = np.empty(n, dtype=np.uint8)
        for i in range(n):
            dec[i] = ((enc_data[i] ^ ((i + key) & 0xFF)) - K7) & 0xFF
        for i in range(n - pat_len + 1):
            match = True
            for j in range(pat_len):
                if dec[i+j] != pattern[j]:
                    match = False
                    break
            if match:
                start = i
                while start > 0 and is_url_safe_numba(dec[start-1]):
                    start -= 1
                end = i + pat_len
                while end < n and dec[end] != 0 and is_url_safe_numba(dec[end]):
                    end += 1
                return start, end
        return -1, -1
else:
    def scan_window_numpy(enc_data, key, pattern, pat_len):
        n = len(enc_data)
        K7 = (key * 7) & 0xFF
        idx = np.arange(n, dtype=np.uint64)
        dec = ((enc_data ^ ((idx + key) & 0xFF)) - K7) & 0xFF
        match = np.ones(n - pat_len + 1, dtype=bool)
        for j in range(pat_len):
            match &= (dec[j:j+n-pat_len+1] == pattern[j])
        found = np.where(match)[0]
        if found.size > 0:
            i = found[0]
            start = i
            while start > 0 and is_url_safe(dec[start-1]):
                start -= 1
            end = i + pat_len
            while end < n and dec[end] != 0 and is_url_safe(dec[end]):
                end += 1
            return start, end
        return -1, -1

    def decrypt_byte_numba(enc, idx, key):
        return ((enc ^ ((idx + key) & 0xFF)) - (key * 7)) & 0xFF

# ─── Hàm tiện ích ─────────────────────────────────────────
def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def backup_file(path):
    bak = path + ".bak"
    shutil.copy2(path, bak)
    return bak

# ─── Class chính ──────────────────────────────────────────
class UniversalPatcher:
    def __init__(self):
        self.file = None           # đường dẫn file hiện tại
        self.xor_key = DEFAULT_XOR_KEY
        self.oxorany_results = []  # (key, offset, string)

    # ── Load file ──────────────────────────────────────
    def load_file(self, path):
        if not os.path.isfile(path):
            print("❌ File không tồn tại.")
            return False
        self.file = path
        print(f"✅ Đã chọn: {path}")
        return True

    # ── Chế độ 1: Không mã hóa (plain text) ─────────────
    def plain_search(self, term):
        """Tìm kiếm trực tiếp trong file nhị phân."""
        if not self.file: return []
        with open(self.file, 'rb') as f:
            data = f.read()
        results = []
        pos = 0
        while True:
            idx = data.find(term.encode(), pos)
            if idx == -1: break
            # Lấy context xung quanh
            ctx_start = max(0, idx - 20)
            ctx_end = min(len(data), idx + len(term) + 20)
            try:
                ctx = data[ctx_start:ctx_end].decode('ascii', errors='replace')
            except:
                ctx = repr(data[ctx_start:ctx_end])
            results.append((idx, ctx))
            pos = idx + 1
        return results

    def plain_replace(self, offset, old_str, new_str):
        """Thay thế trực tiếp tại offset."""
        if not self.file: return False
        if len(new_str) > len(old_str):
            print("⚠️ Chuỗi mới dài hơn chuỗi cũ, không thể thay.")
            return False
        with open(self.file, 'rb') as f:
            data = bytearray(f.read())
        old_bytes = old_str.encode()
        new_bytes = new_str.encode()
        if offset + len(old_bytes) > len(data):
            print("❌ Offset vượt quá kích thước file.")
            return False
        if data[offset:offset+len(old_bytes)] != old_bytes:
            print("⚠️ Dữ liệu tại offset không khớp. Tiếp tục? (y/n)")
            if input().lower() != 'y':
                return False
        data[offset:offset+len(new_bytes)] = new_bytes
        if len(new_bytes) < len(old_bytes):
            data[offset+len(new_bytes):offset+len(old_bytes)] = b'\x00' * (len(old_bytes)-len(new_bytes))
        out = self._get_output_path()
        with open(out, 'wb') as f:
            f.write(data)
        try: shutil.copystat(self.file, out)
        except: pass
        print(f"✅ Đã thay thế thành công → {out}")
        return True

    # ── Chế độ 2: XOR Key ──────────────────────────────
    def xor_crypt(self, data, key):
        return bytes([b ^ (key & 0xFF) for b in data])

    def xor_find_urls(self, data):
        pat = re.compile(rb"https?://[A-Za-z0-9\./_\-\?\=&%:#]+")
        return [(m.start(), m.group().decode(errors="ignore")) for m in pat.finditer(data)]

    def xor_bruteforce(self, start=0, end=255, aggressive=False):
        if not self.file: return {}
        with open(self.file, 'rb') as f: data = f.read()
        results = {}
        for k in range(start, end+1):
            dec = self.xor_crypt(data, k)
            if aggressive:
                urls = self._xor_find_aggressive(dec)
            else:
                urls = self.xor_find_urls(dec)
            if urls:
                results[k] = urls[:10]
        return results

    def _xor_find_aggressive(self, data):
        patterns = [
            rb"https?://[A-Za-z0-9\./_\-\?\=&%:#]+",
            rb"www\.[A-Za-z0-9\./_\-\?\=&%:#]+",
            rb"[A-Za-z0-9\-]+\.(com|net|org|io|vn|edu|gov)[A-Za-z0-9\./_\-\?\=&%:#]*"
        ]
        urls, seen = [], set()
        for pat in patterns:
            for m in re.finditer(pat, data):
                try:
                    u = m.group().decode(errors='ignore')
                    if u not in seen:
                        urls.append((m.start(), u))
                        seen.add(u)
                except: continue
        return urls

    def xor_list_urls(self):
        if not self.file: return []
        with open(self.file, 'rb') as f: data = f.read()
        dec = self.xor_crypt(data, self.xor_key)
        return self.xor_find_urls(dec)

    def xor_replace_url(self, old_url, new_url):
        if not self.file: return False
        with open(self.file, 'rb') as f: data = f.read()
        dec = self.xor_crypt(data, self.xor_key)
        urls = self.xor_find_urls(dec)
        target = None
        for off, u in urls:
            if u == old_url:
                target = (off, u)
                break
        if not target:
            print("❌ Không tìm thấy URL cũ.")
            return False
        off, u = target
        oldb = u.encode()
        newb = new_url.encode()
        if len(newb) > len(oldb):
            print("⚠️ URL mới dài hơn, không thể thay.")
            return False
        patched = bytearray(dec)
        patched[off:off+len(newb)] = newb
        if len(newb) < len(oldb):
            patched[off+len(newb):off+len(oldb)] = b'\x00' * (len(oldb)-len(newb))
        enc_out = self.xor_crypt(bytes(patched), self.xor_key)
        out = self._get_output_path()
        with open(out, 'wb') as f: f.write(enc_out)
        try: shutil.copystat(self.file, out)
        except: pass
        print(f"✅ Đã thay thế và lưu vào {out}")
        return True

    # ── Chế độ 3: Oxorany ──────────────────────────────
    def oxorany_scan(self, search_str="http"):
        if not self.file: return []
        data = np.fromfile(self.file, dtype=np.uint8)
        pattern = np.array([ord(c) for c in search_str.lower()], dtype=np.uint8)
        pat_len = len(pattern)
        results = []
        seen = set()
        scan_func = scan_window_numba if USE_NUMBA else scan_window_numpy
        for key in range(256):
            for base in range(0, len(data) - WIN_SIZE, STEP):
                win = data[base:base+WIN_SIZE]
                s, e = scan_func(win, key, pattern, pat_len)
                if s != -1 and e - s >= MIN_STR_LEN:
                    abs_off = base + s
                    if (key, abs_off) not in seen:
                        seen.add((key, abs_off))
                        dec_chunk = bytes(decrypt_byte_numba(win[i], i, key) for i in range(s, e))
                        try:
                            dstr = dec_chunk.decode('ascii')
                        except:
                            continue
                        if (dstr.startswith('http') or dstr.startswith('www')) and '://' in dstr:
                            results.append((key, abs_off, dstr))
        # Lọc ưu tiên offset chia hết cho 16
        uniq = {}
        for k, off, s in results:
            if off % 16 == 0:
                uniq[(k, s)] = (off, s)
            else:
                if (k, s) not in uniq:
                    uniq[(k, s)] = (off, s)
        final = [(k, off, s) for (k, s), (off, _) in uniq.items()]
        self.oxorany_results = final
        return final

    def oxorany_replace(self, index, new_str):
        if not self.oxorany_results or index < 0 or index >= len(self.oxorany_results):
            print("❌ Chỉ số không hợp lệ.")
            return False
        key, abs_off, old_str = self.oxorany_results[index]
        if len(new_str.encode()) > len(old_str.encode()):
            print("⚠️ Chuỗi mới dài hơn, không thể thay.")
            return False
        buf_start = abs_off - (abs_off % STEP)
        with open(self.file, 'rb') as f:
            f.seek(buf_start)
            enc_win = f.read(WIN_SIZE)
        if len(enc_win) < WIN_SIZE:
            print("❌ Không đọc đủ dữ liệu.")
            return False
        win_arr = np.frombuffer(enc_win, dtype=np.uint8)
        dec = bytes(decrypt_byte_numba(win_arr[i], i, key) for i in range(WIN_SIZE))
        old_bytes = old_str.encode()
        pos = dec.find(old_bytes)
        if pos == -1:
            print("❌ Không tìm thấy chuỗi cũ trong buffer.")
            return False
        dec_arr = bytearray(dec)
        new_bytes = new_str.encode()
        dec_arr[pos:pos+len(new_bytes)] = new_bytes
        if len(new_bytes) < len(old_bytes):
            dec_arr[pos+len(new_bytes):pos+len(old_bytes)] = b'\x00' * (len(old_bytes)-len(new_bytes))
        new_enc = bytes(decrypt_byte_numba(dec_arr[i], i, key) for i in range(WIN_SIZE))
        bak = backup_file(self.file)
        print(f"ℹ️ Backup: {bak}")
        with open(self.file, 'r+b') as f:
            f.seek(buf_start)
            f.write(new_enc)
        print(f"✅ Đã thay thế thành công.")
        self.oxorany_results[index] = (key, abs_off, new_str)
        return True

    def oxorany_save_results(self):
        if not self.oxorany_results:
            print("❌ Chưa có kết quả quét.")
            return
        out = self.file + "_oxorany_urls.txt"
        with open(out, 'w') as f:
            for k, off, s in self.oxorany_results:
                f.write(f"key=0x{k:02X} offset=0x{off:X} -> {s}\n")
        print(f"📄 Đã lưu: {out}")

    # ── Chế độ 4: Scan tổng hợp ───────────────────────
    def combined_scan(self, search_str="http"):
        print("⚡ Đang quét tổng hợp (XOR + Oxorany)...")
        # XOR brute-force toàn bộ
        xor_res = self.xor_bruteforce(0, 255, aggressive=False)
        print(f"✅ XOR: tìm thấy {sum(len(v) for v in xor_res.values())} URL(s) với {len(xor_res)} key.")
        for k, urls in sorted(xor_res.items()):
            for off, u in urls:
                print(f"  [XOR] key=0x{k:02X} offset=0x{off:X} -> {u}")
        # Oxorany scan
        oxo_res = self.oxorany_scan(search_str)
        print(f"✅ Oxorany: tìm thấy {len(oxo_res)} URL(s) sạch.")
        for k, off, s in oxo_res:
            print(f"  [OXORANY] key=0x{k:02X} offset=0x{off:X} -> {s}")
        # Lưu kết quả gộp
        out = self.file + "_combined_urls.txt"
        with open(out, 'w') as f:
            f.write("=== XOR URLs ===\n")
            for k, urls in sorted(xor_res.items()):
                for off, u in urls:
                    f.write(f"key=0x{k:02X} offset=0x{off:X} -> {u}\n")
            f.write("\n=== Oxorany URLs ===\n")
            for k, off, s in oxo_res:
                f.write(f"key=0x{k:02X} offset=0x{off:X} -> {s}\n")
        print(f"📄 Kết quả tổng hợp đã lưu: {out}")

    # ── Tiện ích nội bộ ────────────────────────────────
    def _get_output_path(self):
        dirn = os.path.dirname(self.file)
        base = os.path.basename(self.file)
        name, ext = os.path.splitext(base)
        i = 1
        while True:
            p = os.path.join(dirn, f"{name}_patched_{i}{ext}")
            if not os.path.exists(p):
                return p
            i += 1

# ─── Menu từng chế độ ─────────────────────────────────────
def mode_plain(patcher):
    while True:
        clear_screen()
        print("=" * 50)
        print("     CHẾ ĐỘ 1: KHÔNG MÃ HÓA (PLAIN TEXT)")
        print("=" * 50)
        print("1. Tìm kiếm chuỗi")
        print("2. Thay thế chuỗi (theo offset)")
        print("0. Quay lại menu chính")
        choice = input("Chọn: ").strip()
        if choice == '1':
            term = input("Nhập chuỗi cần tìm: ").strip()
            if term:
                res = patcher.plain_search(term)
                if res:
                    for idx, ctx in res:
                        print(f"  Offset 0x{idx:X}: ...{ctx}...")
                else:
                    print("Không tìm thấy.")
            input("\nEnter để tiếp tục...")
        elif choice == '2':
            try:
                off = int(input("Offset (hex): ").strip(), 16)
                old = input("Chuỗi cũ (để xác nhận): ").strip()
                new = input("Chuỗi mới: ").strip()
                if old and new:
                    patcher.plain_replace(off, old, new)
            except ValueError:
                print("❌ Offset không hợp lệ.")
            input("\nEnter để tiếp tục...")
        elif choice == '0':
            break

def mode_xor(patcher):
    while True:
        clear_screen()
        print("=" * 50)
        print(f"     CHẾ ĐỘ 2: XOR KEY (key hiện tại: 0x{patcher.xor_key:02X})")
        print("=" * 50)
        print("1. Đặt key XOR")
        print("2. Liệt kê URL với key hiện tại")
        print("3. Brute-force tìm key XOR")
        print("4. Thay thế URL (theo key hiện tại)")
        print("0. Quay lại")
        choice = input("Chọn: ").strip()
        if choice == '1':
            try:
                k = input("Nhập key (hex hoặc decimal): ").strip()
                if k.startswith('0x'): patcher.xor_key = int(k,16) & 0xFF
                else: patcher.xor_key = int(k) & 0xFF
                print(f"✅ Key hiện tại: 0x{patcher.xor_key:02X}")
            except ValueError:
                print("❌ Key không hợp lệ.")
            input("\nEnter...")
        elif choice == '2':
            urls = patcher.xor_list_urls()
            if urls:
                for off, u in urls:
                    print(f"  Offset 0x{off:X}: {u}")
            else:
                print("❌ Không có URL nào.")
            input("\nEnter...")
        elif choice == '3':
            try:
                s = input("Key bắt đầu (mặc định 0x00): ").strip()
                start = int(s,16) if s.startswith('0x') else (int(s) if s else 0)
                e = input("Key kết thúc (mặc định 0xFF): ").strip()
                end = int(e,16) if e.startswith('0x') else (int(e) if e else 255)
            except:
                start, end = 0, 255
            agg = input("Chế độ nâng cao (tìm cả domain)? (y/N): ").lower() == 'y'
            res = patcher.xor_bruteforce(start, end, agg)
            if res:
                for k, urls in sorted(res.items()):
                    print(f"\n🔑 Key 0x{k:02X}:")
                    for off, u in urls[:5]:
                        print(f"  Offset 0x{off:X}: {u}")
            else:
                print("❌ Không tìm thấy URL nào.")
            # Hỏi chọn key
            use = input("\nDùng key nào? (Enter bỏ qua): ").strip()
            if use:
                try:
                    if use.startswith('0x'): patcher.xor_key = int(use,16) & 0xFF
                    else: patcher.xor_key = int(use) & 0xFF
                    print(f"✅ Đã đặt key: 0x{patcher.xor_key:02X}")
                except: pass
            input("\nEnter...")
        elif choice == '4':
            old = input("URL cũ: ").strip()
            new = input("URL mới: ").strip()
            if old and new:
                patcher.xor_replace_url(old, new)
            input("\nEnter...")
        elif choice == '0':
            break

def mode_oxorany(patcher):
    while True:
        clear_screen()
        print("=" * 50)
        print("     CHẾ ĐỘ 3: OXORANY")
        print("=" * 50)
        print("1. Quét tìm URL (oxorany)")
        print("2. Hiển thị kết quả quét")
        print("3. Thay thế URL từ kết quả")
        print("4. Lưu kết quả ra file")
        print("0. Quay lại")
        choice = input("Chọn: ").strip()
        if choice == '1':
            term = input("Nhập từ khóa (mặc định 'http'): ").strip() or 'http'
            res = patcher.oxorany_scan(term)
            if res:
                for i, (k, off, s) in enumerate(res, 1):
                    print(f"{i}. key=0x{k:02X} offset=0x{off:X} -> {s}")
            else:
                print("❌ Không tìm thấy.")
            input("\nEnter...")
        elif choice == '2':
            if not patcher.oxorany_results:
                print("❌ Chưa có kết quả quét.")
            else:
                for i, (k, off, s) in enumerate(patcher.oxorany_results, 1):
                    print(f"{i}. key=0x{k:02X} offset=0x{off:X} -> {s}")
            input("\nEnter...")
        elif choice == '3':
            if not patcher.oxorany_results:
                print("❌ Chưa quét, vui lòng quét trước.")
                input(); continue
            try:
                idx = int(input("Chọn số thứ tự URL cần thay: ")) - 1
                new = input("URL mới: ").strip()
                if new:
                    patcher.oxorany_replace(idx, new)
            except:
                print("❌ Lỗi.")
            input("\nEnter...")
        elif choice == '4':
            patcher.oxorany_save_results()
            input("\nEnter...")
        elif choice == '0':
            break

def mode_combined(patcher):
    clear_screen()
    print("=" * 50)
    print("     CHẾ ĐỘ 4: SCAN TỔNG HỢP (XOR + OXORANY)")
    print("=" * 50)
    term = input("Nhập từ khóa cho oxorany (mặc định 'http'): ").strip() or 'http'
    patcher.combined_scan(term)
    input("\nHoàn tất. Enter để quay lại menu chính.")

# ─── Menu chính ────────────────────────────────────────────
def main():
    patcher = UniversalPatcher()
    while True:
        clear_screen()
        print("=" * 60)
        print("           UNIVERSAL .SO PATCHER")
        print("=" * 60)
        print(f"File: {patcher.file if patcher.file else 'Chưa chọn'}")
        print("-" * 60)
        print("1. Load file")
        print("2. Chế độ: Không mã hóa (Plain Text)")
        print("3. Chế độ: XOR Key")
        print("4. Chế độ: Oxorany")
        print("5. Chế độ: Scan tổng hợp")
        print("6. Thoát")
        print("-" * 60)
        ch = input("Chọn: ").strip()
        if ch == '1':
            f = input("Đường dẫn file: ").strip()
            if f: patcher.load_file(f)
            input("\nEnter...")
        elif ch == '2':
            if not patcher.file:
                print("❌ Chưa load file!"); input(); continue
            mode_plain(patcher)
        elif ch == '3':
            if not patcher.file:
                print("❌ Chưa load file!"); input(); continue
            mode_xor(patcher)
        elif ch == '4':
            if not patcher.file:
                print("❌ Chưa load file!"); input(); continue
            mode_oxorany(patcher)
        elif ch == '5':
            if not patcher.file:
                print("❌ Chưa load file!"); input(); continue
            mode_combined(patcher)
        elif ch == '6':
            print("👋 Tạm biệt!")
            break
        else:
            print("❌ Lựa chọn không hợp lệ!")
            input()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n✋ Dừng bởi người dùng.")
