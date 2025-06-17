from aes import aes_encrypt, aes_decrypt
from time import time

def is_printable(s: str) -> bool:
    return all(
        (48 <= ord(c) <= 57) or          # 0–9
        (65 <= ord(c) <= 90) or          # A–Z
        (97 <= ord(c) <= 122) or         # a–z
        ord(c) == 32 or                  # space
        (0x00C0 <= ord(c) <= 0x01BF) or  # Latin Extended-A: tiếng Việt (ơ, ê, đ, â, ...)
        (0x1EA0 <= ord(c) <= 0x1EF9)     # Vietnamese-specific letters (ằ, ắ, ộ, ễ, ...)
        for c in s
    )



def brute_8bit(cipher_hex):
    c = bytes.fromhex(cipher_hex)
    print("Brute-force 8-bit")
    dem = 0
    for i in range(256):
        key = chr(i)
        dem += 1
        try:
            pt = aes_decrypt(c, key)
            if aes_encrypt(pt, key) == c and is_printable(pt):
                print(f"Key = {(key)}")  
                print(f"Plaintext = {pt}")
                print(f"Số lần thực hiên = {dem}")
                return
        except:
            continue

def brute_16bit(cipher_hex):
    c = bytes.fromhex(cipher_hex)
    print("Brute-force 16-bit")
    dem = 0
    for a in range(256):
        for b in range(256):
            key = chr(a) + chr(b) 
            dem += 1
            try:
                pt = aes_decrypt(c, key)
                if aes_encrypt(pt, key) == c and is_printable(pt):
                    print(f"Key = {(key)}")  
                    print(f"Plaintext = {pt}")
                    print(f"Số lần thực hiên = {dem}")
                    return
            except:
                continue

def brute_24bit(cipher_hex):
    c = bytes.fromhex(cipher_hex)
    print("Brute-force 24-bit")
    dem = 0
    for a in range(256):
        for b in range(256):
            for c_ in range(256):
                key = chr(a) + chr(b) + chr(c_)
                dem += 1
                try:
                    pt = aes_decrypt(c, key)
                    if aes_encrypt(pt, key) == c and is_printable(pt):
                        print(f"Key = {(key)}")
                        print(f"Plaintext = {pt}")
                        print(f"Số lần thực hiên = {dem}")
                        return
                except:
                    continue

def menu():
    print("\n=== THÁM MÃ AES ===")
    print("1. Brute-force AES 8-bit")
    print("2. Brute-force AES 16-bit")
    print("3. Brute-force AES 24-bit")
    print("0. Thoát")

def main():
    while True:
        menu()
        choice = input("Chọn: ").strip()

        if choice in {"1", "2", "3"}:
            cipher_hex = input("Nhập ciphertext (hex): ").strip()
            start = time()

            if choice == "1":
                brute_8bit(cipher_hex)
            elif choice == "2":
                brute_16bit(cipher_hex)
            elif choice == "3":
                brute_24bit(cipher_hex)

            print(f"Thời gian xử lý: {round(time() - start, 2)} giây")

        elif choice == "0":
            print("Thoát chương trình.")
            break
        else:
            print("Lựa chọn không hợp lệ.")

if __name__ == "__main__":
    main()
