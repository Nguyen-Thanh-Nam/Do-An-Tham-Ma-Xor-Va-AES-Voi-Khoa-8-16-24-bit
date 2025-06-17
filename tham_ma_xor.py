from itertools import product
from time import time
import string


def xor_encrypt(data, key: str) -> bytes:
    if isinstance(data, str):
        data = data.encode("utf-8")
    key_bytes = key.encode("utf-8")
    return bytes([data[i] ^ key_bytes[i % len(key_bytes)] for i in range(len(data))])


def xor_decrypt(cipher: bytes, key: str) -> bytes:
    key_bytes = key.encode("utf-8")
    return bytes([cipher[i] ^ key_bytes[i % len(key_bytes)] for i in range(len(cipher))])


def is_printable_ascii(s: bytes) -> bool:
    try:
        decoded = s.decode('utf-8')  # Giải mã bytes sang chuỗi Unicode
        return all(
            (65 <= ord(c) <= 90) or          # A–Z
            (97 <= ord(c) <= 122) or         # a–z
            (48 <= ord(c) <= 57) or          # 0–9
            ord(c) == 32 or                  # space
            (0x00C0 <= ord(c) <= 0x01BF) or  # Latin-1 Extended
            (0x1EA0 <= ord(c) <= 0x1EF9)     # Vietnamese-specific letters
            for c in decoded
        )
    except UnicodeDecodeError:
        return False



def brute_8bit(cipher_hex):
    found = False
    print("Brute-force XOR 8-bit")
    cipher = bytes.fromhex(cipher_hex)
    dem = 0
    for i in range(256):
        key = chr(i)
        dem += 1
        pt = xor_decrypt(cipher, key)
        if is_printable_ascii(pt) and xor_encrypt(pt, key) == cipher:
            print(f"Key: {key}")
            print("Plaintext:", pt.decode('utf-8'))
            print(f"Số lần thực hiên = {dem}")
            found = True
            break
    
    if not found:
        print("Không tìm thấy khóa phù hợp.")



def brute_16bit(cipher_hex):
    print("Brute-force XOR 16-bit")
    cipher = bytes.fromhex(cipher_hex)
    found = False
    dem = 0
    for a, b in product(range(256), repeat=2):
        key = chr(a) + chr(b)
        pt = xor_decrypt(cipher, key)
        dem += 1
        if is_printable_ascii(pt) and xor_encrypt(pt, key) == cipher:
            text = pt.decode('utf-8')
            print(f"Key: {key}")
            print("Plaintext:", text)
            print(f"Số lần thực hiên = {dem}")
            found = True
            break

    if not found:
        print("Không tìm thấy khóa phù hợp.")

# Brute-force với key 3 byte (24-bit)
def brute_24bit(cipher_hex):
    found = False
    print("Brute-force XOR 24-bit")
    dem = 0
    cipher = bytes.fromhex(cipher_hex)
    for a, b, c in product(range(256), repeat=3):
        key = chr(a) + chr(b) + chr(c)
        pt = xor_decrypt(cipher, key)
        dem += 1
        if is_printable_ascii(pt) and xor_encrypt(pt, key) == cipher:
            print(f"Key: {key}")
            print("Plaintext:", pt.decode('utf-8'))
            print(f"Số lần thực hiên = {dem}")
            found = True
            break
    if not found:
        print("Không tìm thấy khóa phù hợp.")


# Menu lựa chọn
def menu():
    print("\n=== THÁM MÃ XOR ===")
    print("1. Brute-force XOR 8-bit")
    print("2. Brute-force XOR 16-bit")
    print("3. Brute-force XOR 24-bit")
    print("0. Thoát")

# Chương trình chính
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
