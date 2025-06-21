from itertools import product
from time import time

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
        decoded = s.decode('utf-8')
        return all(
            (64 <= ord(c) <= 90) or
            (97 <= ord(c) <= 122) or
            (48 <= ord(c) <= 57) or
            ord(c) == 32 or
            (0x00C0 <= ord(c) <= 0x01BF) or
            (0x1EA0 <= ord(c) <= 0x1EF9) or
            ord(c) in (44, 46, 10)
            for c in decoded
        )
    except UnicodeDecodeError:
        return False

def brute_xor(cipher_hex, key_size=1):
    try:
        cipher = bytes.fromhex(cipher_hex)
    except ValueError:
        print("Chuỗi hex không hợp lệ.")
        return {}, None

    print(f"Brute-force XOR {key_size * 8}-bit")
    dem = 0
    tried_dict = {}
    valid_result = None

    for key_tuple in product(range(256), repeat=key_size):
        key = ''.join(chr(k) for k in key_tuple)
        dem += 1
        try:
            pt = xor_decrypt(cipher, key)
            decoded = pt.decode('utf-8')
            tried_dict[key] = decoded
            if is_printable_ascii(pt) and xor_encrypt(pt, key) == cipher:
                valid_result = (key, decoded, dem)
                break
        except:
            tried_dict[key] = "lỗi khi giải mã"

    if valid_result:
        key, plaintext, count = valid_result
        print(f"\n✔️ Tìm thấy khóa hợp lệ!")
        print(f"Key: {key}")
        print(f"Plaintext: {plaintext}")
        print(f"Số lần thực hiện: {count}")
    else:
        print("Không tìm thấy khóa phù hợp.")

    if key_size == 3:
        tried_dict = dict(list(tried_dict.items())[-2000:])

    return tried_dict, valid_result

def brute_8bit(cipher_hex):
    return brute_xor(cipher_hex, key_size=1)

def brute_16bit(cipher_hex):
    return brute_xor(cipher_hex, key_size=2)

def brute_24bit(cipher_hex):
    return brute_xor(cipher_hex, key_size=3)

def menu():
    print("\n=== THÁM MÃ XOR ===")
    print("1. Brute-force XOR 8-bit")
    print("2. Brute-force XOR 16-bit")
    print("3. Brute-force XOR 24-bit")
    print("0. Thoát")

def main():
    while True:
        menu()
        choice = input("Chọn: ").strip()

        if choice in {"1", "2", "3"}:
            cipher_hex = input("Nhập ciphertext (hex): ").strip()
            start = time()

            if choice == "1":
                tried, valid = brute_8bit(cipher_hex)
            elif choice == "2":
                tried, valid = brute_16bit(cipher_hex)
            elif choice == "3":
                tried, valid = brute_24bit(cipher_hex)

            print(f"\nThời gian xử lý: {round(time() - start, 2)} giây")

        elif choice == "0":
            print("Thoát chương trình.")
            break
        else:
            print("Lựa chọn không hợp lệ.")

if __name__ == "__main__":
    main()
