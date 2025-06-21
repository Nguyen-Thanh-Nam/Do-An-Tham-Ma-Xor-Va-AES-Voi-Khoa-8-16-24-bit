from aes import aes_encrypt, aes_decrypt
from time import time
from itertools import product


def is_printable(s: str) -> bool:
    return all(
        (48 <= ord(c) <= 57) or
        (64 <= ord(c) <= 90) or
        (97 <= ord(c) <= 122) or
        ord(c) == 32 or
        (0x00C0 <= ord(c) <= 0x01BF) or
        (0x1EA0 <= ord(c) <= 0x1EF9) or
        ord(c) in (44, 46, 10)
        for c in s
    )


def brute_aes(cipher_hex, key_size=1):
    try:
        cipher = bytes.fromhex(cipher_hex)
    except ValueError:
        print("Chuỗi hex không hợp lệ.")
        return {}, None

    print(f"Brute-force AES {key_size * 8}-bit")
    dem = 0
    tried_dict = {}
    valid_result = None

    for key_tuple in product(range(256), repeat=key_size):
        key = ''.join(chr(k) for k in key_tuple)
        dem += 1
        try:
            pt = aes_decrypt(cipher, key)
            tried_dict[key] = pt
            if is_printable(pt):
                valid_result = (key, pt, dem)
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
        keys = list(tried_dict.items())[-2000:]
        tried_dict = dict(keys)

    return tried_dict, valid_result


def brute_8bit(cipher_hex):
    return brute_aes(cipher_hex, key_size=1)


def brute_16bit(cipher_hex):
    return brute_aes(cipher_hex, key_size=2)


def brute_24bit(cipher_hex):
    return brute_aes(cipher_hex, key_size=3)


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
