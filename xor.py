def xor_encrypt(data: str, key: str) -> bytes:
    data_bytes = data.encode("utf-8")      # chuyển plaintext thành bytes
    key_bytes = key.encode("utf-8")
    result = []

    for i in range(len(data_bytes)):
        result.append(data_bytes[i] ^ key_bytes[i % len(key_bytes)])

    return bytes(result)


def xor_decrypt(cipher: bytes, key: str) -> str:
    key_bytes = key.encode("utf-8")
    result = []

    for i in range(len(cipher)):
        result.append(cipher[i] ^ key_bytes[i % len(key_bytes)])

    return bytes(result)


if __name__ == "__main__":
    print("=== XOR ENCRYPTION ===")

    pt = input("Nhập plaintext: ")
    key = input("Nhập key XOR: ")

    ct = xor_encrypt(pt, key)
    print("Ciphertext (hex):", ct.hex())

    decrypted = xor_decrypt(ct, key)
    print("Plaintext sau giải mã:", decrypted.decode('utf-8'))

    
