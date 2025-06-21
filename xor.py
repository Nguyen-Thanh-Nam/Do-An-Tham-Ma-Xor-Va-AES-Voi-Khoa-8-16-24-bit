def xor_encrypt(data: str, key: str) -> bytes:
    data_bytes = data.encode("utf-8")
    key_bytes = key.encode("utf-8")
    key_len = len(key_bytes)
    return bytes(data_bytes[i] ^ key_bytes[i % key_len] for i in range(len(data_bytes)))


def xor_decrypt(cipher: bytes, key: str) -> bytes:
    key_bytes = key.encode("utf-8")
    key_len = len(key_bytes)
    return bytes(cipher[i] ^ key_bytes[i % key_len] for i in range(len(cipher)))



if __name__ == "__main__":
    print("=== XOR ENCRYPTION ===")

    pt = input("Nhập plaintext: ")
    key = input("Nhập key XOR: ")

    ct = xor_encrypt(pt, key)
    print("Ciphertext (hex):", ct.hex())

    decrypted = xor_decrypt(ct, key)
    print("Plaintext sau giải mã:", decrypted.decode('utf-8'))

    
