from time import time
from Crypto.Util.Padding import pad, unpad

# === Lookup tables ===
Sbox = [
    99,124,119,123,242,107,111,197,48,1,103,43,254,215,171,118,
    202,130,201,125,250,89,71,240,173,212,162,175,156,164,114,192,
    183,253,147,38,54,63,247,204,52,165,229,241,113,216,49,21,
    4,199,35,195,24,150,5,154,7,18,128,226,235,39,178,117,
    9,131,44,26,27,110,90,160,82,59,214,179,41,227,47,132,
    83,209,0,237,32,252,177,91,106,203,190,57,74,76,88,207,
    208,239,170,251,67,77,51,133,69,249,2,127,80,60,159,168,
    81,163,64,143,146,157,56,245,188,182,218,33,16,255,243,210,
    205,12,19,236,95,151,68,23,196,167,126,61,100,93,25,115,
    96,129,79,220,34,42,144,136,70,238,184,20,222,94,11,219,
    224,50,58,10,73,6,36,92,194,211,172,98,145,149,228,121,
    231,200,55,109,141,213,78,169,108,86,244,234,101,122,174,8,
    186,120,37,46,28,166,180,198,232,221,116,31,75,189,139,138,
    112,62,181,102,72,3,246,14,97,53,87,185,134,193,29,158,
    225,248,152,17,105,217,142,148,155,30,135,233,206,85,40,223,
    140,161,137,13,191,230,66,104,65,153,45,15,176,84,187,22
]

InvSbox = [0]*256
for i in range(256):
    InvSbox[Sbox[i]] = i

Rcon = [0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36]

XTIME = [((x << 1) ^ 0x1B) & 0xFF if x & 0x80 else x << 1 for x in range(256)]

GF_MUL = [[0]*256 for _ in range(256)]
for a in range(256):
    for b in range(256):
        r, aa, bb = 0, a, b
        for _ in range(8):
            if bb & 1: r ^= aa
            hi = aa & 0x80
            aa = (aa << 1) & 0xFF
            if hi: aa ^= 0x1B
            bb >>= 1
        GF_MUL[a][b] = r


def sub_bytes(s): return [Sbox[b] for b in s]
def inv_sub_bytes(s): return [InvSbox[b] for b in s]

def shift_rows(s):
    return [s[i % 4 + (i // 4 * 4)] for i in [0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11]]

def inv_shift_rows(s):
    return [s[i % 4 + (i // 4 * 4)] for i in [0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3]]

def mix_columns(s):
    r = []
    for c in range(0, 16, 4):
        a = s[c:c+4]
        r += [
            XTIME[a[0]] ^ XTIME[a[1]] ^ a[1] ^ a[2] ^ a[3],
            a[0] ^ XTIME[a[1]] ^ XTIME[a[2]] ^ a[2] ^ a[3],
            a[0] ^ a[1] ^ XTIME[a[2]] ^ XTIME[a[3]] ^ a[3],
            XTIME[a[0]] ^ a[0] ^ a[1] ^ a[2] ^ XTIME[a[3]]
        ]
    return r

def inv_mix_columns(s):
    r = []
    for c in range(0, 16, 4):
        a = s[c:c+4]
        r += [
            GF_MUL[a[0]][14] ^ GF_MUL[a[1]][11] ^ GF_MUL[a[2]][13] ^ GF_MUL[a[3]][9],
            GF_MUL[a[0]][9] ^ GF_MUL[a[1]][14] ^ GF_MUL[a[2]][11] ^ GF_MUL[a[3]][13],
            GF_MUL[a[0]][13] ^ GF_MUL[a[1]][9] ^ GF_MUL[a[2]][14] ^ GF_MUL[a[3]][11],
            GF_MUL[a[0]][11] ^ GF_MUL[a[1]][13] ^ GF_MUL[a[2]][9] ^ GF_MUL[a[3]][14]
        ]
    return r

def add_round_key(s, k): return [x ^ y for x, y in zip(s, k)]

def key_expansion(key):
    ks = list(key)
    for i in range(4, 44):
        t = ks[(i-1)*4:i*4]
        if i % 4 == 0:
            t = [Sbox[b] for b in t[1:] + t[:1]]
            t[0] ^= Rcon[i//4]
        ks += [x ^ y for x, y in zip(ks[(i-4)*4:(i-3)*4], t)]
    return [ks[i*4:(i+1)*4] for i in range(44)]

def encrypt_block(p, w):
    s = add_round_key(list(p), sum(w[0:4], []))
    for r in range(1, 10):
        s = mix_columns(shift_rows(sub_bytes(s)))
        s = add_round_key(s, sum(w[r*4:(r+1)*4], []))
    s = shift_rows(sub_bytes(s))
    s = add_round_key(s, sum(w[40:44], []))
    return bytes(s)

def decrypt_block(c, w):
    s = add_round_key(list(c), sum(w[40:44], []))
    for r in range(9, 0, -1):
        s = inv_mix_columns(add_round_key(inv_sub_bytes(inv_shift_rows(s)), sum(w[r*4:(r+1)*4], [])))
    s = add_round_key(inv_sub_bytes(inv_shift_rows(s)), sum(w[0:4], []))
    return bytes(s)

def fix_key(k):
    k = k.encode("latin1")
    return (k + b'\x00' * 16)[:16]

def aes_encrypt(pt, key_str):
    key = fix_key(key_str)
    w = key_expansion(key)
    pt = pad(pt.encode("utf-8"), 16)
    return b"".join(encrypt_block(pt[i:i+16], w) for i in range(0, len(pt), 16))

def aes_decrypt(ct, key_str):
    key = fix_key(key_str)
    w = key_expansion(key)
    decrypted = b"".join(decrypt_block(ct[i:i+16], w) for i in range(0, len(ct), 16))
    return unpad(decrypted, 16).decode("utf-8", errors="ignore")

if __name__ == "__main__":
    print("=== AES-128 ECB (Python thuần) ===")
    pt = input("Nhập plaintext: ")
    key = input("Nhập key: ")
    ct = aes_encrypt(pt, key)
    print(f"\n[+] Ciphertext (hex): {ct.hex()}")
   
    decrypted = aes_decrypt(ct, key)
    print(f"[+] Giải mã: {decrypted}")
 
