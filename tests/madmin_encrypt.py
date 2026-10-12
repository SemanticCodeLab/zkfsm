#!/usr/bin/env python3
"""Encrypts stdin like madmin's EncryptData (PBKDF2 + AES-256-GCM variant) for
admin routes that take an encrypted body. Standard library only.

usage: madmin_encrypt.py SECRET < plain > cipher
"""
import hashlib
import os
import sys

SBOX = [0] * 256


def _init_sbox():
    p = q = 1
    while True:
        p = p ^ ((p << 1) & 0xFF) ^ (0x1B if p & 0x80 else 0)
        q ^= q << 1
        q ^= q << 2
        q ^= q << 4
        q &= 0xFF
        if q & 0x80:
            q ^= 0x09
        x = q ^ (q << 1 | q >> 7) ^ (q << 2 | q >> 6) ^ (q << 3 | q >> 5) ^ (q << 4 | q >> 4)
        SBOX[p] = (x ^ 0x63) & 0xFF
        if p == 1:
            break
    SBOX[0] = 0x63


_init_sbox()


def xtime(a):
    return ((a << 1) ^ 0x1B) & 0xFF if a & 0x80 else a << 1


def expand_key(key):
    w = [list(key[i:i + 4]) for i in range(0, 32, 4)]
    rcon = 1
    for i in range(8, 60):
        t = list(w[i - 1])
        if i % 8 == 0:
            t = [SBOX[b] for b in t[1:] + t[:1]]
            t[0] ^= rcon
            rcon = xtime(rcon)
        elif i % 8 == 4:
            t = [SBOX[b] for b in t]
        w.append([a ^ b for a, b in zip(w[i - 8], t)])
    return [sum(w[r * 4:r * 4 + 4], []) for r in range(15)]


def encrypt_block(rk, block):
    s = [b ^ k for b, k in zip(block, rk[0])]
    for r in range(1, 15):
        s = [SBOX[b] for b in s]
        s = [s[(i + 4 * (i % 4)) % 16] for i in range(16)]
        if r < 14:
            m = []
            for c in range(0, 16, 4):
                a = s[c:c + 4]
                t = a[0] ^ a[1] ^ a[2] ^ a[3]
                m += [a[i] ^ t ^ xtime(a[i] ^ a[(i + 1) % 4]) for i in range(4)]
            s = m
        s = [b ^ k for b, k in zip(s, rk[r])]
    return bytes(s)


def gmul(x, y):
    z = 0
    for i in range(127, -1, -1):
        if (x >> i) & 1:
            z ^= y
        y = (y >> 1) ^ (0xE1 << 120 if y & 1 else 0)
    return z


def gcm_seal(rk, nonce, plain, ad):
    h = int.from_bytes(encrypt_block(rk, bytes(16)), "big")
    j0 = nonce + b"\x00\x00\x00\x01"
    out = bytearray()
    for i in range(0, len(plain), 16):
        ctr = nonce + (2 + i // 16).to_bytes(4, "big")
        ks = encrypt_block(rk, ctr)
        out += bytes(a ^ b for a, b in zip(plain[i:i + 16], ks))

    def pad(b):
        return b + bytes(-len(b) % 16)

    data = pad(ad) + pad(bytes(out)) + (8 * len(ad)).to_bytes(8, "big") + (8 * len(out)).to_bytes(8, "big")
    y = 0
    for i in range(0, len(data), 16):
        y = gmul(y ^ int.from_bytes(data[i:i + 16], "big"), h)
    tag = bytes(a ^ b for a, b in zip(y.to_bytes(16, "big"), encrypt_block(rk, j0)))
    return bytes(out), tag


def encrypt(secret, plain):
    salt, nonce = os.urandom(32), os.urandom(8)
    rk = expand_key(hashlib.pbkdf2_hmac("sha256", secret, salt, 8192, 32))
    _, tag0 = gcm_seal(rk, nonce + (0).to_bytes(4, "little"), b"", b"")
    out = bytearray(salt + b"\x02" + nonce)
    frag, seq = 1 << 14, 1
    while len(plain) > frag:
        c, t = gcm_seal(rk, nonce + seq.to_bytes(4, "little"), plain[:frag], b"\x00" + tag0)
        out += c + t
        plain, seq = plain[frag:], seq + 1
    c, t = gcm_seal(rk, nonce + seq.to_bytes(4, "little"), plain, b"\x80" + tag0)
    return bytes(out + c + t)


if __name__ == "__main__":
    sys.stdout.buffer.write(encrypt(sys.argv[1].encode(), sys.stdin.buffer.read()))
