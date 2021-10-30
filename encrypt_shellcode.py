#!/usr/bin/env python3
import os
import string
import random
from hashlib import md5
from Cryptodome.Cipher import AES

letters = string.ascii_letters
print("[+] ALPHABET:", letters)

random_key = ''.join(random.choice(letters) for _ in range(32))
random_iv = ''.join(random.choice(letters) for _ in range(16))
print("[+] KEY:", random_key)
print("[+] IV:", random_iv)

random_key_digest = md5(random_key.encode('utf-8'))
random_iv_digest = md5(random_iv.encode('utf-8'))
print("[+] KEY DIGEST (md5):", random_key_digest.hexdigest())
print("[+] IV DIGEST (md5):", random_iv_digest.hexdigest())
random_key_digest = random_key_digest.digest()
random_iv_digest = random_iv_digest.digest()

with open("aes.key", "wb") as f:
    f.write(random_key_digest)

with open("aes.iv", "wb") as f:
    f.write(random_iv_digest)

mode = AES.MODE_CFB
encryptor = AES.new(random_key_digest, mode, random_iv_digest, segment_size=128)

with open("shellcode.bin", "rb") as f:
    shellcode = f.read()

cipher = encryptor.encrypt(shellcode)

with open("shellcode.enc", "wb") as f:
    f.write(cipher)

print("[+] DONE!")
