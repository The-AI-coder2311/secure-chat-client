import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ---------- Encrypt File ----------
def encrypt_file(path):
    key = AESGCM.generate_key(bit_length=128)
    aes = AESGCM(key)

    with open(path, "rb") as f:
        data = f.read()

    nonce = os.urandom(12)
    ciphertext = aes.encrypt(nonce, data, None)

    out_path = path + ".enc"
    with open(out_path, "wb") as f:
        f.write(nonce + ciphertext)

    return out_path, key.hex()

# ---------- Decrypt File ----------
def decrypt_file(path, key_hex):
    key = bytes.fromhex(key_hex)
    aes = AESGCM(key)

    with open(path, "rb") as f:
        raw = f.read()

    nonce = raw[:12]
    ciphertext = raw[12:]

    data = aes.decrypt(nonce, ciphertext, None)

    out_path = path.replace(".enc", "") + ".dec"
    with open(out_path, "wb") as f:
        f.write(data)

    return out_path
