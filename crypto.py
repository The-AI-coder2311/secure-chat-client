import os, hashlib
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ---------- Identity ----------
def gen_identity():
    priv = ed25519.Ed25519PrivateKey.generate()
    return priv, priv.public_key()

def fingerprint(pub):
    return hashlib.sha256(pub.public_bytes_raw()).hexdigest()

# ---------- Diffie-Hellman ----------
def gen_dh():
    priv = x25519.X25519PrivateKey.generate()
    return priv, priv.public_key()

def kdf(shared_secret):
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"secure-chat-client"
    ).derive(shared_secret)

# ---------- Session Key ----------
def make_shared(priv, peer_pub_bytes):
    peer_pub = x25519.X25519PublicKey.from_public_bytes(peer_pub_bytes)
    return kdf(priv.exchange(peer_pub))

# ---------- Ratchet ----------
class Ratchet:
    def __init__(self, root_key):
        self.chain = root_key

    def next_key(self):
        self.chain = kdf(self.chain)
        return self.chain

    def encrypt(self, message: str):
        key = self.next_key()
        aes = AESGCM(key)

        nonce = os.urandom(12)
        ciphertext = aes.encrypt(nonce, message.encode(), None)

        return nonce.hex(), ciphertext.hex()

    def decrypt(self, nonce_hex: str, ciphertext_hex: str):
        key = self.next_key()
        aes = AESGCM(key)

        nonce = bytes.fromhex(nonce_hex)
        ciphertext = bytes.fromhex(ciphertext_hex)

        return aes.decrypt(nonce, ciphertext, None).decode()
