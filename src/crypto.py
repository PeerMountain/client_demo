from Crypto.PublicKey import RSA 
from Crypto.Hash import RIPEMD
import base58
import os
import binascii
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from Crypto.Signature import pss
from dataclasses import dataclass


ADDRESS_PREFIX = [1, 0]


@dataclass(frozen=True)
class Address():
    address: str
    def to_struct(self):
        return self.address
    @classmethod
    def from_struct(cls, addr):
        return cls(addr)


class RSAKey():
    """ Peermountain RSAKey (wraps Cryptodome.RSAKey) """
    def __init__(self, key, is_public):
        self.key = key
        self.is_public = is_public

    @classmethod
    def generate(cls, size=4096, randfunc=os.urandom):
        return cls(RSA.generate(size, randfunc=randfunc), False)

    def export(self):
        assert not self.is_public
        return self.key.exportKey('PEM')

    def public_key(self):
        return RSAKey(self.key.publickey(), True)

    def public_key_hex(self):
        return binascii.hexlify(self.key.publickey().exportKey("DER")).decode()

    @classmethod
    def import_public_key_hex(cls, data):
        return cls(RSA.importKey(binascii.unhexlify(data.encode())), True)

    @classmethod
    def import_key(cls, data):
        return cls(RSA.importKey(data), False)

    @classmethod
    def load_or_generate(cls, filename, size=2048, randfunc=os.urandom):
        if os.path.exists(filename):
            with open(filename, "rb") as fin:
                return cls.import_key(fin.read())
        else:
            key = cls.generate(size, randfunc)
            with open(filename, "wb") as fout:
                fout.write(key.export())
            return key

    def address(self):
        """Return the PeerMountain address.
        """
        # The public key of the pair is hashed SHA-256.
        step_1 = SHA256.new(self.key.publickey().exportKey(format="DER")).digest()
        # The resulting Hash is further hashed with RIPEMD-160.
        step_2 = RIPEMD.new(step_1).digest()
        # Two bytes are prefixed to the resulting RIPEMD-160 hash in order to
        # identify the deployment system.
        step_3 = bytes(ADDRESS_PREFIX) + step_2
        # A checksum is calculated by SHA-256 hashing the extended RIPEMD-160 hash, then hashing
        # the resulting hash once more.
        step_4_checksum = SHA256.new(SHA256.new(step_3).digest()).digest()
        # The last 4 bytes of the final hash are added as the
        # trailing 4 bytes of the extended RIPEMD-160 hash. This is the
        # checksum
        step_4 = step_3 + step_4_checksum[-4:]
        # The resulting object is Base58 encoded
        return Address(base58.b58encode(step_4).decode())

    def encrypt(self, data):
        cipher = PKCS1_OAEP.new(self.key)
        return cipher.encrypt(data)
    
    def decrypt(self, data):
        assert not self.is_public
        cipher = PKCS1_OAEP.new(self.key)
        return cipher.decrypt(data)
    
    def sign(self, message, randbytes=os.urandom):
        message_hash = SHA256.new(message)
        return pss.new(self.key, rand_func=randbytes).sign(message_hash)
        
    def verify(self, message, signature):
        message_hash = SHA256.new(message)
        try:
            pss.new(self.key).verify(message_hash, signature)
            return True
        except (ValueError, TypeError):
            return False
    
class AESKey:
    def __init__(self, key):
        self.key = key
        self.nonce_size = 16 # as per cryptodome recommendation

    def decrypt(self, encrypted: bytes) -> bytes:
        assert len(encrypted) >= 32 # at least a nonce(16) and a tag(16)
        nonce, ciphertext, tag = encrypted[:self.nonce_size], encrypted[self.nonce_size:-16], encrypted[-16:]
        cipher = AES.new(self.key, AES.MODE_GCM, nonce)
        return cipher.decrypt_and_verify(ciphertext, tag)

    def encrypt(self, data: bytes, randbytes=os.urandom) -> bytes:
        assert type(data) is bytes
        nonce = randbytes(self.nonce_size)
        cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        return nonce + ciphertext + tag

    @classmethod
    def generate(cls, keysize=256, randbytes=os.urandom):
        assert keysize in {128, 192, 256}
        return cls(randbytes(keysize//8))

    @classmethod
    def generate_with_pdkdf2_sha256(cls, password, salt, keysize=256, count=1000):
        assert len(salt) >= 8
        key = PBKDF2(password, salt, keysize, count=count, hmac_hash_module=SHA256)
        return cls(key)

    @classmethod
    def load_or_generate(cls, filename, size=2048):
        if os.path.exists(filename):
            with open(filename, "rb") as fin:
                key = fin.read()
                assert len(key) == size // 8
                return cls(key)
        else:
            key = cls.generate(size)
            with open(filename, "wb") as fout:
                fout.write(key.key)
            return key

def aes_encrypt_with_new_key(data):
    key = AESKey.generate()
    return key.encrypt(data), key

