"""
    Requires Python 3.7
        Under windows, install lxml from the unoffical python repo at https://www.lfd.uci.edu/~gohlke/pythonlibs/
        then dependencies:
            pip install pycryptodome
            pip install base58
            pip install msgpack
"""
from typing import Dict
import os
from forms import XForm, BooleanField, FileField, get_metadata_dict
import datetime
import hashlib
from model import Address, GetMessageAndBodyType, Message, MessageEnveloppe,\
    Attestation, ServiceRegistration, ServiceDocument, ServiceAttestation,\
    DestinationType, InviteRegistration, Invitation, RegistrationRequest,\
    Assertion, BodyType, MessageType, Attachement, MessageAnalysis,\
    ResearchAnalysis
from crypto import RSAKey, AESKey
from serialization import MsgpackSerialize
from utils import merge_dicts, read_file_contents
from Crypto.Hash import SHA256
from binascii import hexlify, unhexlify
import unittest

example_key1 = RSAKey.import_key('''-----BEGIN RSA PRIVATE KEY-----
MIICXgIBAAKBgQC6nQgY33OBvHMEWMqkYz4VG4kgJ/Ag9WOjYqBAmZSy+TBthL7T
GIWGRUhVxqg3ADoIhyjaNJoYtXHoUUTFkXSrkXjX/ubnsW9WdKe2EEFTLuyW4vwI
ZxnVwo/Jne/xGADwmVBU6YIQgkRkUdSpxSBKAoxRLJyjNaNaBKtzWtlcUQIDAQAB
AoGALMji2JVHsyr2r2RfvXPTwl0JW546Eq7RarSQoPA6r3j+Fkp1QVPxN3gJFAzI
8eosAz/snfFhyexBme9nAcMWrGzmf0Wp3a+6nkkp2QklhcPZyZYhUGp++hziQvAM
UtwZzM4fshcaqDXIMDxi9Eykrm7uBpY8jrvos95nNyf4GsECQQDMQE1L4RXtjNC8
7qhRfqTq9qesZTW+OxBU3pyu/rv/ZBq6yijJWvIWr2vl2O/bpFGqQJNDlPbVV4Iu
0OYqXWRbAkEA6eS/G5DVQUaPCBAAJ3nHX9VsODwWcF4LjQCb1nldEJgAtfRUYZKv
u0Qj1rTg+5Fnv749c0QC9eu/wqmALmmxwwJBAMtnSdLD7+NmdUWBYivuM+wuAGLl
U7UC+suZ+W0oDy5RkXDs+9sx7555ybjW5l7Ub+NddYo64ekpwWI/9MbBxLsCQQCJ
ynHvum536yp+VHbSysJzKdd8daG+hxkE83PbcVorWXEpwIwpg3I1v5nhdmQIsIvP
gTLQgiPAXyd0dckHDstjAkEAs3gy8xlCyT5V+gnu+ZjGpJKPvhWyFYrdZ78xagkF
XoRbLXdRThjmEaVEb0zxmsiqnEcUCX5eGZB/gYAcZCAbwQ==
-----END RSA PRIVATE KEY-----''')

class MessageSerializationTests(unittest.TestCase):
    def test_invite_registration(self):
        # Setup the random number generator to return only zeros (Only for testing: use os.urandom in prod!)
        def randbytes(l):
            return (b"\00" * l)
        
        # Example Message
        message = InviteRegistration(boostrapNode="http://api.bitstamp.com/teleferic",
                                     boostrapAddr=Address('2nPfgysH5URwM6mcknqwNEgbCi9C36oQsdZ'),
                                     offeringAddr=Address('2n9hLLzhpn4ueRHYoJBtcR7JkmtcV4omzLK'),
                                     serviceAnnouncementMessage = unhexlify('0f2e63df2c59f0b4108d4ae187be24718d9bcaa64903f883d38b9a81d1cca664'),
                                     serviceOfferingID=1,
                                     inviteName=unhexlify('29c88d786ed68ce6fcb62aa63bf9ab61081d72dc7603a3d323a23268ffaa8b66746cf6168fe66480cd433f478e'))
        # 1/Pack the message as structure. The fieldnames must be sorted alphabetically.
        # Note: some fields are strings, and some are binary (this is important later for msgpack)
        json_message = MsgpackSerialize.to_struct(message)
        self.assertEqual(json_message, [('boostrapAddr', '2nPfgysH5URwM6mcknqwNEgbCi9C36oQsdZ'), ('boostrapNode', 'http://api.bitstamp.com/teleferic'), ('inviteName', b')\xc8\x8dxn\xd6\x8c\xe6\xfc\xb6*\xa6;\xf9\xaba\x08\x1dr\xdcv\x03\xa3\xd3#\xa22h\xff\xaa\x8bftl\xf6\x16\x8f\xe6d\x80\xcdC?G\x8e'), ('offeringAddr', '2n9hLLzhpn4ueRHYoJBtcR7JkmtcV4omzLK'), ('serviceAnnouncementMessage', b'\x0f.c\xdf,Y\xf0\xb4\x10\x8dJ\xe1\x87\xbe$q\x8d\x9b\xca\xa6I\x03\xf8\x83\xd3\x8b\x9a\x81\xd1\xcc\xa6d'), ('serviceOfferingID', 1)])
        # 2/  When packed with msgpack we get (in hex):
        serialized_message = MsgpackSerialize.pack(message)
        self.assertEqual(serialized_message,  unhexlify(b'9692ac626f6f737472617041646472d923326e506667797348355552774d366d636b6e71774e4567624369394333366f5173645a92ac626f6f73747261704e6f6465d921687474703a2f2f6170692e6269747374616d702e636f6d2f74656c65666572696392aa696e766974654e616d65c42d29c88d786ed68ce6fcb62aa63bf9ab61081d72dc7603a3d323a23268ffaa8b66746cf6168fe66480cd433f478e92ac6f66666572696e6741646472d923326e39684c4c7a68706e3475655248596f4a42746352374a6b6d746356346f6d7a4c4b92ba73657276696365416e6e6f756e63656d656e744d657373616765c4200f2e63df2c59f0b4108d4ae187be24718d9bcaa64903f883d38b9a81d1cca66492b1736572766963654f66666572696e67494401'))
        # 3/ Sign using RSASSA-PSS as introduced in PKCS1v2.1 (still compatible with in PKCS1 v2.2)
        # This example is deterministic because our randbytes function returns only zeros:
        signature = example_key1.sign(serialized_message, randbytes=randbytes)
        self.assertEqual(signature, unhexlify('a35d156244aaa18e8e151ee90ab3027769804bdf7554c79e7dde985e4ee46f1b6477cc7d858de3bfd1ebd37ddd120b610493596604b357fb024e046be6eb4bbf069fc71cc5037b14441a7e6f1acc4d921938c5090adb2133a45cd414f090c81cea117057aef8ed689c68bccc6994a47318eaad062c7ee41ef6bfdd5fa5133747'))
        # 4/ Encrypt the message using AES 256 GCM. We prepend a 16 byte nonce as per pycryptodome recommendation)
        key = AESKey(unhexlify(b'2ecdf1b6fbc85c51b052ea665a0e946400681d5a7baa69378f9a6275dd236b59'))
        encrypted_message = key.encrypt(serialized_message, randbytes=randbytes)
        self.assertEqual(encrypted_message, unhexlify('000000000000000000000000000000009430a343dc2323e7e63c83c99505e74585cb85719a5d4b8fbd89a68802c497c870a6de5f734908844be8037495d853c2c221d1c8396bcccb2941b5683d0667610b0c19ecf33dd715477dc04edd6a7d80898a93e80ff9476c3366615a238f41b4681539b3fe8883c86ce379bae0eabf50319c6209c5dc52e93022a68fa9ebb610390a23bdcb9d3fc58f0f25919f2c272558b335b10d1ba36593c5e6253146c91ea9fcc8fa97fd0b9dfc909c4aa9e40b98047c6888367e84b28bbc9db1563220b88bd5a7698578bc8efb6a08c475cfd6822c83446c011bf5c2d401309088729cffc4ae82160a030df986bdeee821a99506ceedd9a5d61a232011427915698a210d77ec6ef06ae64e773810b8e3e77c28c41dee7c33e37b2a72efa8f007ef7e6adfb2223d0052003c6549315be43720b8ce0b0f110193'))
        # 4/ Hash of the message
        messageHash = hashlib.sha256(encrypted_message).digest()
        self.assertEqual(messageHash, unhexlify('5d70fb71241e9d65104166ca520e047206ad1303dfa62742a246eadfcf9d7c4b'))
       
        

if __name__ == '__main__':
    unittest.main()
