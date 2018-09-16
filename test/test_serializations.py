""" These tests require "parameterized". Please have a look at https://github.com/wolever/parameterized

    And install the following dependencies:
        pip install pycryptodome
        pip install base58
        pip install msgpack
        pip install parameterized
"""
from typing import Dict
import os
from forms import XForm, BooleanField, FileField, get_metadata_dict
import datetime
import hashlib
from model import Address, Message, MessageEnveloppe,\
    Attestation, ServiceRegistration, ServiceDocument, ServiceAttestation,\
    DestinationType, InviteRegistration, Invitation, RegistrationRequest,\
    Assertion, BodyType, Attachement, MessageAnalysis,\
    ResearchAnalysis
from crypto import RSAKey, AESKey
from serialization import MsgpackSerialize
from utils import merge_dicts, read_file_contents
from Crypto.Hash import SHA256
from binascii import hexlify, unhexlify
import unittest
from parameterized import parameterized

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

# Setup the random number generator to return only zeros (Only for testing: use os.urandom in prod!)
def randbytes_zeros(l):
    return (b"\00" * l)

class MessageBodySerializationTests(unittest.TestCase):
    # Input test_Serialization_SerializeMessageBody_ResultIsCorrect 
    @parameterized.expand([
        # ------------- InviteRegistration -------------
        (InviteRegistration(boostrapNode="http://api.bitstamp.com/teleferic",
                            boostrapAddr=Address('2nPfgysH5URwM6mcknqwNEgbCi9C36oQsdZ'),
                            offeringAddr=Address('2n9hLLzhpn4ueRHYoJBtcR7JkmtcV4omzLK'),
                            serviceAnnouncementMessage = unhexlify('0f2e63df2c59f0b4108d4ae187be24718d9bcaa64903f883d38b9a81d1cca664'),
                            serviceOfferingID=1,
                            inviteName=unhexlify('29c88d786ed68ce6fcb62aa63bf9ab61081d72dc7603a3d323a23268ffaa8b66746cf6168fe66480cd433f478e')),
         [('boostrapAddr', '2nPfgysH5URwM6mcknqwNEgbCi9C36oQsdZ'), ('boostrapNode', 'http://api.bitstamp.com/teleferic'), ('inviteName', b')\xc8\x8dxn\xd6\x8c\xe6\xfc\xb6*\xa6;\xf9\xaba\x08\x1dr\xdcv\x03\xa3\xd3#\xa22h\xff\xaa\x8bftl\xf6\x16\x8f\xe6d\x80\xcdC?G\x8e'), ('offeringAddr', '2n9hLLzhpn4ueRHYoJBtcR7JkmtcV4omzLK'), ('serviceAnnouncementMessage', b'\x0f.c\xdf,Y\xf0\xb4\x10\x8dJ\xe1\x87\xbe$q\x8d\x9b\xca\xa6I\x03\xf8\x83\xd3\x8b\x9a\x81\xd1\xcc\xa6d'), ('serviceOfferingID', 1)],
         '9692ac626f6f737472617041646472d923326e506667797348355552774d366d636b6e71774e4567624369394333366f5173645a92ac626f6f73747261704e6f6465d921687474703a2f2f6170692e6269747374616d702e636f6d2f74656c65666572696392aa696e766974654e616d65c42d29c88d786ed68ce6fcb62aa63bf9ab61081d72dc7603a3d323a23268ffaa8b66746cf6168fe66480cd433f478e92ac6f66666572696e6741646472d923326e39684c4c7a68706e3475655248596f4a42746352374a6b6d746356346f6d7a4c4b92ba73657276696365416e6e6f756e63656d656e744d657373616765c4200f2e63df2c59f0b4108d4ae187be24718d9bcaa64903f883d38b9a81d1cca66492b1736572766963654f66666572696e67494401'
         ),
        
        # ------------- ServiceRegistration -------------
        (ServiceRegistration(
         "exchange",
         Address('2n9hLLzhpn4ueRHYoJBtcR7JkmtcV4omzLK'),
         datetime.date(2018, 1, 1),
         None,
         "Bitstamp",
         "Cryptocurrency Exchange",
         b"", #images
         [ServiceDocument(XForm(["IdentityDocument"]),
                         [ServiceAttestation(Address('2n6HW4uS6Wqq8e4vgkQHnniCu3yrhvjHHHF'),
                                             ["MRZ", "Fraud", "PEP", "Sanction", "SanctionCountry", "CountryRisk", "BlackList"],
                                             DestinationType.SendServiceProvider,
                                             0)]),
                    
          ServiceDocument(XForm(["Name", "Surname", "AddressLine1", "AddressLine2", "PostalCode",
                                 "City", "Country", "Email", "PhoneNumber"]),
                          [ServiceAttestation(Address('2n6HW4uS6Wqq8e4vgkQHnniCu3yrhvjHHHF'), ["AddressValidity", "KnownCustomer", "ResidenceClassifier"]), ]),
          ServiceDocument(XForm(["TermsAndConditions"]),
                          []),
         ]),
        [('documents', [[('requiredAttestations', [[('aePMAddress', '2n6HW4uS6Wqq8e4vgkQHnniCu3yrhvjHHHF'), ('attestation_list', ['MRZ', 'Fraud', 'PEP', 'Sanction', 'SanctionCountry', 'CountryRisk', 'BlackList']), ('destinationPMAddress', 'SendServiceProvider'), ('updateFrequencyInDays', 0)]]), ('xform', [('fields_init', ['IdentityDocument'])])], [('requiredAttestations', [[('aePMAddress', '2n6HW4uS6Wqq8e4vgkQHnniCu3yrhvjHHHF'), ('attestation_list', ['AddressValidity', 'KnownCustomer', 'ResidenceClassifier']), ('destinationPMAddress', 'SendServiceProvider'), ('updateFrequencyInDays', None)]]), ('xform', [('fields_init', ['Name', 'Surname', 'AddressLine1', 'AddressLine2', 'PostalCode', 'City', 'Country', 'Email', 'PhoneNumber'])])], [('requiredAttestations', []), ('xform', [('fields_init', [[('description', None), ('name', 'TermsAndConditions')]])])]]), ('serviceEndDate', None), ('serviceId', 'exchange'), ('serviceMarketing_description', 'Cryptocurrency Exchange'), ('serviceMarketing_image', b''), ('serviceMarketing_name', 'Bitstamp'), ('servicePMAddress', '2n9hLLzhpn4ueRHYoJBtcR7JkmtcV4omzLK'), ('serviceStartDate', '2018-01-01')],
        '9892a9646f63756d656e7473939292b472657175697265644174746573746174696f6e73919492ab6165504d41646472657373d923326e3648573475533657717138653476676b51486e6e69437533797268766a4848484692b06174746573746174696f6e5f6c69737497a34d525aa54672617564a3504550a853616e6374696f6eaf53616e6374696f6e436f756e747279ab436f756e7472795269736ba9426c61636b4c69737492b464657374696e6174696f6e504d41646472657373b353656e645365727669636550726f766964657292b57570646174654672657175656e6379496e446179730092a578666f726d9192ab6669656c64735f696e697491b04964656e74697479446f63756d656e749292b472657175697265644174746573746174696f6e73919492ab6165504d41646472657373d923326e3648573475533657717138653476676b51486e6e69437533797268766a4848484692b06174746573746174696f6e5f6c69737493af4164647265737356616c6964697479ad4b6e6f776e437573746f6d6572b35265736964656e6365436c617373696669657292b464657374696e6174696f6e504d41646472657373b353656e645365727669636550726f766964657292b57570646174654672657175656e6379496e44617973c092a578666f726d9192ab6669656c64735f696e697499a44e616d65a75375726e616d65ac416464726573734c696e6531ac416464726573734c696e6532aa506f7374616c436f6465a443697479a7436f756e747279a5456d61696cab50686f6e654e756d6265729292b472657175697265644174746573746174696f6e739092a578666f726d9192ab6669656c64735f696e6974919292ab6465736372697074696f6ec092a46e616d65b25465726d73416e64436f6e646974696f6e7392ae73657276696365456e6444617465c092a9736572766963654964a865786368616e676592bc736572766963654d61726b6574696e675f6465736372697074696f6eb743727970746f63757272656e63792045786368616e676592b6736572766963654d61726b6574696e675f696d616765c40092b5736572766963654d61726b6574696e675f6e616d65a84269747374616d7092b073657276696365504d41646472657373d923326e39684c4c7a68706e3475655248596f4a42746352374a6b6d746356346f6d7a4c4b92b073657276696365537461727444617465aa323031382d30312d3031'
        ),
        # ------------- Invitation -------------
        (Invitation(boostrapNode='http://api.bitstamp.com/teleferic',
                    boostrapAddr=Address(address='2nPfgysH5URwM6mcknqwNEgbCi9C36oQsdZ'),
                    offeringAddr=Address(address='2n9hLLzhpn4ueRHYoJBtcR7JkmtcV4omzLK'),
                    serviceAnnouncementMessage=b'e\x7f{3\xbc\xee\x00H\xe71\x0e\xd2\x03\xbd\xf4N\x83\xadC2\xd1\x03\x92`-\xbfj\xfc\xe8>\xe8\xbe',
                    serviceOfferingID=1,
                    inviteName=b')\xc8\x8dxn\xd6\x8c\xe6\xfc\xb6*\xa6;\xf9\xaba\x08\x1dr\xdcv\x03\xa3\xd3#\xa22h\xff\xaa\x8bftl\xf6\x16\x8f\xe6d\x80\xcdC?G\x8e',
                    inviteMsgID=b"~\xd4\x90\x9dg\xfd\xa3?\xf6\xe4\xa1n\xbf\xd7:\x0c\xd1\x97J8%'_\x87\xdc\x18\xbf\t\xb6?\x1b<",
                    inviteKey=b'qzH\xe5.)\xa3\xfa7\x9a\x95?\xaah\x93\xe3.\xc5\xa2{\x94^`_\x10\x85\xf3#-BL\x13'),
        [('boostrapAddr', '2nPfgysH5URwM6mcknqwNEgbCi9C36oQsdZ'), ('boostrapNode', 'http://api.bitstamp.com/teleferic'), ('inviteKey', b'qzH\xe5.)\xa3\xfa7\x9a\x95?\xaah\x93\xe3.\xc5\xa2{\x94^`_\x10\x85\xf3#-BL\x13'), ('inviteMsgID', b"~\xd4\x90\x9dg\xfd\xa3?\xf6\xe4\xa1n\xbf\xd7:\x0c\xd1\x97J8%'_\x87\xdc\x18\xbf\t\xb6?\x1b<"), ('inviteName', b')\xc8\x8dxn\xd6\x8c\xe6\xfc\xb6*\xa6;\xf9\xaba\x08\x1dr\xdcv\x03\xa3\xd3#\xa22h\xff\xaa\x8bftl\xf6\x16\x8f\xe6d\x80\xcdC?G\x8e'), ('offeringAddr', '2n9hLLzhpn4ueRHYoJBtcR7JkmtcV4omzLK'), ('serviceAnnouncementMessage', b'e\x7f{3\xbc\xee\x00H\xe71\x0e\xd2\x03\xbd\xf4N\x83\xadC2\xd1\x03\x92`-\xbfj\xfc\xe8>\xe8\xbe'), ('serviceOfferingID', 1)],
        '9892ac626f6f737472617041646472d923326e506667797348355552774d366d636b6e71774e4567624369394333366f5173645a92ac626f6f73747261704e6f6465d921687474703a2f2f6170692e6269747374616d702e636f6d2f74656c65666572696392a9696e766974654b6579c420717a48e52e29a3fa379a953faa6893e32ec5a27b945e605f1085f3232d424c1392ab696e766974654d73674944c4207ed4909d67fda33ff6e4a16ebfd73a0cd1974a3825275f87dc18bf09b63f1b3c92aa696e766974654e616d65c42d29c88d786ed68ce6fcb62aa63bf9ab61081d72dc7603a3d323a23268ffaa8b66746cf6168fe66480cd433f478e92ac6f66666572696e6741646472d923326e39684c4c7a68706e3475655248596f4a42746352374a6b6d746356346f6d7a4c4b92ba73657276696365416e6e6f756e63656d656e744d657373616765c420657f7b33bcee0048e7310ed203bdf44e83ad4332d10392602dbf6afce83ee8be92b1736572766963654f66666572696e67494401'
        ),
        # ------------- RegistrationRequest -------------
        (RegistrationRequest(inviteMsgID=b'$<4px\x17\xeb\x89\xea7\xcc\xfd\x0f\xae\x07"\x89\'n\x10l\xb0T\xfb\x95\x161\x94\xe1\xad\xe7\xd3',
                             keyProof=b'\x15\x1a\xac(\r\xfd\xdf\x08\xbf\xbeE\xd2\x03\x12\xed\x8e\xffXk\xf6X\xdcl7\xb2\xda\xe0J\x0b%;<\x94f\xc5\xa4\x85\x85\xfb\xc8\x9e2\xaa\x07\xb49\xbcs\xc7\xa9\x0f\xf5\x10\xb5#\xe9;\x92l\x04?\xcf\x7f\xa3\xf1\xe8<\xd6L\xbe\x8c\xd9\x99\x1d\x0e`\xad\x06\xf3\x0fM\rz\xc6\xd6\xcb\x83\x0bp\xd6\xe5i&\x15\x03\xec\x9aO\x14\xb3\r\x9ary\x8a&\xe0Sx\xba\xb2>m\xc2e\x11|\xecyr\xfa\x84\x9d\xfdv\x86\xa0\xf5', 
                             inviteName='AccountLevel1', 
                             publicKey='30819f300d06092a864886f70d010101050003818d0030818902818100ba9d0818df7381bc730458caa4633e151b892027f020f563a362a0409994b2f9306d84bed3188586454855c6a837003a088728da349a18b571e85144c59174ab9178d7fee6e7b16f5674a7b61041532eec96e2fc086719d5c28fc99deff11800f0995054e9821082446451d4a9c5204a028c512c9ca335a35a04ab735ad95c510203010001', 
                             publicNickname='nickname1'),
         [('inviteMsgID', b'$<4px\x17\xeb\x89\xea7\xcc\xfd\x0f\xae\x07"\x89\'n\x10l\xb0T\xfb\x95\x161\x94\xe1\xad\xe7\xd3'), ('inviteName', 'AccountLevel1'), ('keyProof', b'\x15\x1a\xac(\r\xfd\xdf\x08\xbf\xbeE\xd2\x03\x12\xed\x8e\xffXk\xf6X\xdcl7\xb2\xda\xe0J\x0b%;<\x94f\xc5\xa4\x85\x85\xfb\xc8\x9e2\xaa\x07\xb49\xbcs\xc7\xa9\x0f\xf5\x10\xb5#\xe9;\x92l\x04?\xcf\x7f\xa3\xf1\xe8<\xd6L\xbe\x8c\xd9\x99\x1d\x0e`\xad\x06\xf3\x0fM\rz\xc6\xd6\xcb\x83\x0bp\xd6\xe5i&\x15\x03\xec\x9aO\x14\xb3\r\x9ary\x8a&\xe0Sx\xba\xb2>m\xc2e\x11|\xecyr\xfa\x84\x9d\xfdv\x86\xa0\xf5'), ('publicKey', '30819f300d06092a864886f70d010101050003818d0030818902818100ba9d0818df7381bc730458caa4633e151b892027f020f563a362a0409994b2f9306d84bed3188586454855c6a837003a088728da349a18b571e85144c59174ab9178d7fee6e7b16f5674a7b61041532eec96e2fc086719d5c28fc99deff11800f0995054e9821082446451d4a9c5204a028c512c9ca335a35a04ab735ad95c510203010001'), ('publicNickname', 'nickname1')],
         '9592ab696e766974654d73674944c420243c34707817eb89ea37ccfd0fae072289276e106cb054fb95163194e1ade7d392aa696e766974654e616d65ad4163636f756e744c6576656c3192a86b657950726f6f66c480151aac280dfddf08bfbe45d20312ed8eff586bf658dc6c37b2dae04a0b253b3c9466c5a48585fbc89e32aa07b439bc73c7a90ff510b523e93b926c043fcf7fa3f1e83cd64cbe8cd9991d0e60ad06f30f4d0d7ac6d6cb830b70d6e569261503ec9a4f14b30d9a72798a26e05378bab23e6dc265117cec7972fa849dfd7686a0f592a97075626c69634b6579da014433303831396633303064303630393261383634383836663730643031303130313035303030333831386430303330383138393032383138313030626139643038313864663733383162633733303435386361613436333365313531623839323032376630323066353633613336326130343039393934623266393330366438346265643331383835383634353438353563366138333730303361303838373238646133343961313862353731653835313434633539313734616239313738643766656536653762313666353637346137623631303431353332656563393665326663303836373139643563323866633939646566663131383030663039393530353465393832313038323434363435316434613963353230346130323863353132633963613333356133356130346162373335616439356335313032303330313030303192ae7075626c69634e69636b6e616d65a96e69636b6e616d6531'
        ),
        # ------------- Assertion -------------
        (Assertion(subjectAddr=Address(address='2n4gSd2aVC6Dep5ECS4NRCw3AG2p73r7DcM'), 
                   validUntil=datetime.date(2020, 1, 1), 
                   retainUntil=datetime.date(2020, 1, 1), 
                   containerKey=b'$\xcd\xf1\x11\xd7%hh<sV\xc7\x18\x95f9\xaeG\x92\x00\xcc\xab%\xbbO\xb2\xcc.\xe9\xf8Wt', 
                   Meta={'Name': Assertion.Metadata(MetaSalt=b'\xdf\\\x1f\xef\x143\xc8f\x85\xb7\xf0Vh\x1dQR\xaf\x80<\xe2Y\x06\xf1\xd1\x9f\xb6\xc6\x80N\x06\xea(\xab\x17\x8fEz\xf6\xb4\x93', MetaValue='John'), 
                         'Surname': Assertion.Metadata(MetaSalt=b'\xb7C\x9e\xc6\xd4)\x00b\xabQzr\xe5\xc1\xd4\x10\xcd\xd6\x17T\xe4 \x84P\xe4\xf9\x00\x13\xfd\xa6\x9f\xef\x19\xd4`*B\x07\xcd\xd5', MetaValue='Doe')}),
        [('Meta', [('Name', [('MetaSalt', b'\xdf\\\x1f\xef\x143\xc8f\x85\xb7\xf0Vh\x1dQR\xaf\x80<\xe2Y\x06\xf1\xd1\x9f\xb6\xc6\x80N\x06\xea(\xab\x17\x8fEz\xf6\xb4\x93'), ('MetaValue', 'John')]), ('Surname', [('MetaSalt', b'\xb7C\x9e\xc6\xd4)\x00b\xabQzr\xe5\xc1\xd4\x10\xcd\xd6\x17T\xe4 \x84P\xe4\xf9\x00\x13\xfd\xa6\x9f\xef\x19\xd4`*B\x07\xcd\xd5'), ('MetaValue', 'Doe')])]), ('containerKey', b'$\xcd\xf1\x11\xd7%hh<sV\xc7\x18\x95f9\xaeG\x92\x00\xcc\xab%\xbbO\xb2\xcc.\xe9\xf8Wt'), ('retainUntil', '2020-01-01'), ('subjectAddr', '2n4gSd2aVC6Dep5ECS4NRCw3AG2p73r7DcM'), ('validUntil', '2020-01-01')],
        '9592a44d6574619292a44e616d659292a84d65746153616c74c428df5c1fef1433c86685b7f056681d5152af803ce25906f1d19fb6c6804e06ea28ab178f457af6b49392a94d65746156616c7565a44a6f686e92a75375726e616d659292a84d65746153616c74c428b7439ec6d4290062ab517a72e5c1d410cdd61754e4208450e4f90013fda69fef19d4602a4207cdd592a94d65746156616c7565a3446f6592ac636f6e7461696e65724b6579c42024cdf111d72568683c7356c718956639ae479200ccab25bb4fb2cc2ee9f8577492ab72657461696e556e74696caa323032302d30312d303192ab7375626a65637441646472d923326e34675364326156433644657035454353344e52437733414732703733723744634d92aa76616c6964556e74696caa323032302d30312d3031'       
        )
        
    ])
    def test_Serialization_SerializeMessageBody_ResultIsCorrect(self, messageBody, result_json, result_hex):
        ''' 'These results are verified manually as best as possible, and then ported to different languagues or platforms '''
        # 1/Pack the message as structure. The fieldnames must be sorted alphabetically.
        # Note: some fields are strings, and some are binary (this is important later for msgpack)
        json_body = MsgpackSerialize.to_struct(messageBody)
        #print (json_message)
        #print (hexlify(MsgpackSerialize.pack(messageBody)))
        self.assertEqual(json_body, result_json)
        # 2/  When packed with msgpack we get (in hex):
        serialized_body = MsgpackSerialize.pack(messageBody)
        self.assertEqual(serialized_body,  unhexlify(result_hex))


class MessageSerializationTests(unittest.TestCase):
    @parameterized.expand([
        (Message(serviceID=1,
                 consumerID=2,
                 dossierSalt="",
                 bodyType=BodyType.RegistrationRequest,
                 body=RegistrationRequest(inviteMsgID=b'$<4px\x17\xeb\x89\xea7\xcc\xfd\x0f\xae\x07"\x89\'n\x10l\xb0T\xfb\x95\x161\x94\xe1\xad\xe7\xd3',
                                          keyProof=b'\x15\x1a\xac(\r\xfd\xdf\x08\xbf\xbeE\xd2\x03\x12\xed\x8e\xffXk\xf6X\xdcl7\xb2\xda\xe0J\x0b%;<\x94f\xc5\xa4\x85\x85\xfb\xc8\x9e2\xaa\x07\xb49\xbcs\xc7\xa9\x0f\xf5\x10\xb5#\xe9;\x92l\x04?\xcf\x7f\xa3\xf1\xe8<\xd6L\xbe\x8c\xd9\x99\x1d\x0e`\xad\x06\xf3\x0fM\rz\xc6\xd6\xcb\x83\x0bp\xd6\xe5i&\x15\x03\xec\x9aO\x14\xb3\r\x9ary\x8a&\xe0Sx\xba\xb2>m\xc2e\x11|\xecyr\xfa\x84\x9d\xfdv\x86\xa0\xf5', 
                                          inviteName='AccountLevel1', 
                                          publicKey='30819f300d06092a864886f70d010101050003818d0030818902818100ba9d0818df7381bc730458caa4633e151b892027f020f563a362a0409994b2f9306d84bed3188586454855c6a837003a088728da349a18b571e85144c59174ab9178d7fee6e7b16f5674a7b61041532eec96e2fc086719d5c28fc99deff11800f0995054e9821082446451d4a9c5204a028c512c9ca335a35a04ab735ad95c510203010001', 
                                          publicNickname='nickname1')),
            [('body', [('inviteMsgID', b'$<4px\x17\xeb\x89\xea7\xcc\xfd\x0f\xae\x07"\x89\'n\x10l\xb0T\xfb\x95\x161\x94\xe1\xad\xe7\xd3'), ('inviteName', 'AccountLevel1'), ('keyProof', b'\x15\x1a\xac(\r\xfd\xdf\x08\xbf\xbeE\xd2\x03\x12\xed\x8e\xffXk\xf6X\xdcl7\xb2\xda\xe0J\x0b%;<\x94f\xc5\xa4\x85\x85\xfb\xc8\x9e2\xaa\x07\xb49\xbcs\xc7\xa9\x0f\xf5\x10\xb5#\xe9;\x92l\x04?\xcf\x7f\xa3\xf1\xe8<\xd6L\xbe\x8c\xd9\x99\x1d\x0e`\xad\x06\xf3\x0fM\rz\xc6\xd6\xcb\x83\x0bp\xd6\xe5i&\x15\x03\xec\x9aO\x14\xb3\r\x9ary\x8a&\xe0Sx\xba\xb2>m\xc2e\x11|\xecyr\xfa\x84\x9d\xfdv\x86\xa0\xf5'), ('publicKey', '30819f300d06092a864886f70d010101050003818d0030818902818100ba9d0818df7381bc730458caa4633e151b892027f020f563a362a0409994b2f9306d84bed3188586454855c6a837003a088728da349a18b571e85144c59174ab9178d7fee6e7b16f5674a7b61041532eec96e2fc086719d5c28fc99deff11800f0995054e9821082446451d4a9c5204a028c512c9ca335a35a04ab735ad95c510203010001'), ('publicNickname', 'nickname1')]), ('bodyType', 'RegistrationRequest'), ('consumerID', 2), ('dossierSalt', ''), ('serviceID', 1)],
            '9592a4626f64799592ab696e766974654d73674944c420243c34707817eb89ea37ccfd0fae072289276e106cb054fb95163194e1ade7d392aa696e766974654e616d65ad4163636f756e744c6576656c3192a86b657950726f6f66c480151aac280dfddf08bfbe45d20312ed8eff586bf658dc6c37b2dae04a0b253b3c9466c5a48585fbc89e32aa07b439bc73c7a90ff510b523e93b926c043fcf7fa3f1e83cd64cbe8cd9991d0e60ad06f30f4d0d7ac6d6cb830b70d6e569261503ec9a4f14b30d9a72798a26e05378bab23e6dc265117cec7972fa849dfd7686a0f592a97075626c69634b6579da014433303831396633303064303630393261383634383836663730643031303130313035303030333831386430303330383138393032383138313030626139643038313864663733383162633733303435386361613436333365313531623839323032376630323066353633613336326130343039393934623266393330366438346265643331383835383634353438353563366138333730303361303838373238646133343961313862353731653835313434633539313734616239313738643766656536653762313666353637346137623631303431353332656563393665326663303836373139643563323866633939646566663131383030663039393530353465393832313038323434363435316434613963353230346130323863353132633963613333356133356130346162373335616439356335313032303330313030303192ae7075626c69634e69636b6e616d65a96e69636b6e616d653192a8626f647954797065b3526567697374726174696f6e5265717565737492aa636f6e73756d657249440292ab646f737369657253616c74a092a973657276696365494401'
        )])
    def test_Serialization_SerializeMessage_ResultIsCorrect(self, message, expected_json, expected_hex):
        ''' 'These results are verified manually as best as possible, and then ported to different languagues or platforms '''
        json_message = MsgpackSerialize.to_struct(message)
        #print (json_message)
        #print (hexlify(MsgpackSerialize.pack(message)))
        self.assertEqual(json_message, expected_json)
        # 2/  When packed with msgpack we get (in hex):
        serialized_message = MsgpackSerialize.pack(message)
        self.assertEqual(serialized_message,  unhexlify(expected_hex))


class MessageSignatureTests(unittest.TestCase):

    @parameterized.expand([
        ('9592a4626f64799592ab696e766974654d73674944c420243c34707817eb89ea37ccfd0fae072289276e106cb054fb95163194e1ade7d392aa696e766974654e616d65ad4163636f756e744c6576656c3192a86b657950726f6f66c480151aac280dfddf08bfbe45d20312ed8eff586bf658dc6c37b2dae04a0b253b3c9466c5a48585fbc89e32aa07b439bc73c7a90ff510b523e93b926c043fcf7fa3f1e83cd64cbe8cd9991d0e60ad06f30f4d0d7ac6d6cb830b70d6e569261503ec9a4f14b30d9a72798a26e05378bab23e6dc265117cec7972fa849dfd7686a0f592a97075626c69634b6579da014433303831396633303064303630393261383634383836663730643031303130313035303030333831386430303330383138393032383138313030626139643038313864663733383162633733303435386361613436333365313531623839323032376630323066353633613336326130343039393934623266393330366438346265643331383835383634353438353563366138333730303361303838373238646133343961313862353731653835313434633539313734616239313738643766656536653762313666353637346137623631303431353332656563393665326663303836373139643563323866633939646566663131383030663039393530353465393832313038323434363435316434613963353230346130323863353132633963613333356133356130346162373335616439356335313032303330313030303192ae7075626c69634e69636b6e616d65a96e69636b6e616d653192a8626f647954797065b3526567697374726174696f6e5265717565737492aa636f6e73756d657249440292ab646f737369657253616c74a092a973657276696365494401',
         '91bd0b69a5b849c3e0fdc344c0cb8a15c40b08656b05ba9f27dcc5abc0499cb6ae33135964c900b0cb2fc5d9a8983ae36c6a71f44d8f523a19d12a35880b580861f30810f30e0e158effe94ad84a76f27552c2d342c405a885327228cd317a07085a2853e9396b13a89abef4dfb60d11250009dcb80cc0784de0d440a5576597',
        ),
        ])
    def test_Signature_SignMessage_ResultIsCorrect(self, serialized_message, expected_signature):
        # 3/ Sign using RSASSA-PSS as introduced in PKCS1v2.1 (still compatible with in PKCS1 v2.2)
        # This example is deterministic because our randbytes function returns only zeros:
        signature = example_key1.sign(unhexlify(serialized_message) , randbytes=randbytes_zeros)
        #print (hexlify(signature))
        self.assertEqual(signature, unhexlify(expected_signature))

 
class MessageEncryptionTests(unittest.TestCase):

       
    def test_Encryption_EncryptMessage_ResultIsCorrect(self):
        # 4/ Encrypt the message using AES 256 GCM. We prepend a 16 byte nonce as per pycryptodome recommendation)
        serialized_message = unhexlify('9692ac626f6f737472617041646472d923326e506667797348355552774d366d636b6e71774e4567624369394333366f5173645a92ac626f6f73747261704e6f6465d921687474703a2f2f6170692e6269747374616d702e636f6d2f74656c65666572696392aa696e766974654e616d65c42d29c88d786ed68ce6fcb62aa63bf9ab61081d72dc7603a3d323a23268ffaa8b66746cf6168fe66480cd433f478e92ac6f66666572696e6741646472d923326e39684c4c7a68706e3475655248596f4a42746352374a6b6d746356346f6d7a4c4b92ba73657276696365416e6e6f756e63656d656e744d657373616765c4200f2e63df2c59f0b4108d4ae187be24718d9bcaa64903f883d38b9a81d1cca66492b1736572766963654f66666572696e67494401') 
        key = AESKey(unhexlify(b'2ecdf1b6fbc85c51b052ea665a0e946400681d5a7baa69378f9a6275dd236b59'))
        encrypted_message = key.encrypt(serialized_message, randbytes=randbytes_zeros)
        self.assertEqual(encrypted_message, unhexlify('000000000000000000000000000000009430a343dc2323e7e63c83c99505e74585cb85719a5d4b8fbd89a68802c497c870a6de5f734908844be8037495d853c2c221d1c8396bcccb2941b5683d0667610b0c19ecf33dd715477dc04edd6a7d80898a93e80ff9476c3366615a238f41b4681539b3fe8883c86ce379bae0eabf50319c6209c5dc52e93022a68fa9ebb610390a23bdcb9d3fc58f0f25919f2c272558b335b10d1ba36593c5e6253146c91ea9fcc8fa97fd0b9dfc909c4aa9e40b98047c6888367e84b28bbc9db1563220b88bd5a7698578bc8efb6a08c475cfd6822c83446c011bf5c2d401309088729cffc4ae82160a030df986bdeee821a99506ceedd9a5d61a232011427915698a210d77ec6ef06ae64e773810b8e3e77c28c41dee7c33e37b2a72efa8f007ef7e6adfb2223d0052003c6549315be43720b8ce0b0f110193'))

        # 4/ Hash of the message
        messageHash = hashlib.sha256(encrypted_message).digest()
        self.assertEqual(messageHash, unhexlify('5d70fb71241e9d65104166ca520e047206ad1303dfa62742a246eadfcf9d7c4b'))
       


if __name__ == '__main__':
    unittest.main()
