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
import random

def random_bytes(len):
    # replace by os.urandom or some other crypto strong random in normal code
    # We do this only to seed at some particular value and produce reproductible examples
    return bytes(random.randrange(0, 256) for _ in range(len))

class SaltStorage():
    """ Salt Storage for the Teleferic Client """
    def __init__(self):
        self.dossierSalts = {}
        self.metadataSalts = {}

    def getDossierSalt(self, sender_address, senderID, receiver_address, receiverID):
        key = (sender_address, senderID, receiver_address, receiverID)
        if key in self.dossierSalts:
            return self.dossierSalts[key]
        dossierSalt = random_bytes(40)
        self.dossierSalts[key] = dossierSalt
        return dossierSalt
    

    def getMetadataSalt(self, fieldName):
        if fieldName in self.metadataSalts:
            return self.metadataSalts[fieldName]
        salt = random_bytes(40)
        self.metadataSalts[fieldName] = salt
        return salt


def makeDossierHash(sender_address, senderID, receiver_address, receiverID, dossierSalt):
    str = "%s:%s:%s:%s:%s" % (sender_address.address, 
                              senderID, 
                              receiver_address.address if receiver_address else "", 
                              receiverID if receiverID else "", 
                              dossierSalt)
    return hashlib.sha256(str.encode()).digest()



class TelefericServer():
    def __init__(self, initial_addresses : Dict[Address, RSAKey]={}):
        self.teleferic_key = RSAKey.load_or_generate("teleferic.pem", 1024)
        self.server_publickey = self.teleferic_key.public_key()
        self.server_address = self.server_publickey.address()
        self.public_keys = initial_addresses.copy()
        self.public_keys[self.teleferic_key.address()] = self.teleferic_key.public_key()
        
    def get_pubkey_for_address(self, addr):
        """ Address => RSAKey (public) """
        return self.public_keys.get(addr)
    
    def send_enveloppe(self, enveloppe):
        packed = MsgpackSerialize.pack(enveloppe)
        if self.server_address in enveloppe.ACL:
            # The message is for the teleferic server  
            message, body = enveloppe.decrypt(self.server_address, self.teleferic_key)
            # No signature check yet as this is just a proof of concept
            if enveloppe.messageType == MessageType.Registration and message.bodyType == BodyType.Registration_Registration:
                # New Registration must be added to the public key database
                public_key = RSAKey.import_public_key_hex(body.publicKey)
                self.public_keys[public_key.address()] = public_key
        
        return SHA256.new(packed).digest()
        
    def get_server_address(self):
        return self.server_publickey.address()
    
    def get_server_publickey(self):
        return self.server_publickey



class AttestationEngine():
    def __init__(self):
        self.key = RSAKey.load_or_generate('KYC3_key.pem', 1024)
        self.address = self.key.address()

    def create_message_analysis(self, name, valid=True):
        return Attestation.AttestationEntry(name, 
                                            MessageAnalysis(bodyHash=None, objectHash=None, metaType=None, metavalue=None, metaSalt=None, attest=valid))
    
    def create_research_analysis(self, name, valid=True):
        return Attestation.AttestationEntry(name, 
                                            ResearchAnalysis(entityAddr=None, bodyHash=None, objectHash=None, targets=[]))

    def create_attestation(self, name):
        Attestation.AttestationEntry("MRZ", )
        
        
    def get_attestation(self, assertion_enveloppe):
        # There are no fields to describe which assertions are requested? We will just make all possible
        message, assertion = assertion_enveloppe.decrypt(self.address, self.key)
        attestation_entries = []
        for a in assertion_enveloppe.attachements:
            key = AESKey(assertion.containerKey)
            decrypted_container = key.decrypt(a.objectContainer)
            #print (decrypted_container)
            attachement_dict = MsgpackSerialize.unpack(Dict[str, str], decrypted_container)
            #for name, value in attachement_dict:
            if "IdentityDocument" in attachement_dict:
                attestation_entries.append(self.create_message_analysis("MRZ"))
                attestation_entries.append(self.create_research_analysis("Fraud"))
                attestation_entries.append(self.create_research_analysis("PEP"))
                attestation_entries.append(self.create_research_analysis("Sanction"))
                attestation_entries.append(self.create_research_analysis("SanctionCountry"))
                attestation_entries.append(self.create_research_analysis("CountryRisk"))
                attestation_entries.append(self.create_research_analysis("BlackList"))
            if {"Name", "Surname", "AddressLine1", "AddressLine2", "PostalCode", "City", "Country", "Email", "PhoneNumber"}.issubset(set(attachement_dict.keys())):
                attestation_entries.append(self.create_research_analysis("AddressValidity"))
                attestation_entries.append(self.create_research_analysis("KnownCustomer"))
                attestation_entries.append(self.create_message_analysis("ResidenceClassifier"))
        return Attestation(assertion.subjectAddr, attestation_entries)
    
    
class TelefericClient():
    def __init__(self, teleferic_server):
        self.teleferic_server = teleferic_server
        self.salt_storage = SaltStorage()

    def get_teleferic_address(self):
        return self.teleferic_server.get_server_address()
    
    def get_teleferic_publickey(self):
        return self.teleferic_server.get_server_publickey()

    def make_enveloppe(self, sender_key, senderID, destination_list, message_body, attachements=[], metahashes=[]):
        """
            destination_list: list of (receiverAddress, receiverID)
            The DossierHash is computed using the first Destination.
            Dossier Hash for public messages?
            Service ID 0, is a special value?
        """
        serviceID = senderID
        if destination_list:
            receiver_address, receiverID = destination_list[0]
        else:
            receiver_address, receiverID = None, None
        sender_address = sender_key.address()
        dossierSalt = self.salt_storage.getDossierSalt(sender_address, senderID, receiver_address, receiverID)
        messageType, bodyType = GetMessageAndBodyType(message_body)
        message = Message(serviceID,
                          receiverID,
                          dossierSalt,
                          bodyType,
                          message_body)

        serialized_message = MsgpackSerialize.pack(message)
        messageSig = sender_key.sign(serialized_message)
        replacesMsgHash = None
        ACL = {}
        if not destination_list:
            # This is a public message: don't encrypt anything
            encrypted_message = serialized_message         
        else:
            # Message with destinations
            # We encrypt the message using AES, query each destination public key and RSA encrypt the key for each destination
            key = AESKey.generate()
            for addr, receiver_id in destination_list:
                pubkey = self.teleferic_server.get_pubkey_for_address(addr)
                ACL[addr] = pubkey.encrypt(key.key)
            encrypted_message = key.encrypt(serialized_message)
            
        messageHash = hashlib.sha256(encrypted_message).digest()
        dossierHash = makeDossierHash(sender_address, senderID, receiver_address, receiverID, dossierSalt)
        
        enveloppe = MessageEnveloppe(messageHash, # hash of encrypted body
                        messageType,
                        dossierHash, # hash of the SerciceAddress+ServiceId+ConsumerAddres+ConsumerId+DossierSalt
                        sender_key.address(),
                        messageSig, # signature of the unencrypted message
                        encrypted_message,
                        ACL, #: List[Address, bytes]]
                        attachements, #: List[Attachement]
                        replacesMsgHash) #: bytes
        return enveloppe

    
    def send_message(self, sender_key, senderID, destination_list, message_body, attachements=[]):
        enveloppe = self.make_enveloppe(sender_key, senderID, destination_list, message_body, attachements)
        return self.teleferic_server.send_enveloppe(enveloppe)
        
def main_scenario():
    random.seed(0)
    randbytes = random_bytes
    # Setup an Attestation Engine
    KYC3 = AttestationEngine()
    # Bitstamp sets up teleferic instance 
    service_key = RSAKey.load_or_generate('service.pem', 1024)
    service_address = service_key.address()
    teleferic_server = TelefericServer(initial_addresses={service_address: service_key.public_key(),
                                                          KYC3.key.address(): KYC3.key.public_key()})
    teleferic = TelefericClient(teleferic_server)
    
    
    # Bitstamp defines a Service 
    serviceAnnouncementMessage = ServiceRegistration(
        "exchange",
        service_address,
        datetime.date(2018, 1, 1),
        None,
        "Bitstamp",
        "Cryptocurrency Exchange",
        b"", #images
        [ServiceDocument(XForm(["IdentityDocument"]),
                         [ServiceAttestation(KYC3.address,
                                             ["MRZ", "Fraud", "PEP", "Sanction", "SanctionCountry", "CountryRisk", "BlackList"],
                                             DestinationType.SendServiceProvider,
                                             0)]),
                    
         ServiceDocument(XForm(["Name", "Surname", "AddressLine1", "AddressLine2", "PostalCode",
                                "City", "Country", "Email", "PhoneNumber"]),
                         [ServiceAttestation(KYC3.address, ["AddressValidity", "KnownCustomer", "ResidenceClassifier"]), ]),
         ServiceDocument(XForm([BooleanField("TermsAndConditions")]),
                         []),
         ])
    serviceAnnouncementMessageHash = teleferic.send_message(service_key, 0, [], serviceAnnouncementMessage)
    serviceOfferingID = 1 # only 1 service

    # Bitstamp send an Registers an Invitation to the chain
    invite_aeskey = AESKey.generate(256, randbytes)
    inviteName = "AccountLevel1"
    inviteKey = invite_aeskey.key
    inviteNameEncrypted = invite_aeskey.encrypt(inviteName.encode(), randbytes=randbytes)
    invitation_registration = InviteRegistration("http://api.bitstamp.com/teleferic",
                                                 teleferic.get_teleferic_address(),
                                                 service_address,
                                                 serviceAnnouncementMessageHash,
                                                 serviceOfferingID,
                                                 inviteNameEncrypted)
    print (invitation_registration)
    
    print('BEGIN----------------')
    inviteMsgID = teleferic.send_message(service_key, 0, [], invitation_registration)
    exit()
    # We receive an invitation
    invitation = Invitation("http://api.bitstamp.com/teleferic",
                            teleferic.get_teleferic_address(),
                            service_address,
                            serviceAnnouncementMessageHash,
                            serviceOfferingID,
                            inviteNameEncrypted,
                            inviteMsgID,
                            inviteKey)
    
    # We setup an RSA key
    customer_key = RSAKey.load_or_generate('client.pem', 1024)
    customer_address = customer_key.address()
    publicNickname = "nickname1"
    # We register to the teleferic server using this invitation
    encrypted_inviteKey = teleferic.get_teleferic_publickey().encrypt(invitation.inviteKey)
    registration = RegistrationRequest(
            inviteMsgID,
            encrypted_inviteKey, # inviteKey encrypted by the deployment machine persona publicKey
            inviteName,
            customer_key.public_key_hex(), # Persona’s public key
            publicNickname,
    )
    teleferic.send_message(customer_key, 0, [(teleferic.get_teleferic_address(), 0)], registration, [])
    # We prepare the required forms
    doc1, doc2, doc3 = serviceAnnouncementMessage.documents
    form1, form2, form3 = doc1.xform, doc2.xform, doc3.xform
    data1 = form1.validate({"IdentityDocument" : read_file_contents("passport.png")})
    data2 = form2.validate({"Name" : "John",
                            "Surname" : "Doe",
                            "AddressLine1" : "167 Custom Road",
                            "AddressLine2" : "",
                            "PostalCode" : "456",
                            "City" : "Luxembourg",
                            "Country" : "Luxembourg",
                            "Email" : "anymail@gmail.com",
                            "PhoneNumber" : "+35278745544"})
    data3 = form3.validate({"TermsAndConditions" : True})

    key = AESKey.generate()
    metadict1, metahashes1 = get_metadata_dict(data1, teleferic.salt_storage)
    metadict2, metahashes2 = get_metadata_dict(data2, teleferic.salt_storage)
    metadict3, metahashes3 = get_metadata_dict(data3, teleferic.salt_storage)
    attachement1 = Attachement.make(key, MsgpackSerialize.pack(data1), metahashes1) 
    attachement2 = Attachement.make(key, MsgpackSerialize.pack(data2), metahashes2) 
    attachement3 = Attachement.make(key, MsgpackSerialize.pack(data3), metahashes3) 
    
    assertion = Assertion(customer_address, # PM Address Persona for the assertion
                          datetime.date(2020, 1, 1), # Unix timestamp, 0 or -1 ZULU time, 0 for none, -1 for indefinite, -2 for undetermined
                          datetime.date(2020, 1, 1), # Unix timestamp, 0 or -1 ZULU time, 0 for none, -1 for indefinite, -2 for undetermined
                          key.key, # AES-256 key Decryption key for container
                          merge_dicts(metadict1, metadict2, metadict3))
    
    metahashes = set(metahashes1 +  metahashes2 + metahashes3)
    assertion_enveloppe = teleferic.make_enveloppe(customer_key, 0, [(KYC3.address, 0)], assertion, [attachement1,
                                                                                                     attachement2,
                                                                                                     attachement3], metahashes)

    # Receive many attestations from KYC3
    attestations = KYC3.get_attestation(assertion_enveloppe)
    print (attestations)
    print ("completed")
    # We register to the bitstamp service
    # TODO

if __name__ == '__main__':
    main_scenario()
