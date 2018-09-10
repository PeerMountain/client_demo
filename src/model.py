from enum import Enum, auto
from dataclasses import dataclass
from typing import Dict, List
import datetime
from crypto import AESKey, Address
from serialization import MsgpackSerialize


class BodyType(Enum):
    Checkpoint = auto()
    InviteRegistration = auto() 
    RegistrationRequest = auto()
    DelegatePersona = auto()
    Backup = auto()
    Recover = auto()
    Assertion = auto()
    Attestation = auto()
    VerificationRequest = auto()
    ServiceOffering = auto()
    ServiceRegistration = auto()
    AmendmentRequest = auto() 
    ServiceSubscription = auto()
    ServiceTermination = auto()
    Delegation = auto()
    Validation = auto()



@dataclass(frozen=True)
class Attachement():
    containerHash: bytes
    containerSig: bytes
    objectContainer: bytes
    objectHash: bytes
    Metahashes: List[bytes]

    @classmethod
    def make(cls, key, data, metahashes):
        """ Make an attachment while computing all hashes """
        objectContainer = key.encrypt(data)
        containerHash = None # TODO
        containerSig = None # TODO
        objectHash = None # TODO
        return cls(containerHash, containerSig, objectContainer, objectHash, metahashes)
      
      
@dataclass(frozen=True)
class MessageBody():
    pass

    
@dataclass(frozen=True)
class Message():
    serviceID: int
    consumerID: int
    dossierSalt: bytes
    bodyType: BodyType
    body: MessageBody

    @classmethod
    def from_struct(cls, data):
        datadict = dict(data)
        # Deserialize Body based on BodyClass
        bodyType = MsgpackSerialize.from_struct(BodyType, datadict["bodyType"])
        bodyClass = GetBodyClass(bodyType)
        body = MsgpackSerialize.from_struct(bodyClass, datadict["body"])
        return cls(datadict["serviceID"], datadict["consumerID"], datadict["dossierSalt"], 
                   bodyType, body)
        
@dataclass(frozen=True)
class MessageEnveloppe():
    messageHash: bytes
    dossierHash: bytes # hash of the DossierSalt?
    senderAddr: Address
    messageSig: bytes
    message: bytes
    ACL: Dict[Address, bytes] # address => encrypted_key
    attachements: List[Attachement]
    replacesMsgHash: bytes = None

    def decrypt(self, address, key):
        """ Returns Message, Body """             
        encrypted_key = self.ACL[address]
        aeskeydata = key.decrypt(encrypted_key)
        aeskey = AESKey(aeskeydata)
        message = MsgpackSerialize.unpack(Message, aeskey.decrypt(self.message))
        return message


DestinationType = Enum("DestinationType", "SendConsumer SendServiceProvider SendBoth")


@dataclass(frozen=True)
class ServiceAttestation():
    aePMAddress: Address
    attestation_list: List[str]
    destinationPMAddress: DestinationType = DestinationType.SendServiceProvider
    updateFrequencyInDays: int = None


@dataclass(frozen=True)
class ServiceDocument():
    xform: str
    requiredAttestations: List[ServiceAttestation]


@dataclass(frozen=True)
class ServiceRegistration(MessageBody):
    serviceId: str
    servicePMAddress: str
    serviceStartDate: datetime.date
    serviceEndDate: datetime.date
    serviceMarketing_name: str
    serviceMarketing_description: str
    serviceMarketing_image: bytes
    documents: List[ServiceDocument]


@dataclass(frozen=True)
class InviteRegistration(MessageBody):
    boostrapNode: str
    boostrapAddr: Address
    offeringAddr: Address
    serviceAnnouncementMessage: bytes
    serviceOfferingID: int
    inviteName: bytes


@dataclass(frozen=True)
class Invitation(InviteRegistration):
    inviteMsgID: bytes
    inviteKey: bytes


@dataclass(frozen=True)
class RegistrationRequest(MessageBody):
    inviteMsgID: bytes
    keyProof: bytes
    inviteName: bytes
    publicKey: bytes
    publicNickname: bytes


@dataclass(frozen=True)
class Assertion(MessageBody):
    @dataclass(frozen=True)
    class Metadata():
        MetaSalt: bytes # 40 bytes or “0” A 40-byte salt value appended to meta-data in order to match public hash values, or 0 for unsalted.  Metasalt should be generated CONFIDENTIAL Page | 19
        MetaValue : str 
    subjectAddr: Address # PM Address Persona for the assertion
    validUntil: datetime.date # Unix timestamp, 0 or -1 ZULU time, 0 for none, -1 for indefinite, -2 for undetermined
    retainUntil: datetime.date # Unix timestamp, 0 or -1 ZULU time, 0 for none, -1 for indefinite, -2 for undetermined
    containerKey: bytes # AES-256 key Decryption key for container
    Meta: Dict[str, Metadata] # metaType=>  Meta element type (see table) 
   

@dataclass(frozen=True)
class AttestationDetail():
    pass


AttestationType = Enum("AttestationType", "MessageAnalysis MessageComparision ResearchAnalysis Rejection")


@dataclass(frozen=True)
class Attestation(MessageBody):
    @dataclass(frozen=True)
    class AttestationEntry():
        attestType: str
        #attestSig: bytes # xades-t
        detail: AttestationDetail
    subject: Address
    attestations: AttestationEntry
 
 
@dataclass(frozen=True)
class MessageAnalysis(AttestationDetail):
    bodyHash: bytes
    objectHash: bytes
    metaType: int
    metavalue: str
    metaSalt: bytes
    attest: str
    
    
@dataclass(frozen=True)
class Match():
    matchType: int 
    matchValue: str
    matchSalt: bytes
    attest: str
    
    
@dataclass(frozen=True)
class MatchTarget():
    bodyHash: bytes
    objectHash: bytes
    matches : List[Match]

    
@dataclass(frozen=True)
class MessageComparison(AttestationDetail):
    sourceBodyHash: bytes
    sourceObjectHash: bytes
    targets: List[MatchTarget]
   
    
@dataclass(frozen=True)
class ResearchAnalysis(AttestationDetail):
    @dataclass(frozen=True)
    class riskIntel():
        metaType: int
        metaValue: str
        metaSalt: str
        attest: str
        externalSource: str
        sourceID: str
        exteranalDocID: str
        externalKey: str
        risk: str
        riskDescriptor: str
        details: str 
    entityAddr: Address
    bodyHash: bytes
    objectHash: bytes
    targets: List[riskIntel]


@dataclass(frozen=True)
class Rejection(AttestationDetail):
    attestationMessageHash: bytes
    rejectReason: str


def GetBodyType(message_body):
    objtype = type(message_body)
    mapping = {ServiceRegistration : BodyType.ServiceRegistration,
               InviteRegistration : BodyType.InviteRegistration,
               RegistrationRequest : BodyType.RegistrationRequest,
               Assertion: BodyType.Assertion}
    return mapping[objtype]



def GetBodyClass(bodyType):
    mapping = {BodyType.ServiceRegistration: ServiceRegistration ,
               BodyType.InviteRegistration: InviteRegistration,
               BodyType.RegistrationRequest : RegistrationRequest,
               BodyType.Assertion : Assertion}
    return mapping[bodyType]




