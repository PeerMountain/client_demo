""" Basic Xform Generation/Validation
"""

from dataclasses import dataclass
from typing import List, Tuple, Dict
from xml.etree.ElementTree import Element, SubElement, tostring,\
    register_namespace
import xml.dom.minidom
from builtins import str
from enum import Enum
import datetime
from model import Assertion
from Crypto.Hash import HMAC, SHA256


class ValidationError(Exception):
    pass


@dataclass(frozen=True)
class Field():
    name: str
    description: str = None
    
    def generate_xml_schema(self, schema):
        simpleType = SubElement(schema, "xs:simpleType", {"name" : self.name})
        return simpleType

    def generate_xml_view(self, view):
        input = SubElement(view, "input", {"ref" : self.name})
        if self.description:
            label = SubElement(input, "label")
            label.text = self.description
        return input

    def validate(self, value):
        return value
    
    
@dataclass(frozen=True)
class StringField(Field):
    min_length: int = 0
    max_length: int = None

    def generate_xml_schema(self, schema):
        simpleType = super().generate_xml_schema(schema)
        restriction = SubElement(schema, "xs:restriction", {"base" : "xs:string"})
        if self.min_length is not None:
            SubElement(restriction, "xs:minLength", {"value" : str(self.min_length)})
        if self.max_length is not None:
            SubElement(restriction, "xs:maxLength", {"value" : str(self.max_length)})
        return simpleType
        
    def generate_xml_view(self, view):
        input = SubElement(view, "input", {"ref" : self.name})
        if self.description:
            label = SubElement(input, "label")
            label.text = self.description
        return input

    def validate(self, value):
        if type(value) is not str:
            raise ValidationError(f"{self.name} must be a string")
        if self.min_length is not None and len(value) < self.min_length:
            raise ValidationError(f"{self.name}: String too small")
        if self.max_length is not None and len(value) > self.max_length:
            raise ValidationError(f"{self.name}: String too large")
        return value
 
 
@dataclass(frozen=True)
class BooleanField(Field):
    def generate_xml_schema(self, schema):
        simpleType = super().generate_xml_schema(schema)
        restriction = SubElement(schema, "xs:restriction", {"base" : "xs:boolean"})
        return simpleType
        
    def generate_xml_view(self, view):
        input = SubElement(view, "input", {"ref" : self.name, "type" : self.checkbox})
        if self.description:
            label = SubElement(input, "label")
            label.text = self.description
        return input

    def validate(self, value):
        if type(value) is not bool:
            raise ValidationError(f"{self.name} must be a bool")
        return value


@dataclass(frozen=True)
class EnumField(Field):
    allowed_values: Tuple[str] = ()
    
    def generate_xml_schema(self, schema):
        simpleType = super().generate_xml_schema(schema)
        restriction = SubElement(schema, "xs:restriction", {"base" : "xs:string"})
        for value in self.allowed_values:
            SubElement(restriction, "xs:enumeration", {"value" : value})
        return simpleType

    def validate(self, value):
        if type(value) is not str:
            raise ValidationError(f"{self.name} must be a string")
        if not value in self.allowed_values:
            raise ValidationError(f"{self.name}: Invalid Value")
        return value
    

@dataclass(frozen=True)
class IntegerField(Field):
    min: int = None
    max: int = None
    
    def generate_xml_schema(self, schema):
        simpleType = super().generate_xml_schema(schema)
        restriction = SubElement(schema, "xs:restriction", {"base" : "xs:integer"})
        if self.min is not None:
            SubElement(restriction, "xs:minInclusive", {"value" : str(self.min)})
        if self.max is not None:
            SubElement(restriction, "xs:maxInclusive", {"value" : str(self.max)})
        return simpleType

    def generate_xml_view(self, view):
        pass

    def validate(self, value):
        if type(value) is not int:
            raise ValidationError(f"{self.name} must be an int")
        if self.min is not None and value < self.min:
            raise ValidationError(f"{self.name}: Value too small")
        if self.max is not None and value > self.max:
            raise ValidationError(f"{self.name}: Value too large")
        return value


@dataclass(frozen=True)
class DateField(Field):
    def generate_xml_schema(self, schema):
        simpleType = super().generate_xml_schema(schema)
        restriction = SubElement(schema, "xs:restriction", {"base" : "xs:date"})
        return simpleType
    
    def generate_xml_view(self, view):
        pass

    def validate(self, value):
        if type(value) is not datetime.date:
            raise ValidationError(f"{self.name} must be an date")
        return value


@dataclass(frozen=True)
class FloatField(Field):
    pass


@dataclass(frozen=True)
class FileField(Field):
    pass


@dataclass(frozen=True)
class CountryField(Field):
    pass


@dataclass(frozen=True)
class LanguageField(Field):
    pass


@dataclass(frozen=True)
class StandardField():
    field: Field
    salted: bool = True


StandardFields = set([StandardField(FileField("IdentityDocument"), False),
                      # Vcard equivalent fields                                 
                      StandardField(StringField("Name")),
                      StandardField(StringField("Surname")),
                      StandardField(StringField("AddressLine1")),
                      StandardField(StringField("AddressLine2")),
                      StandardField(StringField("PostalCode")),
                      StandardField(StringField("City")),
                      StandardField(StringField("Country")),
                      StandardField(StringField("Email")),
                      StandardField(StringField("PhoneNumber")),
                      # as in spec
                      StandardField(DateField("DateOfBirth")),
                      StandardField(StringField("PlaceOfBirth")),
                      StandardField(StringField("PlaceOfResidence")),
                      StandardField(StringField("Nationality")),
                      StandardField(StringField("CountryOfBirth")),
                      StandardField(StringField("CountryOfResidence")),
                      StandardField(StringField("PlaceOfBusiness")),
                      StandardField(StringField("Pseudonym")),
                      StandardField(StringField("LanguageProficiency")),
                      StandardField(StringField("IDNumber"))])


@dataclass
class XForm():
    fields_init: List[str]
    
    def __post_init__(self):
        self.fields = []
        stdfields_by_name = {field.field.name: field.field for field in StandardFields}
        for f in self.fields_init:
            if type(f) is str:
                if f not in stdfields_by_name:
                    raise Exception(f"The field {f} is not standard")
                self.fields.append(stdfields_by_name[f])
            else:
                assert isinstance(f, Field)
                self.fields.append(f)
         
    def to_xform(self):
        root = Element('xforms')
        root.set('xmlns:xs','http://www.w3.org/2001/XMLSchema')
        model = SubElement(root, "model")
        schema = SubElement(root, "xs:schema")
        view = SubElement(root, "view")
        for f in self.fields:
            SubElement(model, f.name)
            f.generate_xml_schema(schema)
            f.generate_xml_view(view)
        xml_str = tostring(root).decode()
        parsed = xml.dom.minidom.parseString(xml_str)
        return (parsed.toprettyxml())
    
    def validate(self, values):
        given = set(values.keys())
        fields_by_name = {f.name:f for f in self.fields}
        required = set(fields_by_name.keys())
        if (given - required):
            raise Exception("Invalid fields; %s" , ",".join(given - required))
        result = {}
        for name in values:
            result[name] = fields_by_name[name].validate(values[name])
        if (required - given):
            raise Exception("Missing fields; %s" , ",".join(required - given))
        return result


def get_metadata_dict(data, salt_storage):
    results = {}
    metahashes = []
    stdfields_by_name = {field.field.name: field for field in StandardFields}
    for name, value in data.items():
        if name in stdfields_by_name and type(stdfields_by_name[name].field) is not FileField:
            if stdfields_by_name[name].salted:
                salt = salt_storage.getMetadataSalt(value)
            else:
                salt = ""
            results[name] = Assertion.Metadata(salt, value)
            h = HMAC.new(salt, digestmod=SHA256)
            h.update(value.encode())
            metahashes.append(h.digest())
    return (results, metahashes)


if __name__ == '__main__':
    form1 = XForm(["Name", "DateOfBirth", StringField("NonStandardField1"), StringField("NonStandardField2")]) 
    print (form1.validate({"DateOfBirth" : datetime.date.today(),
                       "NonStandardField1" : "z",
                       "NonStandardField2": "iji",
                       "Name": "0" }))
    
    
'''
                StringField("Name"),
                  IntegerField("DocumentType"),
                  StringField("DocumentIssuer"),
                  DateField("DocumentIssueDate"),
                  DateField("DocumentExpDate"),
                  StringField("RegisteredAddress"),
                  EnumField("Gender", ["M", "F", "U"]),
                  StringField("Occupation"),
                  StringField("BirthName"),
                  StringField("FamilyName"),
                  StringField("GivenName"),
                  StringField("EyeColor"),
                  StringField("Heigh"),
                  StringField("Weight"),
                  StringField("ConvictedOf"),
                  StringField("Position"),
                  StringField("Ethnicity"),
                  StringField("ProductProduced"),
                  DateField("Inception"),
                  StringField("OfficialWebsite"),
                  DateField("DissolutionDate"),
                  StringField("PoliticalAlignement"),
                  StringField("LegalEntityID"),
                  StringField("TotalRevenue"),
                  StringField("TickerSymbol"),
                  StringField("OpenCorporateID"),
                  StringField("LegalForm"),
                  StringField("Employer"),
                  StringField("EmployerPersona"),
                  BooleanField("DocumentAccepted"),
                  BooleanField("MRZAccepted"),
                  StringField("IBAN"),
                  StringField("BIC"),
                  StringField("ClientNumber"),
                  StringField("CardNumber"),
                  DateField("CardExp"),
                  StringField("CardCVV"),
                  StringField("CardName"),
                  StringField("MatchObject"),
                  FloatField("MatchScore"),
                  # Documents
                  FileField("GeneralDocument"),
                  FileField("Passport"),
                  FileField("DriverLicense"),
                  FileField("NationalID"),
                  FileField("RegionalIdentityCard"),
                  FileField("BirthCertificate"),
                  FileField("SocialSecurityCard"),
                  FileField("ResidencePermitOrVisa"),
                  FileField("StudentIdentityCard"),
                  FileField("GovernmentOrDeparmentOfDefenceIDCard"),
                  FileField("PersonalQualification"),
                  FileField("CompanyFiling"),
                  FileField("CommercialRegistration"),
                  FileField("TradePermit"),
                  FileField("ShareRegistry"),
                  FileField("VesselRegistrationDocument"),
                  FileField("VesselInsuranceDocument"),
                  FileField("PortraitFront"),
                  FileField("PresencePortaits"),
                  FileField("PortraitSide"),
                  FileField("VesselFront"),
                  FileField("VesselPortSide"),
                  FileField("VesselStarboardSide"),
                  FileField("VesselRear"),
                  FileField("VesselIdentityTag"),
                  FileField("PIV_Video"),
                  FileField("DigitalFootprint"),
                  FileField("FatcaForm"),
                  FileField("Mifid2Form"),
                  FileField("TradingForm")'''