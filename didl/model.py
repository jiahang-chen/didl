from enum import Enum

class Status(Enum):
    ACTIVE = "Active"
    INACTIVE = "Inactive"
    REVOKED = "Revoked"

class Key(Enum):
    # Personal Information
    Address = "Address"
    DateOfBirth = "DateOfBirth"
    Email = "Email"
    FirstName = "FirstName"
    Gender = "Gender"
    LastName = "LastName"
    Nationality = "Nationality"  
    PhoneNumber = "PhoneNumber"
    Title = "Title"
    
    # Organizational Information
    Organization = "Organization"
    Role = "Role"
    Department = "Department"

    DelegatingParty = "DelegatingParty"
    TargetedAudience = "TargetedAudience"

    # Authentication and Authorization

    AccessCapability = "AccessCapability"
    

class IdentifierFormat(Enum):
     DID = "DID"
     DN = "DN"
     E164 = "e164"
     EPC = "EPC"
     EUI_48 = "EUI-48"
     EUI_64 = "EUI-64"
     GUID = "GUID"
     IRI = "IRI"
     RFC1035 = "RFC1035"
     RFC5322 = "RFC5322"
     RFC7613 = "RFC7613"
     URI = "URI"
     URL = "URL"
     URN = "URN"
     UUIDv1 = "UUIDv1"
     UUIDv2 = "UUIDv2"
     UUIDv3 = "UUIDv3"
     UUIDv4 = "UUIDv4"
     UUIDv5 = "UUIDv5"    


class CredentialFormat(Enum):
    FingerPrint = "Fingerprint"
    Voice = "Voice"
    SessionKey = "SessionKey"
    Signature = "Signature"
    SmartCard = "SmartCard"
    OneTimePassword = "OneTimePassword"
    PasswordCredential = "PasswordCredential"
    

class AssertionFormat(Enum):
    AccessToken = "AccessToken"
    ApplicationToken = "ApplicationToken"
    BearerToken = "BearerToken"
    IDToken = "IDToken"
    JsonWebToken = "JsonWebToken"
    KerberosTicket = "KerberosTicket"
    RefreshToken = "RefreshToken"
    SAML2Assertion = "Saml2.0Assertion"
    X509Certificate = "X509Certificate"
    VerifiableCredential = "VerifiableCredential"
    VerifiablePresentation = "VerifiablePresentation"


class ProofType(str, Enum):
    DataIntegrityProof = "DataIntegrityProof"
    Ed25519Signature2020 = "Ed25519Signature2020"

class ProofPurpose(str,Enum):
    assertionMethod = "assertionMethod"
    authentication = "authentication"
    capabilityInvocation = "capabilityInvocation"
    capabilityDelegation = "capabilityDelegation"
    keyAgreement = "keyAgreement"

class DataIntegritySuite(str, Enum):
    eddsa_rdfc_2022 = "eddsa-rdfc-2022"
    eddsa_jcs_2022 = "eddsa-jcs-2022"