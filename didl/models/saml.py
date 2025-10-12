from pydantic import BaseModel, Field, validator, PrivateAttr, ConfigDict, field_validator
from typing import List, Dict, Any, Optional, Union
from datetime import datetime, timezone
import uuid
from enum import Enum
from didl.base import Assertion, Identifier, AssertionFormat, IdentifierFormat, Attribute, Key
from didl.proof import DataIntegrityProof, Ed25519Signature2020, DataIntegritySuite
from didl.model import Status, ProofType, ProofPurpose
from didl.utils import CustomJSONEncoder
import json
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509 import load_pem_x509_certificate
import base64
import hashlib
from dataclasses import dataclass
from xml.etree import ElementTree as ET
from xml.dom import minidom

# 直观的SAML到DIDL映射定义
# 区分属性(attributes)和元数据(metadata)
SAML_TO_DIDL_MAPPING = {
    # 属性映射 - 这些将作为didl:attribute
    "attributes": {
        "session_index": Key.SessionKey,  
    },
    
    # 元数据映射 - 这些将作为DIDL的元数据字段
    "metadata": {
        "issue_instant": "issueDate",  # didl:issueDate
        "not_before": "validFrom",     # didl:validFrom
        "not_on_or_after": "validTo",  # didl:validTo
        "issuer": "issuer",            # didl:issuer
        "id": "uid",                   # didl:uid
    }
}

# 特殊处理映射 - 需要转换逻辑的字段
SAML_SPECIAL_MAPPING = {
    "issue_instant": {
        "type": "timestamp_to_string"
    },
    "not_before": {
        "type": "timestamp_to_string"
    },
    "not_on_or_after": {
        "type": "timestamp_to_string"
    },
    "authn_context_class_ref": {
        "type": "authn_context_to_method"
    }
}

# SAML属性名称到DIDL Key的映射
SAML_ATTRIBUTE_NAME_MAPPING = {
    # 标准SAML属性名称
    "givenname": Key.FirstName,
    "firstname": Key.FirstName,
    "surname": Key.LastName,
    "lastname": Key.LastName,
    "email": Key.Email,
    "mail": Key.Email,
    "emailaddress": Key.Email,
    "role": Key.Role,
    "title": Key.Title,
    "organization": Key.Organization,
    "org": Key.Organization,
    "department": Key.Department,
    "dept": Key.Department,
    "phone": Key.PhoneNumber,
    "phonenumber": Key.PhoneNumber,
    "telephonenumber": Key.PhoneNumber,
    "address": Key.Address,
    "dateofbirth": Key.DateOfBirth,
    "birthdate": Key.DateOfBirth,
    "gender": Key.Gender,
    "nationality": Key.Nationality,
}

class SAMLVersion(str, Enum):
    V2_0 = "2.0"

class SAMLNameIDFormat(str, Enum):
    UNSPECIFIED = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
    EMAIL = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
    TRANSIENT = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
    PERSISTENT = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
    ENTITY = "urn:oasis:names:tc:SAML:2.0:nameid-format:entity"
    X509_SUBJECT = "urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName"
    WINDOWS_DOMAIN = "urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName"
    KERBEROS = "urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos"

class SAMLConfirmationMethod(str, Enum):
    BEARER = "urn:oasis:names:tc:SAML:2.0:cm:bearer"
    HOLDER_OF_KEY = "urn:oasis:names:tc:SAML:2.0:cm:holder-of-key"
    SENDER_VOUCHES = "urn:oasis:names:tc:SAML:2.0:cm:sender-vouches"

class SAMLStatus(str, Enum):
    SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success"
    REQUESTER = "urn:oasis:names:tc:SAML:2.0:status:Requester"
    RESPONDER = "urn:oasis:names:tc:SAML:2.0:status:Responder"
    VERSION_MISMATCH = "urn:oasis:names:tc:SAML:2.0:status:VersionMismatch"

@dataclass
class SAMLNameID:
    """Represents a SAML NameID element"""
    value: str
    format: Optional[SAMLNameIDFormat] = None
    name_qualifier: Optional[str] = None
    sp_name_qualifier: Optional[str] = None
    sp_provided_id: Optional[str] = None

@dataclass
class SAMLSubject:
    """Represents a SAML Subject element"""
    name_id: Optional[SAMLNameID] = None
    subject_confirmations: List[Dict[str, Any]] = None

    def __post_init__(self):
        if self.subject_confirmations is None:
            self.subject_confirmations = []

@dataclass
class SAMLCondition:
    """Represents a SAML Condition element"""
    not_before: Optional[datetime] = None
    not_on_or_after: Optional[datetime] = None
    audience_restriction: Optional[List[str]] = None
    one_time_use: bool = False
    proxy_restriction: Optional[Dict[str, Any]] = None

@dataclass
class SAMLAuthnStatement:
    """Represents a SAML Authentication Statement"""
    authn_instant: datetime
    session_index: Optional[str] = None
    session_not_on_or_after: Optional[datetime] = None
    authn_context_class_ref: Optional[str] = None
    authn_context_decl_ref: Optional[str] = None
    authn_context_decl: Optional[Dict[str, Any]] = None
    subject_locality: Optional[Dict[str, str]] = None

@dataclass
class SAMLAttributeStatement:
    """Represents a SAML Attribute Statement"""
    attributes: List[Dict[str, Any]] = None

    def __post_init__(self):
        if self.attributes is None:
            self.attributes = []

class SAML2Assertion(BaseModel):
    """Represents a SAML 2.0 Assertion Object."""
    
    model_config = ConfigDict(arbitrary_types_allowed=True)
    _private_key: Optional[bytes] = PrivateAttr(default=None)
    _certificate: Optional[bytes] = PrivateAttr(default=None)

    # SAML Assertion Header
    version: SAMLVersion = SAMLVersion.V2_0
    id: str = Field(default_factory=lambda: f"_{str(uuid.uuid4())}")
    issue_instant: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    issuer: Optional[str] = None

    # SAML Subject
    subject: Optional[SAMLSubject] = None

    # SAML Conditions
    conditions: Optional[SAMLCondition] = None

    # SAML Statements
    authn_statement: Optional[SAMLAuthnStatement] = None
    attribute_statement: Optional[SAMLAttributeStatement] = None

    # Signature
    signature: Optional[str] = None
    signature_algorithm: Optional[str] = None

    # XML representation
    xml_assertion: Optional[str] = None

    # DIDL Assertion object
    didl_assertion: Optional[Assertion] = Field(default=None, init=False)

    @field_validator("issue_instant", mode="before")
    def _ensure_datetime_utc(cls, v):
        if v is None:
            return datetime.now(timezone.utc)
        if isinstance(v, (int, float)):
            return datetime.fromtimestamp(int(v), tz=timezone.utc)
        if isinstance(v, str):
            s = v.replace("Z", "+00:00")
            try:
                dt = datetime.fromisoformat(s)
            except Exception as e:
                raise ValueError(f"Invalid datetime string: {v}") from e
            return dt.astimezone(timezone.utc)
        if isinstance(v, datetime):
            return v if v.tzinfo else v.replace(tzinfo=timezone.utc)
        raise TypeError(f"Unsupported datetime type: {type(v)}")

    def model_post_init(self, __context):
        """Initialize the SAML assertion after model creation"""
        if not self.xml_assertion:
            self.xml_assertion = self._generate_xml()
        
        self.generate_didl(proof_type=ProofType.DataIntegrityProof)

    def _generate_xml(self) -> str:
        """Generate the SAML XML assertion"""
        # Create the root assertion element
        assertion = ET.Element("saml:Assertion", {
            "xmlns:saml": "urn:oasis:names:tc:SAML:2.0:assertion",
            "Version": self.version.value,
            "ID": self.id,
            "IssueInstant": self.issue_instant.strftime("%Y-%m-%dT%H:%M:%SZ")
        })

        # Add Issuer
        if self.issuer:
            issuer_elem = ET.SubElement(assertion, "saml:Issuer")
            issuer_elem.text = self.issuer

        # Add Subject
        if self.subject:
            subject_elem = ET.SubElement(assertion, "saml:Subject")
            
            if self.subject.name_id:
                name_id_elem = ET.SubElement(subject_elem, "saml:NameID")
                name_id_elem.text = self.subject.name_id.value
                if self.subject.name_id.format:
                    name_id_elem.set("Format", self.subject.name_id.format.value)
                if self.subject.name_id.name_qualifier:
                    name_id_elem.set("NameQualifier", self.subject.name_id.name_qualifier)
                if self.subject.name_id.sp_name_qualifier:
                    name_id_elem.set("SPNameQualifier", self.subject.name_id.sp_name_qualifier)
                if self.subject.name_id.sp_provided_id:
                    name_id_elem.set("SPProvidedID", self.subject.name_id.sp_provided_id)

            # Add SubjectConfirmations
            for confirmation in self.subject.subject_confirmations:
                conf_elem = ET.SubElement(subject_elem, "saml:SubjectConfirmation")
                conf_elem.set("Method", confirmation.get("method", SAMLConfirmationMethod.BEARER.value))
                
                if "data" in confirmation:
                    data_elem = ET.SubElement(conf_elem, "saml:SubjectConfirmationData")
                    data = confirmation["data"]
                    if "not_before" in data:
                        data_elem.set("NotBefore", data["not_before"])
                    if "not_on_or_after" in data:
                        data_elem.set("NotOnOrAfter", data["not_on_or_after"])
                    if "recipient" in data:
                        data_elem.set("Recipient", data["recipient"])
                    if "in_response_to" in data:
                        data_elem.set("InResponseTo", data["in_response_to"])

        # Add Conditions
        if self.conditions:
            conditions_elem = ET.SubElement(assertion, "saml:Conditions")
            if self.conditions.not_before:
                conditions_elem.set("NotBefore", self.conditions.not_before.strftime("%Y-%m-%dT%H:%M:%SZ"))
            if self.conditions.not_on_or_after:
                conditions_elem.set("NotOnOrAfter", self.conditions.not_on_or_after.strftime("%Y-%m-%dT%H:%M:%SZ"))

            # Add AudienceRestriction
            if self.conditions.audience_restriction:
                audience_elem = ET.SubElement(conditions_elem, "saml:AudienceRestriction")
                for audience in self.conditions.audience_restriction:
                    audience_child = ET.SubElement(audience_elem, "saml:Audience")
                    audience_child.text = audience

            # Add OneTimeUse
            if self.conditions.one_time_use:
                ET.SubElement(conditions_elem, "saml:OneTimeUse")

        # Add AuthnStatement
        if self.authn_statement:
            authn_elem = ET.SubElement(assertion, "saml:AuthnStatement")
            authn_elem.set("AuthnInstant", self.authn_statement.authn_instant.strftime("%Y-%m-%dT%H:%M:%SZ"))
            
            if self.authn_statement.session_index:
                authn_elem.set("SessionIndex", self.authn_statement.session_index)
            if self.authn_statement.session_not_on_or_after:
                authn_elem.set("SessionNotOnOrAfter", self.authn_statement.session_not_on_or_after.strftime("%Y-%m-%dT%H:%M:%SZ"))

            # Add AuthnContext
            authn_context_elem = ET.SubElement(authn_elem, "saml:AuthnContext")
            if self.authn_statement.authn_context_class_ref:
                class_ref_elem = ET.SubElement(authn_context_elem, "saml:AuthnContextClassRef")
                class_ref_elem.text = self.authn_statement.authn_context_class_ref

        # Add AttributeStatement
        if self.attribute_statement:
            attr_stmt_elem = ET.SubElement(assertion, "saml:AttributeStatement")
            for attr in self.attribute_statement.attributes:
                attr_elem = ET.SubElement(attr_stmt_elem, "saml:Attribute")
                attr_elem.set("Name", attr["name"])
                if "name_format" in attr:
                    attr_elem.set("NameFormat", attr["name_format"])
                if "friendly_name" in attr:
                    attr_elem.set("FriendlyName", attr["friendly_name"])
                
                for value in attr.get("values", []):
                    attr_value_elem = ET.SubElement(attr_elem, "saml:AttributeValue")
                    attr_value_elem.text = str(value)

        # Convert to string
        xml_str = ET.tostring(assertion, encoding='unicode')
        return minidom.parseString(xml_str).toprettyxml(indent="  ")

    def generate_didl(self, proof_type: Optional[ProofType] = None) -> None:
        """Generate the DIDL assertion object from the SAML data."""
        # Extract subject identifier
        subject_id = None
        if self.subject and self.subject.name_id:
            subject_id = self.subject.name_id.value

        # Generate the relatesTo object
        relatesTo = Identifier(uid=subject_id or self.id, identifierFormat=IdentifierFormat.URI)

        # Map SAML attributes to DIDL Attribute objects
        assertedAttribute = self._map_saml_attributes_to_didl()

        # 使用映射字典处理元数据
        metadata = self._extract_metadata_from_mapping()

        # Generate the DIDL assertion object
        self.didl_assertion = Assertion(
            uid=metadata.get("uid", self.id),
            issuer=metadata.get("issuer"),
            issueDate=metadata.get("issueDate"),
            validFrom=metadata.get("validFrom"),
            validTo=metadata.get("validTo"),
            relatesTo=relatesTo,
            assertedAttribute=assertedAttribute,
            assertionFormat=AssertionFormat.SAML2Assertion,
            status=Status.NOTAVAILABLE
        )

        if proof_type == ProofType.DataIntegrityProof:
            # Generate the DID Linking Proof object
            proof = DataIntegrityProof(
                type=ProofType.DataIntegrityProof,
                proof_purpose=ProofPurpose.assertionMethod,
                proof_value="",
                verification_method=self.issuer or "",
                cryptographic_suite=DataIntegritySuite.eddsa_rdfc_2022,
                created=datetime.now(timezone.utc)
            )
        elif proof_type == ProofType.Ed25519Signature2020:
            proof = Ed25519Signature2020(
                type=ProofType.Ed25519Signature2020,
                proof_purpose=ProofPurpose.assertionMethod,
                proof_value="",
                verification_method=self.issuer or "",
                created=datetime.now(timezone.utc)
            )
        else:
            raise NotImplementedError("Not implemented proof type")

        # Generate a new ED25519 keypair for signing
        sk = ed25519.Ed25519PrivateKey.generate()
        pk = sk.public_key()
        sk_bytes = sk.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )
        pk_bytes = pk.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        
        didl_payload_dict = self.to_didl_dict()
        didl_payload_dict_bytes = json.dumps(didl_payload_dict).encode('utf-8')
        sig = proof.sign(didl_payload_dict_bytes, sk_bytes)
        
        # Set the DID Linking Proof object
        self.didl_assertion.proof = proof

    def _map_saml_attributes_to_didl(self) -> List[Attribute]:
        """Maps SAML attributes to DIDL Attribute objects using the mapping configuration."""
        attributes = []
        
        # 使用映射字典处理SAML模型属性
        for saml_field, didl_key in SAML_TO_DIDL_MAPPING["attributes"].items():
            value = getattr(self, saml_field, None)
            if value is not None:
                # 应用特殊处理逻辑
                processed_value = self._apply_special_mapping(saml_field, value)
                if processed_value is not None:
                    attributes.append(Attribute(key=didl_key, value=str(processed_value)))
        
        # 处理认证语句中的特殊字段
        if self.authn_statement:
            if self.authn_statement.authn_context_class_ref:
                processed_value = self._apply_special_mapping("authn_context_class_ref", 
                                                           self.authn_statement.authn_context_class_ref)
                if processed_value is not None:
                    attributes.append(Attribute(key=Key.AuthenticationMethod, value=str(processed_value)))
            
            if self.authn_statement.session_index:
                attributes.append(Attribute(key=Key.UserID, value=str(self.authn_statement.session_index)))
        
        # 处理SAML AttributeStatement中的属性
        if self.attribute_statement:
            for attr in self.attribute_statement.attributes:
                attr_name = attr.get("name", "Unknown")
                attr_values = attr.get("values", [])
                
                for value in attr_values:
                    # 使用预定义的SAML属性名称映射
                    mapped_key = self._map_saml_attribute_name_to_didl_key(attr_name)
                    attributes.append(Attribute(key=mapped_key, value=str(value)))
        
        return attributes
    
    def _map_saml_attribute_name_to_didl_key(self, attr_name: str) -> Key:
        """Maps SAML attribute names to DIDL Key enum values using the mapping configuration."""
        # 转换为小写进行大小写不敏感匹配
        attr_name_lower = attr_name.lower()
        
        # 返回映射的key，如果没找到则使用Title作为后备
        return SAML_ATTRIBUTE_NAME_MAPPING.get(attr_name_lower, Key.Title)
    
    def _apply_special_mapping(self, field_name: str, value: Any) -> Any:
        """应用特殊映射逻辑"""
        if field_name not in SAML_SPECIAL_MAPPING:
            return value
        
        mapping_config = SAML_SPECIAL_MAPPING[field_name]
        mapping_type = mapping_config["type"]
        
        if mapping_type == "timestamp_to_string":
            return self._convert_timestamp_to_string(value)
        elif mapping_type == "authn_context_to_method":
            return self._convert_authn_context_to_method(value)
        else:
            return value
    
    def _convert_timestamp_to_string(self, value: Any) -> str:
        """将时间戳转换为字符串"""
        if isinstance(value, datetime):
            return str(int(value.timestamp()))
        elif isinstance(value, (int, float)):
            return str(int(value))
        else:
            return str(value)
    
    def _convert_authn_context_to_method(self, value: Any) -> str:
        """将认证上下文类转换为认证方法"""
        if isinstance(value, str):
            # 简化认证上下文类名称
            if "password" in value.lower():
                return "Password"
            elif "kerberos" in value.lower():
                return "Kerberos"
            elif "certificate" in value.lower():
                return "Certificate"
            elif "smartcard" in value.lower():
                return "SmartCard"
            else:
                return value
        else:
            return str(value)
    
    def _extract_metadata_from_mapping(self) -> Dict[str, Any]:
        """从映射字典中提取元数据"""
        metadata = {}
        
        for saml_field, didl_field in SAML_TO_DIDL_MAPPING["metadata"].items():
            value = getattr(self, saml_field, None)
            if value is not None:
                metadata[didl_field] = value  # 保持原始值用于DIDL
        
        # 处理conditions中的时间字段
        if self.conditions:
            if self.conditions.not_before:
                metadata["validFrom"] = self.conditions.not_before
            if self.conditions.not_on_or_after:
                metadata["validTo"] = self.conditions.not_on_or_after
        
        return metadata

    def sign_assertion(self, private_key_pem: bytes, certificate_pem: Optional[bytes] = None) -> str:
        """Sign the SAML assertion with the provided private key."""
        self._private_key = private_key_pem
        self._certificate = certificate_pem
        
        # Load the private key
        private_key = serialization.load_pem_private_key(private_key_pem, password=None)
        
        # Create the XML to sign
        xml_to_sign = self._generate_xml()
        
        # For simplicity, we'll create a basic signature
        # In a real implementation, you'd use XML signature standards
        signature_data = xml_to_sign.encode('utf-8')
        signature = private_key.sign(
            signature_data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        
        self.signature = base64.b64encode(signature).decode('utf-8')
        self.signature_algorithm = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
        
        # Update XML with signature
        self.xml_assertion = self._generate_xml_with_signature()
        
        return self.xml_assertion

    def _generate_xml_with_signature(self) -> str:
        """Generate XML with embedded signature."""
        # This is a simplified implementation
        # In practice, you'd use proper XML signature standards
        xml_base = self._generate_xml()
        
        # Add signature element (simplified)
        if self.signature:
            # Parse the base XML and add signature
            root = ET.fromstring(xml_base)
            
            # Add signature element
            signature_elem = ET.SubElement(root, "ds:Signature", {
                "xmlns:ds": "http://www.w3.org/2000/09/xmldsig#"
            })
            
            # Add SignedInfo
            signed_info = ET.SubElement(signature_elem, "ds:SignedInfo")
            canonicalization_method = ET.SubElement(signed_info, "ds:CanonicalizationMethod")
            canonicalization_method.set("Algorithm", "http://www.w3.org/2001/10/xml-exc-c14n#")
            
            signature_method = ET.SubElement(signed_info, "ds:SignatureMethod")
            signature_method.set("Algorithm", self.signature_algorithm)
            
            # Add Reference
            reference = ET.SubElement(signed_info, "ds:Reference")
            reference.set("URI", f"#{self.id}")
            
            transforms = ET.SubElement(reference, "ds:Transforms")
            transform = ET.SubElement(transforms, "ds:Transform")
            transform.set("Algorithm", "http://www.w3.org/2000/09/xmldsig#enveloped-signature")
            
            digest_method = ET.SubElement(reference, "ds:DigestMethod")
            digest_method.set("Algorithm", "http://www.w3.org/2001/04/xmlenc#sha256")
            
            digest_value = ET.SubElement(reference, "ds:DigestValue")
            # Calculate digest (simplified)
            digest = hashlib.sha256(ET.tostring(root, encoding='utf-8')).digest()
            digest_value.text = base64.b64encode(digest).decode('utf-8')
            
            # Add SignatureValue
            signature_value = ET.SubElement(signature_elem, "ds:SignatureValue")
            signature_value.text = self.signature
            
            # Add KeyInfo if certificate is provided
            if self._certificate:
                key_info = ET.SubElement(signature_elem, "ds:KeyInfo")
                x509_data = ET.SubElement(key_info, "ds:X509Data")
                x509_cert = ET.SubElement(x509_data, "ds:X509Certificate")
                # Remove PEM headers and newlines
                cert_content = self._certificate.decode('utf-8')
                cert_content = cert_content.replace('-----BEGIN CERTIFICATE-----', '')
                cert_content = cert_content.replace('-----END CERTIFICATE-----', '')
                cert_content = cert_content.replace('\n', '').replace('\r', '')
                x509_cert.text = cert_content
            
            return minidom.parseString(ET.tostring(root, encoding='unicode')).toprettyxml(indent="  ")
        
        return xml_base

    def verify_signature(self, public_key_pem: bytes) -> bool:
        """Verify the SAML assertion signature."""
        if not self.signature:
            return False
        
        try:
            public_key = serialization.load_pem_public_key(public_key_pem)
            signature_data = base64.b64decode(self.signature)
            
            # Get the XML without signature for verification
            xml_to_verify = self._generate_xml().encode('utf-8')
            
            public_key.verify(
                signature_data,
                xml_to_verify,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False

    def to_didl_dict(self) -> Dict[str, Any]:
        """Converts the SAML2Assertion object to a DIDL Assertion dictionary."""

        didl_dict = self.didl_assertion.to_json()
        return json.loads(json.dumps(didl_dict, cls=CustomJSONEncoder))

    @classmethod
    def from_didl_dict(cls, data: Dict[str, Any]):
        """Converts a DIDL Assertion dictionary to a SAML2Assertion object."""
        uid = data.get("@id")
        issuer = data.get("didl:issuer")
        issueDate = data.get("didl:issueDate")
        validFrom = data.get("didl:validFrom")
        validTo = data.get("didl:validTo")
        print(issuer, issueDate, validFrom, validTo)
        assertion_format = AssertionFormat(data.get("didl:assertionFormat"))
        if assertion_format != AssertionFormat.SAML2Assertion:
            raise ValueError(f"Unknown assertion format: {assertion_format}")

        # Extract subject from relatesTo
        relates_to = data.get("didl:relatesTo", {})
        subject_id = relates_to.get("@id") if relates_to else None

        # Create basic SAML assertion
        saml_assertion = cls(
            id=uid,
            issuer=issuer,
            issue_instant=issueDate
        )

        # Set conditions if validity dates are provided
        if validFrom or validTo:
            saml_assertion.conditions = SAMLCondition(
                not_before=validFrom,
                not_on_or_after=validTo
            )

        # Set subject if available
        if subject_id:
            saml_assertion.subject = SAMLSubject(
                name_id=SAMLNameID(value=subject_id)
            )

        return saml_assertion

    @classmethod
    def from_xml(cls, xml_string: str):
        """Create a SAML2Assertion from XML string."""
        root = ET.fromstring(xml_string)
        
        # Extract basic attributes
        version = root.get("Version", "2.0")
        assertion_id = root.get("ID")
        issue_instant_str = root.get("IssueInstant")
        issue_instant = datetime.fromisoformat(issue_instant_str.replace("Z", "+00:00")) if issue_instant_str else None
        
        # Extract issuer
        issuer_elem = root.find(".//saml:Issuer", namespaces={"saml": "urn:oasis:names:tc:SAML:2.0:assertion"})
        issuer = issuer_elem.text if issuer_elem is not None else None
        
        # Create assertion
        assertion = cls(
            version=SAMLVersion(version),
            id=assertion_id,
            issue_instant=issue_instant,
            issuer=issuer
        )
        
        # Parse subject
        subject_elem = root.find(".//saml:Subject", namespaces={"saml": "urn:oasis:names:tc:SAML:2.0:assertion"})
        if subject_elem is not None:
            name_id_elem = subject_elem.find(".//saml:NameID", namespaces={"saml": "urn:oasis:names:tc:SAML:2.0:assertion"})
            if name_id_elem is not None:
                name_id = SAMLNameID(
                    value=name_id_elem.text,
                    format=SAMLNameIDFormat(name_id_elem.get("Format")) if name_id_elem.get("Format") else None
                )
                assertion.subject = SAMLSubject(name_id=name_id)
        
        # Parse conditions
        conditions_elem = root.find(".//saml:Conditions", namespaces={"saml": "urn:oasis:names:tc:SAML:2.0:assertion"})
        if conditions_elem is not None:
            not_before_str = conditions_elem.get("NotBefore")
            not_on_or_after_str = conditions_elem.get("NotOnOrAfter")
            
            not_before = datetime.fromisoformat(not_before_str.replace("Z", "+00:00")) if not_before_str else None
            not_on_or_after = datetime.fromisoformat(not_on_or_after_str.replace("Z", "+00:00")) if not_on_or_after_str else None
            
            assertion.conditions = SAMLCondition(
                not_before=not_before,
                not_on_or_after=not_on_or_after
            )
        
        # Parse attribute statement
        attr_stmt_elem = root.find(".//saml:AttributeStatement", namespaces={"saml": "urn:oasis:names:tc:SAML:2.0:assertion"})
        if attr_stmt_elem is not None:
            attributes = []
            for attr_elem in attr_stmt_elem.findall(".//saml:Attribute", namespaces={"saml": "urn:oasis:names:tc:SAML:2.0:assertion"}):
                attr_name = attr_elem.get("Name")
                attr_values = []
                for value_elem in attr_elem.findall(".//saml:AttributeValue", namespaces={"saml": "urn:oasis:names:tc:SAML:2.0:assertion"}):
                    attr_values.append(value_elem.text)
                
                attributes.append({
                    "name": attr_name,
                    "values": attr_values
                })
            
            assertion.attribute_statement = SAMLAttributeStatement(attributes=attributes)
        
        assertion.xml_assertion = xml_string
        return assertion
