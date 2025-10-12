from pydantic import BaseModel, Field, PrivateAttr, ConfigDict, field_validator
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from enum import Enum
from didl.base import Assertion, Identifier, AssertionFormat, IdentifierFormat, Attribute, Key
from didl.proof import DataIntegrityProof, Ed25519Signature2020, DataIntegritySuite
from didl.model import Status, ProofType, ProofPurpose
from didl.utils import CustomJSONEncoder
import json
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64
import struct
from dataclasses import dataclass
import os

# 直观的Kerberos到DIDL映射定义
# 区分属性(attributes)和元数据(metadata)
KERBEROS_TO_DIDL_MAPPING = {
    # 属性映射 - 这些将作为didl:attribute
    "attributes": {
        "realm": Key.Realm,
        "client_principal": Key.DelegatingParty,
        "server_principal": Key.TargetedAudience,
        "session_key": Key.SessionKey,
    },
    
    # 元数据映射 - 这些将作为DIDL的元数据字段
    "metadata": {
        "start_time": "validFrom",  # didl:validFrom
        "end_time": "validTo",      # didl:validTo
        "renew_till": "RenewableTill",    # 可以映射到validTo或作为单独字段
        "auth_time": "issueDate",   # didl:issueDate
    }
}

# 特殊处理映射 - 需要转换逻辑的字段
KERBEROS_SPECIAL_MAPPING = {
    "ticket_flags": {
        "type": "enum_to_string",
        "enum_class": "KerberosTicketFlag",
        "separator": ","
    },
    "encryption_type": {
        "type": "enum_to_string", 
        "enum_class": "KerberosEncryptionType"
    },
    "session_key": {
        "type": "base64_encode"
    },
    "auth_time": {
        "type": "timestamp_to_string"
    },
    "start_time": {
        "type": "timestamp_to_string"
    },
    "end_time": {
        "type": "timestamp_to_string"
    },
    "renew_till": {
        "type": "timestamp_to_string"
    }
}

class KerberosMessageType(int, Enum):
    """Kerberos message types"""
    AS_REQ = 10
    AS_REP = 11
    TGS_REQ = 12
    TGS_REP = 13
    AP_REQ = 14
    AP_REP = 15
    KRB_SAFE = 20
    KRB_PRIV = 21
    KRB_CRED = 22
    KRB_ERROR = 30

class KerberosEncryptionType(int, Enum):
    """Kerberos encryption types"""
    DES_CBC_CRC = 1
    DES_CBC_MD4 = 2
    DES_CBC_MD5 = 3
    DES3_CBC_SHA1 = 16
    AES128_CTS_HMAC_SHA1_96 = 17
    AES256_CTS_HMAC_SHA1_96 = 18
    AES128_CTS_HMAC_SHA256_128 = 19
    AES256_CTS_HMAC_SHA384_192 = 20
    CAMELLIA128_CTS_CMAC = 25
    CAMELLIA256_CTS_CMAC = 26

class KerberosTicketFlag(int, Enum):
    """Kerberos ticket flags"""
    RESERVED = 0x80000000
    FORWARDABLE = 0x40000000
    FORWARDED = 0x20000000
    PROXIABLE = 0x10000000
    PROXY = 0x08000000
    MAY_POSTDATE = 0x04000000
    POSTDATED = 0x02000000
    INVALID = 0x01000000
    RENEWABLE = 0x00800000
    INITIAL = 0x00400000
    PRE_AUTHENT = 0x00200000
    HW_AUTHENT = 0x00100000
    TRANSITED_POLICY_CHECKED = 0x00080000
    OK_AS_DELEGATE = 0x00040000
    REQUEST_ANONYMOUS = 0x00020000
    NAME_CANONICALIZE = 0x00010000
    CNAME_IN_ADDL_TKT = 0x00008000
    ENC_TKT_IN_SKEY = 0x00004000
    RENEWABLE_OK = 0x00002000
    ENC_TKT_IN_SKEY_2 = 0x00001000
    DISABLE_TRANSITED_CHECK = 0x00000800
    RENEWABLE_2 = 0x00000400
    ENC_TKT_IN_SKEY_3 = 0x00000200
    RENEWABLE_3 = 0x00000100
    ENC_TKT_IN_SKEY_4 = 0x00000080
    RENEWABLE_4 = 0x00000040
    ENC_TKT_IN_SKEY_5 = 0x00000020
    RENEWABLE_5 = 0x00000010
    ENC_TKT_IN_SKEY_6 = 0x00000008
    RENEWABLE_6 = 0x00000004
    ENC_TKT_IN_SKEY_7 = 0x00000002
    RENEWABLE_7 = 0x00000001

@dataclass
class KerberosPrincipal:
    """Represents a Kerberos principal name"""
    name_type: int = 1  # NT_PRINCIPAL
    name_string: List[str] = None

    def __post_init__(self):
        if self.name_string is None:
            self.name_string = []

@dataclass
class KerberosRealm:
    """Represents a Kerberos realm"""
    realm: str

@dataclass
class KerberosEncryptionKey:
    """Represents a Kerberos encryption key"""
    keytype: KerberosEncryptionType
    keyvalue: bytes

@dataclass
class KerberosTicket:
    """Represents a Kerberos ticket"""
    tkt_vno: int = 5
    realm: Optional[KerberosRealm] = None
    sname: Optional[KerberosPrincipal] = None
    enc_part: Optional[Dict[str, Any]] = None

@dataclass
class KerberosEncTicketPart:
    """Represents the encrypted part of a Kerberos ticket"""
    flags: int = 0
    key: Optional[KerberosEncryptionKey] = None
    crealm: Optional[KerberosRealm] = None
    cname: Optional[KerberosPrincipal] = None
    transited: Optional[Dict[str, Any]] = None
    authtime: Optional[datetime] = None
    starttime: Optional[datetime] = None
    endtime: Optional[datetime] = None
    renew_till: Optional[datetime] = None
    caddr: Optional[List[Dict[str, Any]]] = None
    authorization_data: Optional[List[Dict[str, Any]]] = None

class KerberosTicketModel(BaseModel):
    """Represents a Kerberos Ticket Object."""
    
    model_config = ConfigDict(arbitrary_types_allowed=True)
    _session_key: Optional[bytes] = PrivateAttr(default=None)
    _ticket_key: Optional[bytes] = PrivateAttr(default=None)

    # Kerberos Ticket Header
    msg_type: KerberosMessageType = KerberosMessageType.AP_REQ
    pvno: int = 5
    ticket: Optional[KerberosTicket] = None
    authenticator: Optional[Dict[str, Any]] = None

    # Additional fields for DIDL integration
    realm: str = Field(default="EXAMPLE.COM")
    client_principal: Optional[str] = None
    server_principal: Optional[str] = None
    session_key: Optional[str] = None  # Base64 encoded
    ticket_flags: int = 0
    auth_time: Optional[datetime] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    renew_till: Optional[datetime] = None

    # DIDL Assertion object
    didl_assertion: Optional[Assertion] = Field(default=None, init=False)

    @field_validator("auth_time", "start_time", "end_time", "renew_till", mode="before")
    def _ensure_datetime_utc(cls, v):
        if v is None:
            return None
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
        """Initialize the Kerberos ticket after model creation"""
        if not self.ticket:
            self.ticket = self._create_default_ticket()
        
        self.generate_didl(proof_type=ProofType.DataIntegrityProof)

    def _create_default_ticket(self) -> KerberosTicket:
        """Create a default Kerberos ticket"""
        return KerberosTicket(
            tkt_vno=5,
            realm=KerberosRealm(realm=self.realm),
            sname=KerberosPrincipal(
                name_type=1,
                name_string=[self.server_principal or "krbtgt", self.realm]
            ),
            enc_part={
                "etype": KerberosEncryptionType.AES256_CTS_HMAC_SHA1_96.value,
                "kvno": 1,
                "cipher": b""  # Will be set when encrypted
            }
        )

    def generate_session_key(self, key_type: KerberosEncryptionType = KerberosEncryptionType.AES256_CTS_HMAC_SHA1_96) -> bytes:
        """Generate a new session key"""
        if key_type == KerberosEncryptionType.AES256_CTS_HMAC_SHA1_96:
            self._session_key = os.urandom(32)  # 256-bit key
        elif key_type == KerberosEncryptionType.AES128_CTS_HMAC_SHA1_96:
            self._session_key = os.urandom(16)  # 128-bit key
        else:
            raise NotImplementedError(f"Unsupported encryption type: {key_type}")
        
        self.session_key = base64.b64encode(self._session_key).decode('utf-8')
        return self._session_key

    def encrypt_ticket(self, ticket_key: bytes, key_type: KerberosEncryptionType = KerberosEncryptionType.AES256_CTS_HMAC_SHA1_96) -> bytes:
        """Encrypt the ticket with the provided key"""
        self._ticket_key = ticket_key
        
        # Create the ticket data to encrypt
        ticket_data = self._create_ticket_data()
        
        # Encrypt the ticket data
        if key_type == KerberosEncryptionType.AES256_CTS_HMAC_SHA1_96:
            # Use AES-256-CTS for encryption
            iv = os.urandom(16)
            cipher = Cipher(algorithms.AES(ticket_key), modes.CBC(iv))
            encryptor = cipher.encryptor()
            
            # Pad the data to block size
            padded_data = self._pad_data(ticket_data, 16)
            encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
            
            # Combine IV and encrypted data
            result = iv + encrypted_data
            
        else:
            raise NotImplementedError(f"Unsupported encryption type: {key_type}")
        
        # Update the ticket's encrypted part
        if self.ticket:
            self.ticket.enc_part = {
                "etype": key_type.value,
                "kvno": 1,
                "cipher": result
            }
        
        return result

    def _create_ticket_data(self) -> bytes:
        """Create the ticket data to be encrypted"""
        # This is a simplified implementation
        # In a real Kerberos implementation, this would follow ASN.1 DER encoding
        
        data = bytearray()
        
        # Add ticket flags
        data.extend(struct.pack(">I", self.ticket_flags))
        
        # Add timestamps
        if self.auth_time:
            data.extend(struct.pack(">I", int(self.auth_time.timestamp())))
        if self.start_time:
            data.extend(struct.pack(">I", int(self.start_time.timestamp())))
        if self.end_time:
            data.extend(struct.pack(">I", int(self.end_time.timestamp())))
        if self.renew_till:
            data.extend(struct.pack(">I", int(self.renew_till.timestamp())))
        
        # Add client principal
        if self.client_principal:
            data.extend(self.client_principal.encode('utf-8'))
        
        # Add realm
        data.extend(self.realm.encode('utf-8'))
        
        return bytes(data)

    def _pad_data(self, data: bytes, block_size: int) -> bytes:
        """Pad data to block size"""
        padding_length = block_size - (len(data) % block_size)
        padding = bytes([padding_length] * padding_length)
        return data + padding

    def decrypt_ticket(self, ticket_key: bytes) -> bool:
        """Decrypt the ticket with the provided key"""
        if not self.ticket or not self.ticket.enc_part:
            return False
        
        try:
            encrypted_data = self.ticket.enc_part["cipher"]
            key_type = self.ticket.enc_part["etype"]
            
            if key_type == KerberosEncryptionType.AES256_CTS_HMAC_SHA1_96.value:
                # Extract IV and encrypted data
                iv = encrypted_data[:16]
                cipher_data = encrypted_data[16:]
                
                # Decrypt
                cipher = Cipher(algorithms.AES(ticket_key), modes.CBC(iv))
                decryptor = cipher.decryptor()
                decrypted_data = decryptor.update(cipher_data) + decryptor.finalize()
                
                # Remove padding
                padding_length = decrypted_data[-1]
                decrypted_data = decrypted_data[:-padding_length]
                
                # Parse the decrypted data
                self._parse_ticket_data(decrypted_data)
                return True
                
            else:
                raise NotImplementedError(f"Unsupported encryption type: {key_type}")
                
        except Exception:
            return False

    def _parse_ticket_data(self, data: bytes):
        """Parse the decrypted ticket data"""
        # This is a simplified implementation
        # In a real implementation, this would parse ASN.1 DER data
        
        offset = 0
        
        # Parse ticket flags
        if len(data) >= offset + 4:
            self.ticket_flags = struct.unpack(">I", data[offset:offset+4])[0]
            offset += 4
        
        # Parse timestamps
        if len(data) >= offset + 4:
            auth_timestamp = struct.unpack(">I", data[offset:offset+4])[0]
            self.auth_time = datetime.fromtimestamp(auth_timestamp, tz=timezone.utc)
            offset += 4
        
        if len(data) >= offset + 4:
            start_timestamp = struct.unpack(">I", data[offset:offset+4])[0]
            self.start_time = datetime.fromtimestamp(start_timestamp, tz=timezone.utc)
            offset += 4
        
        if len(data) >= offset + 4:
            end_timestamp = struct.unpack(">I", data[offset:offset+4])[0]
            self.end_time = datetime.fromtimestamp(end_timestamp, tz=timezone.utc)
            offset += 4
        
        if len(data) >= offset + 4:
            renew_timestamp = struct.unpack(">I", data[offset:offset+4])[0]
            self.renew_till = datetime.fromtimestamp(renew_timestamp, tz=timezone.utc)
            offset += 4

    def generate_didl(self, proof_type: Optional[ProofType] = None) -> None:
        """Generate the DIDL assertion object from the Kerberos ticket data."""
        # Generate a unique identifier for the ticket
        ticket_id = f"kerberos_ticket_{self.realm}_{self.client_principal}_{int(self.auth_time.timestamp()) if self.auth_time else 0}"
        
        # Generate the relatesTo object
        relatesTo = Identifier(uid=self.client_principal or ticket_id, identifierFormat=IdentifierFormat.URI)

        # Map Kerberos ticket attributes to DIDL Attribute objects
        assertedAttribute = self._map_kerberos_attributes_to_didl()

        # 使用映射字典处理元数据
        metadata = self._extract_metadata_from_mapping()

        # Generate the DIDL assertion object
        self.didl_assertion = Assertion(
            uid=ticket_id,
            issuer=self.realm,
            issueDate=metadata.get("issueDate"),
            validFrom=metadata.get("validFrom"),
            validTo=metadata.get("validTo"),
            RenewableTill=metadata.get("RenewableTill"),
            relatesTo=relatesTo,
            assertedAttribute=assertedAttribute,
            assertionFormat=AssertionFormat.KerberosTicket,
            status=Status.NOTAVAILABLE
        )

        if proof_type == ProofType.DataIntegrityProof:
            # Generate the DID Linking Proof object
            proof = DataIntegrityProof(
                type=ProofType.DataIntegrityProof,
                proof_purpose=ProofPurpose.assertionMethod,
                proof_value="",
                verification_method=self.realm or "",
                cryptographic_suite=DataIntegritySuite.eddsa_rdfc_2022,
                created=datetime.now(timezone.utc)
            )
        elif proof_type == ProofType.Ed25519Signature2020:
            proof = Ed25519Signature2020(
                type=ProofType.Ed25519Signature2020,
                proof_purpose=ProofPurpose.assertionMethod,
                proof_value="",
                verification_method=self.realm or "",
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

    def _map_kerberos_attributes_to_didl(self) -> List[Attribute]:
        """Maps Kerberos ticket attributes to DIDL Attribute objects using the mapping configuration."""
        attributes = []
        
        # 使用映射字典处理属性
        for kerberos_field, didl_key in KERBEROS_TO_DIDL_MAPPING["attributes"].items():
            value = getattr(self, kerberos_field, None)
            if value is not None:
                # 应用特殊处理逻辑
                processed_value = self._apply_special_mapping(kerberos_field, value)
                if processed_value is not None:
                    attributes.append(Attribute(key=didl_key, value=str(processed_value)))
        
        # 处理需要从ticket.enc_part获取的字段
        if self.ticket and self.ticket.enc_part:
            # 处理加密类型
            enc_type = self.ticket.enc_part.get("etype")
            if enc_type:
                processed_value = self._apply_special_mapping("encryption_type", enc_type)
                if processed_value is not None:
                    attributes.append(Attribute(key=Key.EncryptionType, value=str(processed_value)))
            
            # 处理密钥版本号
            kvno = self.ticket.enc_part.get("kvno")
            if kvno:
                attributes.append(Attribute(key=Key.KeyVersionNumber, value=str(kvno)))
        
        # 生成ticket ID
        #ticket_id = f"kerberos_ticket_{self.realm}_{self.client_principal}_{int(self.auth_time.timestamp()) if self.auth_time else 0}"
        #attributes.append(Attribute(key=Key.TicketID, value=ticket_id))
        
        # 添加认证方法
        #attributes.append(Attribute(key=Key.AuthenticationMethod, value="Kerberos"))

        return attributes
    
    def _apply_special_mapping(self, field_name: str, value: Any) -> Any:
        """应用特殊映射逻辑"""
        if field_name not in KERBEROS_SPECIAL_MAPPING:
            return value
        
        mapping_config = KERBEROS_SPECIAL_MAPPING[field_name]
        mapping_type = mapping_config["type"]
        
        if mapping_type == "enum_to_string":
            return self._convert_enum_to_string(value, mapping_config)
        elif mapping_type == "base64_encode":
            return self._convert_to_base64(value)
        elif mapping_type == "timestamp_to_string":
            return self._convert_timestamp_to_string(value)
        else:
            return value
    
    def _convert_enum_to_string(self, value: Any, config: Dict[str, Any]) -> str:
        """将枚举值转换为字符串"""
        enum_class_name = config["enum_class"]
        separator = config.get("separator", ",")
        
        if enum_class_name == "KerberosTicketFlag":
            flag_names = []
            for flag in KerberosTicketFlag:
                if value & flag.value:
                    flag_names.append(flag.name)
            return separator.join(flag_names) if flag_names else str(value)
        
        elif enum_class_name == "KerberosEncryptionType":
            try:
                return KerberosEncryptionType(value).name
            except ValueError:
                return str(value)
        
        return str(value)
    
    def _convert_to_base64(self, value: Any) -> str:
        """转换为base64编码"""
        if isinstance(value, bytes):
            return base64.b64encode(value).decode('utf-8')
        elif isinstance(value, str):
            # 如果已经是base64字符串，直接返回
            return value
        else:
            return str(value)
    
    def _convert_timestamp_to_string(self, value: Any) -> str:
        """将时间戳转换为字符串"""
        if isinstance(value, datetime):
            return str(int(value.timestamp()))
        elif isinstance(value, (int, float)):
            return str(int(value))
        else:
                    return str(value)
    
    def _extract_metadata_from_mapping(self) -> Dict[str, Any]:
        """从映射字典中提取元数据"""
        metadata = {}
        
        for kerberos_field, didl_field in KERBEROS_TO_DIDL_MAPPING["metadata"].items():
            value = getattr(self, kerberos_field, None)
            if value is not None:
                # 应用特殊处理逻辑
                processed_value = self._apply_special_mapping(kerberos_field, value)
                if processed_value is not None:
                    metadata[didl_field] = value  # 保持原始datetime对象用于DIDL
        
        return metadata
    
    def create_authenticator(self, client_key: bytes) -> Dict[str, Any]:
        """Create a Kerberos authenticator"""
        if not self._session_key:
            self.generate_session_key()
        
        # Create authenticator data
        authenticator_data = {
            "authenticator-vno": 5,
            "crealm": self.realm,
            "cname": {
                "name-type": 1,
                "name-string": [self.client_principal or "unknown"]
            },
            "cusec": int(datetime.now().microsecond),
            "ctime": int(datetime.now().timestamp()),
            "subkey": {
                "keytype": KerberosEncryptionType.AES256_CTS_HMAC_SHA1_96.value,
                "keyvalue": base64.b64encode(self._session_key).decode('utf-8')
            },
            "seq-number": 0,
            "authorization-data": []
        }
        
        # Encrypt the authenticator with the session key
        authenticator_bytes = json.dumps(authenticator_data).encode('utf-8')
        
        # Use AES encryption for the authenticator
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self._session_key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        
        padded_data = self._pad_data(authenticator_bytes, 16)
        encrypted_authenticator = encryptor.update(padded_data) + encryptor.finalize()
        
        self.authenticator = {
            "etype": KerberosEncryptionType.AES256_CTS_HMAC_SHA1_96.value,
            "kvno": 1,
            "cipher": base64.b64encode(iv + encrypted_authenticator).decode('utf-8')
        }
        
        return self.authenticator

    def verify_authenticator(self, session_key: bytes) -> bool:
        """Verify the Kerberos authenticator"""
        if not self.authenticator:
            return False
        
        try:
            encrypted_data = base64.b64decode(self.authenticator["cipher"])
            iv = encrypted_data[:16]
            cipher_data = encrypted_data[16:]
            
            # Decrypt
            cipher = Cipher(algorithms.AES(session_key), modes.CBC(iv))
            decryptor = cipher.decryptor()
            decrypted_data = decryptor.update(cipher_data) + decryptor.finalize()
            
            # Remove padding
            padding_length = decrypted_data[-1]
            decrypted_data = decrypted_data[:-padding_length]
            
            # Parse the authenticator
            authenticator_data = json.loads(decrypted_data.decode('utf-8'))
            
            # Verify basic fields
            if authenticator_data.get("authenticator-vno") != 5:
                return False
            
            if authenticator_data.get("crealm") != self.realm:
                return False
            
            return True
            
        except Exception:
            return False

    def to_didl_dict(self) -> Dict[str, Any]:
        """Converts the KerberosTicket object to a DIDL Assertion dictionary."""
        if not self.didl_assertion:
            print("DEBUG: didl_assertion is None")
            return {}
        
        print(f"DEBUG: didl_assertion.uid = {self.didl_assertion.uid}")
        print(f"DEBUG: didl_assertion.issuer = {self.didl_assertion.issuer}")
        print(f"DEBUG: didl_assertion.assertionFormat = {self.didl_assertion.assertionFormat}")
        
        didl_dict = self.didl_assertion.to_json()
        print(f"DEBUG: didl_dict = {didl_dict}")
        return json.loads(json.dumps(didl_dict, cls=CustomJSONEncoder))

    @classmethod
    def from_didl_dict(cls, data: Dict[str, Any]):
        """Converts a DIDL Assertion dictionary to a KerberosTicket object."""
        uid = data.get("@id")
        issuer = data.get("didl:issuer")
        issueDate = data.get("didl:issueDate")
        validFrom = data.get("didl:validFrom")
        validTo = data.get("didl:validTo")
        assertion_format = AssertionFormat(data.get("didl:assertionFormat"))
        
        if assertion_format != AssertionFormat.KerberosTicket:
            raise ValueError(f"Unknown assertion format: {assertion_format}")

        # Extract subject from relatesTo
        relates_to = data.get("didl:relatesTo", {})
        client_principal = relates_to.get("@id") if relates_to else None

        # Create basic Kerberos ticket
        kerberos_ticket = cls(
            realm=issuer or "EXAMPLE.COM",
            client_principal=client_principal,
            auth_time=issueDate,
            start_time=validFrom,
            end_time=validTo
        )

        return kerberos_ticket

    def to_kerberos_format(self) -> Dict[str, Any]:
        """Convert to standard Kerberos format"""
        return {
            "msg-type": self.msg_type.value,
            "pvno": self.pvno,
            "ticket": {
                "tkt-vno": self.ticket.tkt_vno if self.ticket else 5,
                "realm": self.ticket.realm.realm if self.ticket and self.ticket.realm else self.realm,
                "sname": {
                    "name-type": self.ticket.sname.name_type if self.ticket and self.ticket.sname else 1,
                    "name-string": self.ticket.sname.name_string if self.ticket and self.ticket.sname else []
                },
                "enc-part": self.ticket.enc_part if self.ticket else None
            },
            "authenticator": self.authenticator
        }

    @classmethod
    def from_kerberos_format(cls, data: Dict[str, Any]):
        """Create from standard Kerberos format"""
        msg_type = KerberosMessageType(data.get("msg-type", 14))
        pvno = data.get("pvno", 5)
        
        ticket_data = data.get("ticket", {})
        ticket = KerberosTicket(
            tkt_vno=ticket_data.get("tkt-vno", 5),
            realm=KerberosRealm(realm=ticket_data.get("realm", "EXAMPLE.COM")),
            sname=KerberosPrincipal(
                name_type=ticket_data.get("sname", {}).get("name-type", 1),
                name_string=ticket_data.get("sname", {}).get("name-string", [])
            ),
            enc_part=ticket_data.get("enc-part")
        )
        
        return cls(
            msg_type=msg_type,
            pvno=pvno,
            ticket=ticket,
            authenticator=data.get("authenticator"),
            realm=ticket.realm.realm,
            server_principal=ticket.sname.name_string[0] if ticket.sname.name_string else None
        )

