from pydantic import BaseModel, Field, validator, PrivateAttr
from typing import List, Dict, Any, Optional
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
from jose import jwt
from dataclasses import dataclass
import base64, hashlib, json
from pydantic import PrivateAttr, field_validator, ConfigDict


# 使用tuple简化映射关系
JWT_DIDL_ATTRIBUTE_MAPPINGS = [
    ("aud", Key.TargetedAudience),
    ("azp", Key.DelegatingParty),
    ("scope", Key.AccessRights),
    ("given_name", Key.FirstName),
    ("family_name", Key.LastName),
    ("role", Key.Role)
]

# 使用tuple简化元数据映射关系
JWT_DIDL_METADATA_MAPPINGS = [
    ("exp", "validTo"),
    ("iat", "issueDate"),
    ("nbf", "validFrom"),
    ("iss", "issuer"),
    ("sub", "relatesTo"),
    ("jti", "uid")
]

# 特殊处理映射 - 需要转换逻辑的字段
JWT_SPECIAL_MAPPING = {
    "exp": {
        "type": "timestamp_to_string"
    },
    "iat": {
        "type": "timestamp_to_string"
    },
    "nbf": {
        "type": "timestamp_to_string"
    },
    "scope": {
        "type": "scope_to_attributes"
    },
    "aud": {
        "type": "audience_to_scope"
    }
}

def _to_unix_timestamp(dt: Optional[datetime]) -> Optional[int]:
    if dt is None:
        return None
    return int(dt.timestamp())

def _from_unix_timestamp(ts: Optional[int]) -> Optional[datetime]:
    if ts is None:
        return None
    return datetime.fromtimestamp(ts, tz=timezone.utc)

def _from_iso8601_str_to_timestamp(s: str) -> Optional[datetime]:
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


class JWTAlgorithm(str, Enum):
    RS256 = "RS256"
    ES256 = "ES256"
    EdDSA = "EdDSA"
    ES256K = "ES256K"
    ES384 = "ES384"
    ES512 = "ES512"

def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

def _int_to_b64url(n: int) -> str:
    if n == 0:
        return _b64url(b"\x00")
    length = (n.bit_length() + 7) // 8
    return _b64url(n.to_bytes(length, "big"))

def _public_key_to_jwk(pub) -> Dict[str, str]:
    from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519
    from cryptography.hazmat.primitives import serialization

    # RSA
    if isinstance(pub, rsa.RSAPublicKey):
        nums = pub.public_numbers()
        return {"kty": "RSA", "n": _int_to_b64url(nums.n), "e": _int_to_b64url(nums.e)}

    # EC (P-256/P-384/P-521/secp256k1)
    if isinstance(pub, ec.EllipticCurvePublicKey):
        nums = pub.public_numbers()
        size = (pub.curve.key_size + 7) // 8
        x = nums.x.to_bytes(size, "big")
        y = nums.y.to_bytes(size, "big")
        if isinstance(pub.curve, ec.SECP256R1): crv = "P-256"
        elif isinstance(pub.curve, ec.SECP384R1): crv = "P-384"
        elif isinstance(pub.curve, ec.SECP521R1): crv = "P-521"
        elif isinstance(pub.curve, ec.SECP256K1): crv = "secp256k1"
        else: raise ValueError("Unsupported EC curve")
        return {"kty": "EC", "crv": crv, "x": _b64url(x), "y": _b64url(y)}

    # OKP (Ed25519)
    if isinstance(pub, ed25519.Ed25519PublicKey):
        x = pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        return {"kty": "OKP", "crv": "Ed25519", "x": _b64url(x)}

    raise ValueError("Unsupported key type for JWK")

def _jwk_thumbprint_sha256(jwk: Dict[str, str]) -> str:
    # 按 RFC 7638 固定字段、字典序 JSON、SHA-256，再 base64url
    kty = jwk["kty"]
    if kty == "RSA":
        obj = {"e": jwk["e"], "kty": "RSA", "n": jwk["n"]}
    elif kty == "EC":
        obj = {"crv": jwk["crv"], "kty": "EC", "x": jwk["x"], "y": jwk["y"]}
    elif kty == "OKP":
        obj = {"crv": jwk["crv"], "kty": "OKP", "x": jwk["x"]}
    else:
        raise ValueError("Unsupported kty")
    data = json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return _b64url(hashlib.sha256(data).digest())

def kid_from_public_pem(public_pem: bytes) -> str:
    pub = serialization.load_pem_public_key(public_pem)
    jwk = _public_key_to_jwk(pub)
    return _jwk_thumbprint_sha256(jwk)


@dataclass
class KeyPair:
    private_pem: bytes 
    public_pem: bytes
    curve_name: Optional[str] = None 
    kid: Optional[str] = None

def generate_keypair(alg: JWTAlgorithm, rsa_bits: int = 2048) -> KeyPair:
    """
    generate key pair according to the applied algorithm (without password) 
    ES256 -> P-256，ES256K -> secp256k1，ES384 -> P-384，ES512 -> P-521，EdDSA -> Ed25519。
    """
    if alg == JWTAlgorithm.RS256:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=rsa_bits)
        public_key = private_key.public_key()
        curve_name = None

    elif alg == JWTAlgorithm.ES256:
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()
        curve_name = "P-256"

    elif alg == JWTAlgorithm.ES256K:
        #  cryptography >= 2.5
        private_key = ec.generate_private_key(ec.SECP256K1())
        public_key = private_key.public_key()
        curve_name = "secp256k1"

    elif alg == JWTAlgorithm.ES384:
        private_key = ec.generate_private_key(ec.SECP384R1())
        public_key = private_key.public_key()
        curve_name = "P-384"

    elif alg == JWTAlgorithm.ES512:
        # Using P-521 curve 
        private_key = ec.generate_private_key(ec.SECP521R1())
        public_key = private_key.public_key()
        curve_name = "P-521"

    elif alg == JWTAlgorithm.EdDSA:
        # Using ed25519 
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        curve_name = "Ed25519"

    else:
        raise NotImplementedError(f"Unsupported alg: {alg}")

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    kp = KeyPair(
        private_pem=private_pem, 
        public_pem=public_pem, 
        curve_name=curve_name,
        kid=kid_from_public_pem(public_pem)
        )

    return kp 

class JsonWebToken(BaseModel):
    """Represents a JSON Web Token (JWT) Object."""
    
    model_config = ConfigDict(arbitrary_types_allowed=True)
    _keypair: Optional[KeyPair] = PrivateAttr(default=None)


    # Header 
    alg: JWTAlgorithm
    typ: str = "JWT"
    kid: Optional[str] = None

    # Payload 
    exp: Optional[datetime] = None
    iat: Optional[datetime] = None
    jti: Optional[str] = Field(default_factory=lambda: str(uuid.uuid4()))
    iss: Optional[str] = None
    aud: Optional[str] = None
    sub: Optional[str] = None
    nbf: Optional[datetime] = None
    azp: Optional[str] = None
    scope: Optional[str] = None
    custom_attributes: List[Attribute] = Field(default_factory=list)

    # Signature 
    signature: Optional[str] = None

    jwt: Optional[str] = None 

    # DIDL Assertion object 
    didl_assertion: Optional[Assertion] = Field(default=None, init=False)


    @field_validator("exp", "iat", "nbf", mode="before")
    def _ensure_datetime_utc(cls, v):
        from datetime import datetime, timezone
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
        # automatically generate a signature                  
        if not self.signature:
            print(f"Signature not provided, generating new key pair ({self.alg.value}) and signing JWT...")
            if not isinstance(self.alg, JWTAlgorithm):
                raise ValueError("Algorithm not defined or invalid")
            self._keypair = generate_keypair(self.alg)
            if not self.kid:
                self.kid = self._keypair.kid 

            self.jwt = self.sign_jwt(
                payload=self.to_jwt_payload_dict(),
                private_pem=self._keypair.private_pem.decode(),
                alg=self.alg,
                headers=self.to_jwt_header_dict()
            )
            _, _, self.signature = self.jwt.split(".")
        else:
            h64, p64 = self._encode_header_payload()
            self.jwt = f"{h64}.{p64}.{self.signature}"
        self.generate_didl(proof_type=ProofType.DataIntegrityProof)

    def _encode_header_payload(self) -> tuple[str, str]:
        header = self.to_jwt_header_dict()
        payload = self.to_jwt_payload_dict()
        h_json = json.dumps(header, separators=(",", ":"), sort_keys=False).encode("utf-8")
        p_json = json.dumps(payload, separators=(",", ":"), sort_keys=False).encode("utf-8")
        return _b64url(h_json), _b64url(p_json)
    
    def generate_didl(self, proof_type: Optional[ProofType] = None) -> None:
        """
        Generate the DIDL assertion object from the JWT data.
        """
        # 使用映射字典处理元数据
        metadata = self._extract_metadata_from_mapping()

        # Generate the relatesTo object
        relatesTo = Identifier(uid=self.sub, identifierFormat=IdentifierFormat.UUIDv4)
        
        # Map JWT claims to DIDL Attribute objects
        assertedAttribute = self._map_jwt_claims_to_attributes()
        
        # Generate the DIDL assertion object
        self.didl_assertion = Assertion(
            uid=metadata.get("uid", self.jti),
            issuer=metadata.get("issuer"),
            issueDate=metadata.get("issueDate"),
            validFrom=metadata.get("validFrom"),
            validTo=metadata.get("validTo"),
            relatesTo=relatesTo,
            assertedAttribute=assertedAttribute,
            assertionFormat=AssertionFormat.JsonWebToken,
            status=Status.NOTAVAILABLE
        )
        if proof_type == ProofType.DataIntegrityProof:
            # Generate the DID Linking Proof object
            proof = DataIntegrityProof(
                type=ProofType.DataIntegrityProof,
                proof_purpose=ProofPurpose.assertionMethod,
                proof_value="",
                verification_method=self.kid or "",
                cryptographic_suite=DataIntegritySuite.eddsa_rdfc_2022,
                created=datetime.now(timezone.utc)
            )

        elif proof_type == ProofType.Ed25519Signature2020:
            proof = Ed25519Signature2020(
                type=ProofType.Ed25519Signature2020,
                proof_purpose=ProofPurpose.assertionMethod,
                proof_value="",
                verification_method=self.kid or "",
                created=datetime.now(timezone.utc)
            )
        else:
            raise NotImplementedError("Not implemented proof type")
        
        # Generate a new ED25519 keypair
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
        
        print("DEBUG proof dump:", self.didl_assertion.proof.model_dump(by_alias=True, exclude_none=True))

    def _map_jwt_claims_to_attributes(self) -> List[Attribute]:
        """Maps JWT claims to DIDL Attribute objects using the mapping configuration."""
        attributes = []
        # 使用tuple映射处理属性
        for jwt_field, didl_key in JWT_DIDL_ATTRIBUTE_MAPPINGS:
            value = getattr(self, jwt_field, None)
            if value is not None:
                # 应用特殊处理逻辑
                processed_value = self._apply_special_mapping(jwt_field, value)
                if processed_value is not None:
                        attributes.append(Attribute(key=didl_key, value=str(processed_value)))
        
        # 添加自定义属性
        attributes.extend(self.custom_attributes)
        return attributes
    
    def _apply_special_mapping(self, field_name: str, value: Any) -> Any:
        """应用特殊映射逻辑"""
        if field_name not in JWT_SPECIAL_MAPPING:
            return value
        
        mapping_config = JWT_SPECIAL_MAPPING[field_name]
        mapping_type = mapping_config["type"]
        
        if mapping_type == "timestamp_to_string":
            return self._convert_timestamp_to_string(value)
        elif mapping_type == "scope_to_attributes":
            return self._convert_scope_to_attributes(value)
        elif mapping_type == "audience_to_scope":
            return value
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
    
    def _convert_scope_to_attributes(self, value: Any) -> List[str]:
        """将scope转换为属性列表"""
        if isinstance(value, str):
            return [f"{s}" for s in value.split()]
        elif isinstance(value, list):
            return [f"{s}" for s in value]
        else:
            return [f"{value}"]

    def _extract_metadata_from_mapping(self) -> Dict[str, Any]:
        """从映射字典中提取元数据"""
        metadata = {}
        
        for jwt_field, didl_field in JWT_DIDL_METADATA_MAPPINGS:
            value = getattr(self, jwt_field, None)
            if value is not None:
                metadata[didl_field] = value  # 保持原始值用于DIDL
        
        return metadata
    
    @classmethod
    def sign_jwt(cls, payload: dict, private_pem: bytes, alg: JWTAlgorithm, headers: Optional[dict] = None) -> str:
        """
        using python-jose sign JWT
        """
        headers = headers or {}
        try:
            return jwt.encode(payload, private_pem, algorithm=alg.value, headers=headers)
        except Exception as e:
            raise RuntimeError(
                f"Failed to sign with {alg.value}. "
                f"Check you installed python-jose with the cryptography backend: "
                f'pip install "python-jose[cryptography]". Original error: {e}'
            )

    @classmethod
    def verify_jwt(cls, token: str, public_pem: bytes, alg: JWTAlgorithm, audience: Optional[str] = None) -> dict:
        """
        验证 JWT，强制限定 algorithms 以避免算法混淆类问题。
        """
        options = {"verify_aud": audience is not None}
        return jwt.decode(
            token,
            public_pem,
            algorithms=[alg.value],  
            audience=audience,
            options=options,
        )
    
    def to_jwt_header_dict(self) -> Dict[str, Any]:
        jwt_dict = {
            "alg": self.alg.value,
            "typ": self.typ,
        }
        if self.kid: 
            jwt_dict["kid"] = self.kid
        return jwt_dict 
    
    def to_jwt_payload_dict(self):
        payload = {
            "exp": _to_unix_timestamp(self.exp),
            "iat": _to_unix_timestamp(self.iat),
            "jti": self.jti,
            "iss": self.iss,
            "aud": self.aud,
            "sub": self.sub,
            "nbf": _to_unix_timestamp(self.nbf),
            "azp": self.azp,
            "scope": self.scope,
        }
        # 使用tuple映射处理自定义属性
        for attr in self.custom_attributes:
            # 查找预定义的映射
            jwt_field = None
            for jwt_name, didl_key in JWT_DIDL_ATTRIBUTE_MAPPINGS:
                if attr.key == didl_key:
                    jwt_field = jwt_name
                    break
            if jwt_field:
                # 使用映射的JWT字段名
                payload[jwt_field] = attr.value
            #else:
                # 对于没有预定义映射的属性，使用key的value作为字段名
            #    if hasattr(attr.key, 'value'):
            #        field_name = attr.key.value
            #    else:
            #        field_name = str(attr.key)
            #
            #    if field_name not in payload:
            #        payload[field_name] = attr.value
            #    else:
                    # 如果冲突，添加前缀避免覆盖
            #        payload[f"custom_{field_name}"] = attr.value
        return {k: v for k, v in payload.items() if v is not None}
    
    @classmethod
    def from_jwt_dict(cls, data: Dict[str, Any]):
        """Converts a JWT claims dictionary to a JsonWebToken object."""
        raw_alg = data.pop("alg")
        try:
            alg = JWTAlgorithm(raw_alg)
        except ValueError:
            raise ValueError(f"Invalid algorithm: {raw_alg}")
        
        typ = data.pop("typ", "JWT")
        kid = data.pop("kid", None)

        exp = _from_unix_timestamp(data.pop("exp", None))
        iat = _from_unix_timestamp(data.pop("iat", None))
        nbf = _from_unix_timestamp(data.pop("nbf", None))

        standard_claims = {
            "jti": data.pop("jti", None),
            "iss": data.pop("iss", None),
            "aud": data.pop("aud", None),
            "sub": data.pop("sub", None),
            "azp": data.pop("azp", None),
            "scope": data.pop("scope", None),
        }
        custom_attrs = []
        for k, v in data.items():
            for jwt_field, didl_key in JWT_DIDL_ATTRIBUTE_MAPPINGS:
                if k == jwt_field:
                    custom_attrs.append(
                        Attribute(
                            key=Key(didl_key),
                            value=str(v)
                        )
                    )
                    break

        return cls(
            alg=alg, typ=typ, kid=kid,
            exp=exp, iat=iat, nbf=nbf,
            custom_attributes=custom_attrs,
            **standard_claims
        )

    def to_didl_dict(self) -> Dict[str, Any]:
        """Converts the JsonWebToken object to a DIDL Assertion dictionary."""
        #didl_dict = self.model_dump(
        #    exclude={"alg","typ","kid","exp","iat","jti","iss","aud","sub","nbf","azp","scope","custom_attributes","signature","jwt"},
        #    exclude_none=True,
        #)
        #return json.loads(json.dumps(didl_dict, cls=CustomJSONEncoder))
        
        return json.loads(json.dumps(self.didl_assertion.to_json(), cls=CustomJSONEncoder))

    @classmethod
    def from_didl_dict(cls, data: Dict[str, Any]):
        """Converts a DIDL Assertion dictionary to a JsonWebToken object."""
        didl_assertion = Assertion.from_json(data)
        jwt_claims = {}
        jwt_claims["jti"] = didl_assertion.uid
        #jwt_claims["iss"] = didl_assertion.issuer
        #jwt_claims["iat"] = didl_assertion.issueDate
        #jwt_claims["nbf"] = didl_assertion.validFrom
        #jwt_claims["exp"] = didl_assertion.validTo
        jwt_claims["sub"] = didl_assertion.relatesTo.uid
        return cls(
            alg=JWTAlgorithm.RS256, typ="JWT", 
            custom_attributes=didl_assertion.assertedAttribute,
            **jwt_claims
        )