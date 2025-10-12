from abc import ABC, abstractmethod
from enum import Enum
from datetime import datetime, timezone
from pydantic import BaseModel, Field, ConfigDict
from typing import Union, Any, Literal
import base58
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from pyld import jsonld 
import json 
from didl.model import ProofType, ProofPurpose, DataIntegritySuite

class LinkedDataProof(ABC, BaseModel):
    type: ProofType 
    proof_purpose: ProofPurpose = Field(default=ProofPurpose.assertionMethod, alias="proofPurpose")
    proof_value: str = Field(default="", alias="proofValue")
    verification_method: str = Field(default="", alias="verificationMethod")
    created: datetime

    model_config = ConfigDict(
        use_enum_values=True,
        populate_by_name=True,  
        json_encoders={
            datetime: lambda v: v.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        },
    )

    @abstractmethod
    def sign(self, message: bytes, private_key: bytes) -> str:
        pass

    @abstractmethod
    def verify(self, message: bytes, signature: str, public_key: bytes) -> bool:
        pass

    def to_json(self, **json_kwargs: Any) -> str:
        """
        Serialize the proof to a JSON string using aliases and ISO8601 timestamps.
        Additional kwargs are passed to Pydantic's `.json()` method.
        """
        # by_alias and exclude_none ensure correct field names and omit None values
        return self.json(by_alias=True, exclude_none=True, **json_kwargs)

    @classmethod
    def from_json(cls, json_str: Union[str, bytes], **parse_kwargs: Any) -> "LinkedDataProof":
        """
        Parse a JSON string (or bytes) into a LinkedDataProof instance.

        - In Pydantic v2, `model_validate_json` is preferred: it
          directly performs a two-step process (JSON parsing + validation)
          and can be more performant and explicit about validation.

        Additional kwargs are passed to the underlying method.
        """
        # Pydantic v2: use model_validate_json if available
        if hasattr(cls, "model_validate_json"):
            return cls.model_validate_json(json_str, **parse_kwargs)  # type: ignore

class DataIntegrityProof(LinkedDataProof):
    type: Literal["DataIntegrityProof"] = Field(default="DataIntegrityProof")
    cryptographic_suite: DataIntegritySuite = Field(..., alias="cryptographicSuite")
    model_config = ConfigDict(populate_by_name=True, use_enum_values=True)

    def sign(self, message: bytes, private_key: bytes) -> str:
        if not isinstance(message, (bytes, bytearray)):
            raise RuntimeError('message must be bytes')
        if self.cryptographic_suite == DataIntegritySuite.eddsa_jcs_2022:

            message = message.decode('utf-8')
            doc_str = message if isinstance(message, str) else json.dumps(message, ensure_ascii=False)
            payload = json.dumps(json.loads(doc_str), separators=(',', ':'), sort_keys=True).encode('utf-8')

        elif self.cryptographic_suite == DataIntegritySuite.eddsa_rdfc_2022:
            normalized = jsonld.normalize(
                message,
                {
                    'format': 'application/n-quads',
                    'algorithm': 'URDNA2015',
                }
                )
            payload = normalized.encode('utf-8')   
        else:
            raise ValueError(f'Unsupported cryptographic suite {self.cryptographic_suite}')
        
        sk = Ed25519PrivateKey.from_private_bytes(private_key)
        sig = sk.sign(payload)
        proof = base58.b58encode(sig).decode('utf-8')
        self.proof_value = proof
        return proof


    def verify(self, message: Any, signature: str, public_key: bytes) -> bool:
        if not isinstance(message, (bytes, bytearray)):
            raise RuntimeError('message must be bytes')
        if self.cryptographic_suite == DataIntegritySuite.eddsa_jcs_2022:
            message = message.decode('utf-8')
            doc_str = message if isinstance(message, str) else json.dumps(message, ensure_ascii=False)
            payload = json.dumps(json.loads(doc_str), separators=(',', ':'), sort_keys=True).encode('utf-8')
        elif self.cryptographic_suite == DataIntegritySuite.eddsa_rdfc_2022:
            normalized = jsonld.normalize(
                message,
                {
                    'format': 'application/n-quads',
                    'algorithm': 'URDNA2015',
                }
            )
            payload = normalized.encode('utf-8')   

        else:
            raise ValueError(f'Unsupported cryptographic suite {self.cryptographic_suite}')
        
        pk = Ed25519PublicKey.from_public_bytes(public_key)
        sig_bytes = base58.b58decode(signature)
        try:
            pk.verify(sig_bytes, payload)
            return True
        except Exception:
            return False

class Ed25519Signature2020(LinkedDataProof):
    type: Literal["Ed25519Signature2020"] = Field(default="Ed25519Signature2020")
    model_config = ConfigDict(populate_by_name=True, use_enum_values=True)

    def sign(self, message: Any, private_key: bytes) -> str:
        # Normalize JSON for JCS: sort keys, no spaces
        if not isinstance(message, (bytes, bytearray)):
            message = json.dumps(message, separators=(',', ':'), sort_keys=True).encode('utf-8')
        sk = Ed25519PrivateKey.from_private_bytes(private_key)
        sig = sk.sign(message)
        proof = base58.b58encode(sig).decode('utf-8')
        self.proof_value = proof
        return proof

    def verify(self, message: bytes, signature: str, public_key: bytes) -> bool:
        if not isinstance(message, (bytes, bytearray)):
            message = json.dumps(message, separators=(',', ':'), sort_keys=True).encode('utf-8')
        pk = Ed25519PublicKey.from_public_bytes(public_key)
        sig_bytes = base58.b58decode(signature)
        try:
            pk.verify(sig_bytes, message)
            return True
        except Exception:
            return False
