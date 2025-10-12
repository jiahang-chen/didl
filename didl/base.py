from pydantic import BaseModel, Field, ConfigDict, field_validator
from typing import List, Optional, Dict, Any, Union, Annotated
from datetime import datetime
from didl.model import Status, AssertionFormat, IdentifierFormat, CredentialFormat, Key, ProofType 
from didl.proof import LinkedDataProof, DataIntegrityProof, Ed25519Signature2020
import json 
from didl.utils import CustomJSONEncoder

class Attribute(BaseModel):
    key: Key = Field(..., alias="didl:key")
    value: str = Field(..., alias="didl:value")

    model_config = ConfigDict(
        populate_by_name=True
    )

class IdentifierFunctional(BaseModel):
    pass    

class Identity(BaseModel):
    """A digital identity that can be specialized to identifiers, credentials, or assertions"""
    uid: str = Field(..., alias="@id")
    issuer: Optional[str] = Field(None, alias="didl:issuer") 
    issueDate: Optional[datetime] = Field(None, alias="didl:issueDate") 
    validFrom: Optional[datetime] = Field(None, alias="didl:validFrom") 
    renewableTill: Optional[datetime] = Field(None, alias="didl:RenewableTill") 
    validTo: Optional[datetime] = Field(None, alias="didl:validTo") 
    profile: Optional[str] = Field(None, alias="didl:profile") 
    status: Optional[Status] = Field(None, alias="didl:status") 

    # Default JSON-LD context and type for DIDL
    CONTEXT: Dict[str, Any] = Field(default_factory=lambda: {
        "@context": {
            "didl": "https://git.vcs.mmi.rwth-aachen.de/-/snippets/3/raw/main/didl.ttl#",
            "xsd": "http://www.w3.org/2001/XMLSchema#",
            "sec": "https://w3id.org/security#"
        }
    }, exclude=True)
    TYPE: str = Field("didl:Identity", exclude=True)

    model_config = ConfigDict(
        populate_by_name=True,
        arbitrary_types_allowed=True,
        extra="forbid") 

    
    @field_validator("issueDate", "validFrom", "validTo", mode="before")
    @classmethod
    def _jsonld_datetime(cls, v):
        if isinstance(v, dict) and "@value" in v:
            s = v["@value"]
            if isinstance(s, str):
                s = s.replace("Z", "+00:00")  
                return datetime.fromisoformat(s)
        return v
    
    @field_validator("status", mode="before")
    @classmethod 
    def _jsonld_status(cls, v):
        if isinstance(v, dict) and "@id" in v:
            return Status(v["@id"])
        return v 

    @classmethod
    def from_json(cls, data: Union[str, Dict[str, Any]]) -> "Identity":
        """
        Create an Identity object from a JSON string or dictionary.
        """
        if isinstance(data, str):
            raw = json.loads(data)
        else: 
            raw = data.copy()
        raw.pop("@context", None)
        raw.pop("@type", None)
        return cls.model_validate(raw)

    def to_json(self) -> Dict:
        body = self.model_dump(by_alias=True, exclude_none=True, mode="json")
        body["@type"] = self.TYPE
        jsonld = {**self.CONTEXT, **body}
        return jsonld 
        
class Identifier(Identity):
    identifierFormat: Optional[IdentifierFormat] = Field(None, alias="didl:identifierFormat")
    functional: Optional[IdentifierFunctional] = Field(None, alias="didl:functional")
    TYPE: str = Field("didl:IdentifierToken", exclude=True)

class CompositeIdentifier(Identifier):
    localPart: Identifier = Field(..., alias="didl:localPart")
    TYPE: str = Field("didl:CompositeIdentifier", exclude=True)

class Credential(Identity):
    """A collection of identity-related attributes that have been issued by a trusted party"""
    credentialFormat: Optional[CredentialFormat] = Field(None, alias="didl:credentialFormat")
    credentialAttribute: List[Attribute] = Field(default_factory=list, alias="didl:credentialAttribute")
    TYPE: str = Field("didl:Credential", exclude=True)

ProofUnion = Annotated[
    Union[DataIntegrityProof, Ed25519Signature2020],
    Field(discriminator="type")
]

class Assertion(Identity):
    assertionFormat: Optional[AssertionFormat] = Field(None, alias="didl:assertionFormat")
    assertedAttribute: List[Attribute] = Field(default_factory=list, alias="didl:assertedAttribute")
    relatesTo: Optional[Identifier] = Field(None, alias="didl:relatesTo")
    TYPE: str = Field("didl:Assertion", exclude=True)
    proof: Optional[ProofUnion] = Field(None, alias="sec:proof")

    @field_validator("assertedAttribute", mode="before")
    @classmethod
    def _jsonld_asserted_attribute(cls, v):
        if isinstance(v, list):
            return_list = []
            for attr in v:
                if isinstance(attr, Attribute):
                    return v
                _key = None
                _value = None
                for i in attr.keys():
                    if "key" in i:
                        _key = Key(attr[i])
                    elif "value" in i:
                        _value = attr[i]
                return_list.append(
                    Attribute(key=_key, value=_value)
                )
            return return_list
        return v


class AssertionCollection(Assertion):
    subAssertion: List[Assertion] = Field(default_factory=list, alias="didl:subAssertion")
    TYPE: str = Field("didl:AssertionCollection", exclude=True)