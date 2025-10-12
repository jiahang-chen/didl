"""
DIDL Models Package

This package contains various assertion models that can be used with the DIDL framework.
Each model represents a different type of digital identity assertion format.
"""

from typing import List, Dict, Any, Optional
from datetime import datetime
from didl.base import Attribute, Key

class BaseModelMapper:
    """通用模型映射基类，提供标准的映射功能"""
    
    def __init__(self, mapping_config: Dict[str, Any], special_mapping: Dict[str, Any]):
        self.mapping_config = mapping_config
        self.special_mapping = special_mapping
    
    def map_attributes(self, model_instance) -> List[Attribute]:
        """映射模型属性到DIDL Attribute对象"""
        attributes = []
        
        # 使用映射字典处理属性
        for model_field, didl_key in self.mapping_config["attributes"].items():
            value = getattr(model_instance, model_field, None)
            if value is not None:
                # 应用特殊处理逻辑
                processed_value = self._apply_special_mapping(model_field, value)
                if processed_value is not None:
                    if isinstance(processed_value, list):
                        # 对于可能产生多个属性的字段
                        for item in processed_value:
                            attributes.append(Attribute(key=didl_key, value=str(item)))
                    else:
                        attributes.append(Attribute(key=didl_key, value=str(processed_value)))
        
        return attributes
    
    def extract_metadata(self, model_instance) -> Dict[str, Any]:
        """从模型实例中提取元数据"""
        metadata = {}
        
        for model_field, didl_field in self.mapping_config["metadata"].items():
            value = getattr(model_instance, model_field, None)
            if value is not None:
                metadata[didl_field] = value  # 保持原始值用于DIDL
        
        return metadata
    
    def _apply_special_mapping(self, field_name: str, value: Any) -> Any:
        """应用特殊映射逻辑"""
        if field_name not in self.special_mapping:
            return value
        
        mapping_config = self.special_mapping[field_name]
        mapping_type = mapping_config["type"]
        
        if mapping_type == "timestamp_to_string":
            return self._convert_timestamp_to_string(value)
        elif mapping_type == "enum_to_string":
            return self._convert_enum_to_string(value, mapping_config)
        elif mapping_type == "base64_encode":
            return self._convert_to_base64(value)
        elif mapping_type == "scope_to_attributes":
            return self._convert_scope_to_attributes(value)
        elif mapping_type == "audience_to_scope":
            return self._convert_audience_to_scope(value)
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
    
    def _convert_enum_to_string(self, value: Any, config: Dict[str, Any]) -> str:
        """将枚举值转换为字符串"""
        enum_class_name = config["enum_class"]
        separator = config.get("separator", ",")
        
        # 这里需要根据具体的枚举类来处理
        # 子类可以重写这个方法
        return str(value)
    
    def _convert_to_base64(self, value: Any) -> str:
        """转换为base64编码"""
        import base64
        if isinstance(value, bytes):
            return base64.b64encode(value).decode('utf-8')
        elif isinstance(value, str):
            # 如果已经是base64字符串，直接返回
            return value
        else:
            return str(value)
    
    def _convert_scope_to_attributes(self, value: Any) -> List[str]:
        """将scope转换为属性列表"""
        if isinstance(value, str):
            return [f"Scope:{s}" for s in value.split()]
        elif isinstance(value, list):
            return [f"Scope:{s}" for s in value]
        else:
            return [f"Scope:{value}"]
    
    def _convert_audience_to_scope(self, value: Any) -> str:
        """将audience转换为scope"""
        if isinstance(value, str):
            return f"Audience:{value}"
        elif isinstance(value, list):
            return f"Audience:{','.join(value)}"
        else:
            return f"Audience:{value}"
    
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

# 导出所有模型
from .kerberos import KerberosTicketModel
from .jwt import JsonWebToken
from .saml import SAML2Assertion

__all__ = [
    'BaseModelMapper',
    'KerberosTicketModel', 
    'JsonWebToken',
    'SAML2Assertion'
]

