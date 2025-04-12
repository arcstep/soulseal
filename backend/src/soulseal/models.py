"""
用户模块数据模型

定义用户相关的核心数据模型,包括用户角色和用户基础信息。
"""

from pydantic import BaseModel, Field, EmailStr, field_validator, constr, ConfigDict, model_validator, model_serializer
from argon2 import PasswordHasher
from typing import Optional, Dict, Any, List, Set, Union, Generic, TypeVar
from datetime import datetime, timedelta
from string import ascii_letters, digits
from enum import Enum

import re
import uuid
import secrets

import logging

logger = logging.getLogger(__name__)

T = TypeVar('T')

class Result(BaseModel, Generic[T]):
    """返回结果"""

    @classmethod
    def ok(cls, data: Optional[T] = None, message: str = "操作成功") -> "Result[T]":
        return cls(success=True, message=message, data=data)

    @classmethod
    def fail(cls, error: str, message: str = "操作失败") -> "Result[T]":
        logger.warning(f"操作失败: {error}")
        return cls(success=False, message=message, error=error)

    model_config = ConfigDict(
        arbitrary_types_allowed=True,  # 允许任意类型
        from_attributes=True,  # 允许从对象属性读取（原 orm_mode）
    )
    
    success: bool
    message: Optional[str] = None
    error: Optional[str] = None
    data: Optional[T] = None

    def is_ok(self) -> bool:
        return self.success

    def is_fail(self) -> bool:
        return not self.success
