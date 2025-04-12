"""
令牌模块共享模型

定义令牌相关的共享数据模型、类型和常量，
确保token_sdk.py和tokens.py之间的一致性。
"""

from typing import Dict, Any, Optional, Union, List, Tuple, TypeVar, Generic, Self
from datetime import datetime, timedelta
from enum import Enum
from pydantic import BaseModel, Field, ConfigDict
import os
import uuid
import jwt

# 从环境变量读取配置，确保在所有地方使用相同的配置
JWT_SECRET_KEY = os.getenv("FASTAPI_SECRET_KEY", "MY-SECRET-KEY")
JWT_ALGORITHM = os.getenv("FASTAPI_ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("FASTAPI_ACCESS_TOKEN_EXPIRE_MINUTES", 5))
REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("FASTAPI_REFRESH_TOKEN_EXPIRE_DAYS", 30))

# 令牌类型
class TokenType(str, Enum):
    """令牌类型"""
    ACCESS = "access"
    REFRESH = "refresh"

# 令牌声明基本模型
class TokenClaims(BaseModel):
    """令牌信息"""
    @classmethod
    def get_refresh_token_prefix(cls, user_id: str) -> str:
        """获取刷新令牌前缀"""
        return f"token-{user_id}-refresh"

    @classmethod
    def get_refresh_token_key(cls, user_id: str, device_id: str) -> str:
        """获取刷新令牌键"""
        return f"{cls.get_refresh_token_prefix(user_id)}:{device_id}"
    
    @classmethod
    def create_refresh_token(cls, user_id: str, username: str, roles: List[str], device_id: str = None, **kwargs) -> Self:
        """创建刷新令牌"""
        # 使用当前时间或kwargs中的iat
        iat = kwargs.get('iat', datetime.utcnow())
        # 使用默认过期时间或kwargs中的exp
        exp = kwargs.get('exp', iat + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS))
        
        return cls(
            token_type=TokenType.REFRESH,
            user_id=user_id,
            username=username,
            roles=roles,
            device_id=device_id,
            iat=iat,
            exp=exp
        )

    @classmethod
    def create_access_token(cls, user_id: str, username: str, roles: List[str], device_id: str = None, **kwargs) -> Self:
        """创建访问令牌"""
        # 使用当前时间或kwargs中的iat
        iat = kwargs.get('iat', datetime.utcnow())
        # 使用默认过期时间或kwargs中的exp
        exp = kwargs.get('exp', iat + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
        
        return cls(
            token_type=TokenType.ACCESS,
            user_id=user_id,
            username=username,
            roles=roles,
            device_id=device_id,
            iat=iat,
            exp=exp
        )

    model_config = ConfigDict(
        arbitrary_types_allowed=True,
        from_attributes=True
    )

    # 根据设备的令牌信息    
    token_type: TokenType = Field(..., description="令牌类型")
    device_id: str = Field(default_factory=lambda: f"device_{uuid.uuid4().hex[:8]}", description="设备ID")
    iat: datetime = Field(default_factory=datetime.utcnow, description="令牌创建时间")
    exp: datetime = Field(default_factory=datetime.utcnow, description="令牌过期时间")

    # 用户信息
    user_id: str = Field(..., description="用户唯一标识")
    username: str = Field(..., description="用户名")
    roles: List[str] = Field(..., description="用户角色列表")

    def revoke(self) -> Self:
        """撤销令牌"""
        self.exp = self.iat
        return self

    def jwt_encode(self) -> str:
        """将令牌信息转换为JWT令牌"""
        return jwt.encode(
            payload=self.model_dump(),
            key=JWT_SECRET_KEY,
            algorithm=JWT_ALGORITHM
        )

# 令牌操作结果类型定义
T = TypeVar('T')

class TokenResult(BaseModel, Generic[T]):
    """令牌操作结果"""
    @classmethod
    def ok(cls, data: Optional[T] = None, message: str = "操作成功") -> "TokenResult[T]":
        return cls(success=True, message=message, data=data)

    @classmethod
    def fail(cls, error: str, message: str = "操作失败") -> "TokenResult[T]":
        # 使用Python内置的logging，避免循环导入
        import logging
        logging.warning(f"操作失败: {error}")
        return cls(success=False, message=message, error=error)

    model_config = ConfigDict(
        arbitrary_types_allowed=True,
        from_attributes=True
    )
    
    success: bool
    message: Optional[str] = None
    error: Optional[str] = None
    data: Optional[T] = None

    def is_ok(self) -> bool:
        return self.success

    def is_fail(self) -> bool:
        return not self.success 