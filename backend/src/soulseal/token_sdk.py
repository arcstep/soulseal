from typing import Dict, Any, Optional, Union, List, Tuple, Self, TypeVar, Generic
from datetime import datetime, timedelta
from enum import Enum
from pydantic import BaseModel, Field, ConfigDict
import jwt
import logging
import os
import uuid

T = TypeVar('T')

class TokenType(str, Enum):
    """令牌类型"""
    ACCESS = "access"
    REFRESH = "refresh"

class Result(BaseModel, Generic[T]):
    """返回结果"""
    @classmethod
    def ok(cls, data: Optional[T] = None, message: str = "操作成功") -> "Result[T]":
        return cls(success=True, message=message, data=data)

    @classmethod
    def fail(cls, error: str, message: str = "操作失败") -> "Result[T]":
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

class TokenClaims(BaseModel):
    """令牌信息"""
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

class TokenSDK:
    """令牌验证和白名单管理SDK
    
    提供访问令牌验证和白名单管理功能，可被多个项目共享使用。
    """
    
    def __init__(self, 
                 jwt_secret_key: str = None, 
                 jwt_algorithm: str = "HS256",
                 access_token_expire_minutes: int = 5,
                 token_blacklist_storage = None,
                 blacklist_verify_url: str = None):
        """初始化令牌SDK
        
        Args:
            jwt_secret_key: JWT密钥，如果不提供则从环境变量FASTAPI_SECRET_KEY获取
            jwt_algorithm: JWT算法，默认HS256
            access_token_expire_minutes: 访问令牌有效期(分钟)
            token_blacklist_storage: 黑名单存储，可以是Redis或其他分布式存储
            blacklist_verify_url: 远程黑名单验证服务URL，如果提供则使用远程验证
        """
        self._logger = logging.getLogger(__name__)
        self._jwt_secret_key = jwt_secret_key or os.getenv("FASTAPI_SECRET_KEY", "MY-SECRET-KEY")
        self._jwt_algorithm = jwt_algorithm
        self._access_token_expire_minutes = access_token_expire_minutes
        
        # 黑名单存储，可以是本地或远程
        self._token_blacklist = token_blacklist_storage or {}
        self._blacklist_verify_url = blacklist_verify_url
        
        # 如果提供了验证URL，需要添加requests库依赖
        if self._blacklist_verify_url:
            try:
                import requests
                self._requests = requests
            except ImportError:
                self._logger.warning("提供了blacklist_verify_url但未安装requests库，将使用本地黑名单")
                self._blacklist_verify_url = None

    @classmethod
    def create_access_token(cls, user_id: str, username: str, roles: List[str], device_id: str = None, 
                           jwt_secret_key: str = None, jwt_algorithm: str = "HS256", 
                           expire_minutes: int = 5) -> str:
        """创建新的访问令牌（无需实例化SDK）"""
        if not device_id:
            device_id = f"device_{uuid.uuid4().hex[:8]}"
            
        payload = {
            "token_type": TokenType.ACCESS,
            "user_id": user_id,
            "username": username,
            "roles": roles,
            "device_id": device_id,
            "iat": datetime.utcnow(),
            "exp": datetime.utcnow() + timedelta(minutes=expire_minutes)
        }
        
        secret_key = jwt_secret_key or os.getenv("FASTAPI_SECRET_KEY", "MY-SECRET-KEY")
        
        return jwt.encode(
            payload=payload,
            key=secret_key,
            algorithm=jwt_algorithm
        )

    def create_and_register_token(self, user_id: str, username: str, roles: List[str], device_id: str = None) -> str:
        """创建并注册访问令牌到白名单"""
        if not device_id:
            device_id = f"device_{uuid.uuid4().hex[:8]}"
            
        # 创建令牌声明
        claims = TokenClaims(
            token_type=TokenType.ACCESS,
            user_id=user_id,
            username=username,
            roles=roles,
            device_id=device_id,
            iat=datetime.utcnow(),
            exp=datetime.utcnow() + timedelta(minutes=self._access_token_expire_minutes)
        )
        
        # 直接返回JWT编码的令牌，不再添加到白名单
        return jwt.encode(
            payload=claims.model_dump(),
            key=self._jwt_secret_key,
            algorithm=self._jwt_algorithm
        )

    def verify_token(self, token: str) -> Result[Dict[str, Any]]:
        """验证JWT访问令牌有效性（只检查黑名单）"""
        try:
            # 解析但不验证签名获取必要信息
            unverified = jwt.decode(
                token, key=None,
                options={'verify_signature': False, 'verify_exp': False}
            )
            
            user_id = unverified.get("user_id")
            device_id = unverified.get("device_id")
            
            # 只检查是否在黑名单中
            if self.is_blacklisted(user_id, device_id):
                return Result.fail("令牌已被撤销")
                
            # 验证签名和过期时间
            try:
                valid_data = jwt.decode(
                    token,
                    key=self._jwt_secret_key,
                    algorithms=[self._jwt_algorithm],
                    options={'verify_signature': True, 'verify_exp': True}
                )
                return Result.ok(data=valid_data)
                
            except jwt.ExpiredSignatureError:
                return Result.fail("访问令牌已过期")
                
            except Exception as e:
                return Result.fail(f"令牌验证错误: {str(e)}")
                
        except Exception as e:
            return Result.fail(f"令牌解析错误: {str(e)}")

    def revoke_token(self, token_id: str, expires_at: datetime) -> None:
        """将令牌加入黑名单"""
        self._token_blacklist[token_id] = expires_at
        self._logger.info(f"令牌已加入黑名单: {token_id}, 过期时间: {expires_at}")
        
        # 每5分钟自动清理过期条目
        now = datetime.utcnow()
        if not hasattr(self, '_last_cleanup') or now - self._last_cleanup > timedelta(minutes=5):
            self._last_cleanup = now
            self._cleanup()

    def is_blacklisted(self, user_id: str, device_id: str) -> bool:
        """检查令牌是否在黑名单中"""
        token_id = f"{user_id}:{device_id}"
        
        # 如果配置了远程验证URL，使用HTTP调用
        if self._blacklist_verify_url:
            try:
                response = self._requests.get(
                    f"{self._blacklist_verify_url}",
                    params={"user_id": user_id, "device_id": device_id},
                    timeout=2.0  # 设置超时避免阻塞
                )
                if response.status_code == 200:
                    return response.json().get("is_blacklisted", False)
                else:
                    self._logger.warning(f"黑名单验证服务返回错误: {response.status_code}")
                    # 远程调用失败时，回退到本地验证
            except Exception as e:
                self._logger.error(f"黑名单远程验证失败: {str(e)}")
                # 出现异常时，回退到本地验证
        
        # 本地验证
        return token_id in self._token_blacklist and datetime.utcnow() <= self._token_blacklist[token_id]
