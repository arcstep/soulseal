from typing import Dict, Any, Optional, Union, List, Tuple, Self
from datetime import datetime, timedelta, timezone
from fastapi import Response
from pathlib import Path
from calendar import timegm
from enum import Enum
from pydantic import BaseModel, Field, ConfigDict
from voidring import IndexedRocksDB, CachedRocksDB

import os
import jwt
import logging
import uuid

from .models import Result
from .token_sdk import TokenSDK, TokenClaims, TokenType, Result

__JWT_SECRET_KEY__ = os.getenv("FASTAPI_SECRET_KEY", "MY-SECRET-KEY")
__JWT_ALGORITHM__ = os.getenv("FASTAPI_ALGORITHM", "HS256")
__ACCESS_TOKEN_EXPIRE_MINUTES__ = int(os.getenv("FASTAPI_ACCESS_TOKEN_EXPIRE_MINUTES", 5))
__REFRESH_TOKEN_EXPIRE_DAYS__ = int(os.getenv("FASTAPI_REFRESH_TOKEN_EXPIRE_DAYS", 30))

class TokenType(str, Enum):
    """令牌类型"""
    ACCESS = "access"
    REFRESH = "refresh"

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
        return cls(
            token_type=TokenType.REFRESH,
            user_id=user_id,
            username=username,
            roles=roles,
            device_id=device_id,
            exp=datetime.utcnow() + timedelta(days=__REFRESH_TOKEN_EXPIRE_DAYS__)
        )

    @classmethod
    def create_access_token(cls, user_id: str, username: str, roles: List[str], device_id: str = None, **kwargs) -> Self:
        """创建访问令牌"""
        return cls(
            token_type=TokenType.ACCESS,
            user_id=user_id,
            username=username,
            roles=roles,
            device_id=device_id,
            exp=datetime.utcnow() + timedelta(minutes=__ACCESS_TOKEN_EXPIRE_MINUTES__)
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
            key=__JWT_SECRET_KEY__,
            algorithm=__JWT_ALGORITHM__
        )

class TokensManager:
    """令牌管理器，使用TokenSDK处理访问令牌验证和白名单管理"""
    
    def __init__(self, db: IndexedRocksDB, token_blacklist = None):
        """初始化认证管理器

        刷新令牌持久化保存在 rocksdb 中，访问令牌保存在内存中。
        刷新令牌应当在用户登录时颁发，访问令牌应当在用户每次授权请求时验证，如果缺少合法的访问令牌就使用刷新令牌重新颁发；
        """

        self._logger = logging.getLogger(__name__)

        # 刷新令牌持久化保存在数据库中
        self._cache = CachedRocksDB(db)

        # 初始化令牌SDK
        self._token_sdk = TokenSDK(
            jwt_secret_key=__JWT_SECRET_KEY__,
            jwt_algorithm=__JWT_ALGORITHM__,
            access_token_expire_minutes=__ACCESS_TOKEN_EXPIRE_MINUTES__
        )

        # TokenBlacklist可以通过参数传入，便于共享和测试
        self._token_blacklist = token_blacklist
        
    def get_refresh_token(self, user_id: str, device_id: str) -> TokenClaims:
        """获取刷新令牌"""
        token_key = TokenClaims.get_refresh_token_key(user_id, device_id)
        token_claims = self._cache.get(token_key)
        if token_claims:
            return token_claims.jwt_encode()
        return None
    
    def update_refresh_token(self, user_id: str, username: str, roles: List[str], device_id: str) -> TokenClaims:
        """保存刷新令牌到数据库"""
        # 创建刷新令牌
        claims = TokenClaims.create_refresh_token(user_id, username, roles, device_id)

        # 保存刷新令牌到数据库
        token_key = TokenClaims.get_refresh_token_key(user_id, device_id)
        self._cache.put(token_key, claims)

        self._logger.info(f"已更新刷新令牌: {claims}")
        return claims
    
    def verify_access_token(self, token: str) -> Result[TokenClaims]:
        """验证 JWT 访问令牌，如果有必要就使用刷新令牌刷新"""
        result = self._token_sdk.verify_token(token)
        
        if result.is_fail() and "已过期" in result.error:
            # 尝试使用刷新令牌
            unverified = jwt.decode(
                token, key=None, 
                options={'verify_signature': False, 'verify_exp': False}
            )
            return self.refresh_access_token(
                user_id=unverified.get("user_id", None),
                username=unverified.get("username", None),
                roles=unverified.get("roles", None),
                device_id=unverified.get("device_id", None)
            )
        
        return result
    
    def refresh_access_token(self, user_id: str, username: str, roles: List["UserRole"], device_id: str) -> Result[str]:
        """使用 Refresh-Token 刷新令牌颁发新的 Access-Token"""

        try:
            refresh_token = self.get_refresh_token(user_id, device_id)
            if not refresh_token:
                return Result.fail("没有找到刷新令牌")

            self._logger.info(f"找到刷新令牌: {refresh_token}")
            
            # 验证刷新令牌
            jwt.decode(
                jwt=refresh_token,
                key=__JWT_SECRET_KEY__,
                algorithms=[__JWT_ALGORITHM__],
                options={
                    'verify_signature': True,
                    'verify_exp': True,
                    'require': ['exp', 'iat'],
                }
            )
            
            # 刷新访问令牌
            new_access_token = self._update_access_token(
                user_id,
                username,
                roles,
                device_id
            )
            self._logger.info(f"已重新颁发访问令牌: {new_access_token}")
            return Result.ok(data=new_access_token.model_dump(), message="访问令牌刷新成功")

        except jwt.ExpiredSignatureError as e:
            return Result.fail(f"令牌验证失败: {str(e)}")

        except Exception as e:
            return Result.fail(f"令牌验证错误: {str(e)}")

    def _update_access_token(self, user_id: str, username: str, roles: List[str], device_id: str) -> TokenClaims:
        """更新内存中的访问令牌"""
        token = self._token_sdk.create_and_register_token(user_id, username, roles, device_id)
        # 转换为TokenClaims对象返回...
        return TokenClaims(**jwt.decode(token, key=__JWT_SECRET_KEY__, algorithms=[__JWT_ALGORITHM__]))

    def revoke_refresh_token(self, user_id: str, device_id: str) -> None:
        """撤销数据库中的刷新令牌"""
        token_key = TokenClaims.get_refresh_token_key(user_id, device_id)
        claims = self._cache.get(token_key)
        if claims:
            claims.revoke()
            self._cache.put(token_key, claims)
            self._logger.info(f"刷新令牌已撤销: {token_key}")
    
    def revoke_access_token(self, user_id: str, device_id: str = None) -> None:
        """撤销访问令牌，加入黑名单"""
        token_id = f"{user_id}:{device_id}" if device_id else user_id
        # 默认一小时后过期
        exp = datetime.utcnow() + timedelta(hours=1)
        self._token_blacklist.add(token_id, exp)
        self._logger.info(f"访问令牌已加入黑名单: {token_id}")

class TokenBlacklist:
    """基于内存的令牌黑名单"""
    
    def __init__(self):
        self._blacklist = {}  # {token_id: 过期时间}
        self._logger = logging.getLogger(__name__)
        self._last_cleanup = datetime.utcnow()
        self._cleanup_interval = timedelta(minutes=5)  # 每5分钟清理一次
    
    def add(self, token_id: str, expires_at: datetime) -> None:
        """将令牌加入黑名单，并自动清理过期条目"""
        self._blacklist[token_id] = expires_at
        self._logger.info(f"令牌已加入黑名单: {token_id}, 过期时间: {expires_at}")
        
        # 检查是否需要清理
        now = datetime.utcnow()
        if now - self._last_cleanup > self._cleanup_interval:
            self._cleanup()
            self._last_cleanup = now
    
    def contains(self, token_id: str) -> bool:
        """检查令牌是否在黑名单中"""
        if token_id in self._blacklist:
            # 检查是否已过期
            if datetime.utcnow() > self._blacklist[token_id]:
                del self._blacklist[token_id]
                return False
            return True
        return False
    
    def _cleanup(self) -> None:
        """清理过期的黑名单条目"""
        now = datetime.utcnow()
        expired_keys = [k for k, v in self._blacklist.items() if now > v]
        
        if expired_keys:
            for k in expired_keys:
                del self._blacklist[k]
            self._logger.info(f"已清理 {len(expired_keys)} 个过期的黑名单条目")