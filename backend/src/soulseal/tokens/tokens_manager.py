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

from ..models import Result
from .token_models import (
    TokenType, TokenClaims, TokenResult,
    JWT_SECRET_KEY, JWT_ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES, REFRESH_TOKEN_EXPIRE_DAYS
)
from .token_sdk import TokenSDK

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
    """令牌管理器，负责刷新令牌的持久化管理和访问令牌的黑名单管理
    
    TokensManager主要用于主服务，负责：
    1. 持久化存储刷新令牌（使用RocksDB）
    2. 管理访问令牌黑名单（使用TokenBlacklist）
    3. 创建、验证、续订和刷新访问令牌
    
    与TokenSDK的关系：
    - TokensManager内部会创建一个本地模式的TokenSDK实例
    - TokenSDK使用TokensManager提供的方法管理刷新令牌和黑名单
    - 这形成了一种协作关系，TokensManager管理持久化存储，TokenSDK处理令牌验证和管理逻辑
    
    使用场景：
    - 主要用于主服务，负责所有令牌的集中管理
    - 同进程的子服务可以直接使用主服务的TokensManager实例
    - 独立进程的子服务应通过API与主服务通信，而不是直接使用TokensManager
    """
    
    def __init__(self, db: IndexedRocksDB, token_blacklist = None, token_storage_method: str = "cookie"):
        """初始化令牌管理器

        创建一个TokensManager实例，用于管理令牌的生命周期。
        
        Args:
            db: RocksDB实例，用于持久化存储刷新令牌
            token_blacklist: 令牌黑名单实例，如果不提供则会创建一个新的
            token_storage_method: 令牌存储方式，cookie或header，默认为cookie

        刷新令牌持久化保存在RocksDB中，访问令牌保存在内存中。
        刷新令牌在用户登录时颁发，访问令牌在用户每次授权请求时验证，
        如果缺少合法的访问令牌就使用刷新令牌重新颁发。
        """

        self._logger = logging.getLogger(__name__)

        # 刷新令牌持久化保存在数据库中
        self._cache = CachedRocksDB(db)

        # TokenBlacklist可以通过参数传入，便于共享和测试
        self._token_blacklist = token_blacklist or TokenBlacklist()
        
        # 令牌存储方式
        self.token_storage_method = token_storage_method
        
    def get_refresh_token(self, user_id: str, device_id: str) -> str:
        """获取刷新令牌
        
        从数据库中获取用户特定设备的刷新令牌。
        
        Args:
            user_id: 用户ID
            device_id: 设备ID
            
        Returns:
            str: JWT格式的刷新令牌，如果不存在则返回None
        """
        token_key = TokenClaims.get_refresh_token_key(user_id, device_id)
        token_claims = self._cache.get(token_key)
        if token_claims:
            return token_claims.jwt_encode()
        return None
    
    def update_refresh_token(self, user_id: str, username: str, roles: List[str], device_id: str) -> TokenClaims:
        """保存刷新令牌到数据库
        
        创建新的刷新令牌并保存到数据库中。
        通常在用户登录时调用。
        
        Args:
            user_id: 用户ID
            username: 用户名
            roles: 用户角色列表
            device_id: 设备ID
            
        Returns:
            TokenClaims: 创建的刷新令牌对象
        """
        # 创建刷新令牌
        claims = TokenClaims.create_refresh_token(user_id, username, roles, device_id)

        # 保存刷新令牌到数据库
        token_key = TokenClaims.get_refresh_token_key(user_id, device_id)
        self._cache.put(token_key, claims)

        self._logger.info(f"已更新刷新令牌: {claims}")
        return claims
    
    def revoke_refresh_token(self, user_id: str, device_id: str) -> None:
        """撤销数据库中的刷新令牌
        
        将刷新令牌标记为已撤销（通过将过期时间设置为创建时间）。
        通常在用户注销或更改密码时调用。
        
        Args:
            user_id: 用户ID
            device_id: 设备ID
        """
        token_key = TokenClaims.get_refresh_token_key(user_id, device_id)
        claims = self._cache.get(token_key)
        if claims:
            claims.revoke()
            self._cache.put(token_key, claims)
            self._logger.info(f"刷新令牌已撤销: {token_key}")
    
    def refresh_access_token(self, user_id: str, username: str, roles: List[str], device_id: str) -> Result[Dict[str, Any]]:
        """使用刷新令牌创建新的访问令牌
        
        当访问令牌过期时，使用用户的刷新令牌来创建新的访问令牌。
        此方法由TokenSDK在本地模式下调用，用于自动刷新过期的访问令牌。
        
        Args:
            user_id: 用户ID
            username: 用户名
            roles: 用户角色列表
            device_id: 设备ID
            
        Returns:
            Result: 刷新结果，包含新的访问令牌或错误信息
        """
        # 获取刷新令牌
        refresh_token = self.get_refresh_token(user_id, device_id)
        if not refresh_token:
            self._logger.warning(f"刷新令牌不存在: {user_id}:{device_id}")
            return Result.fail("刷新令牌不存在")
        
        try:
            # 验证刷新令牌
            refresh_data = jwt.decode(
                refresh_token,
                key=JWT_SECRET_KEY,
                algorithms=[JWT_ALGORITHM]
            )
            
            # 检查令牌类型
            if refresh_data.get("token_type") != TokenType.REFRESH:
                self._logger.warning(f"无效的刷新令牌类型: {refresh_data.get('token_type')}")
                return Result.fail("无效的刷新令牌类型")
            
            # 创建新的访问令牌
            claims = TokenClaims.create_access_token(user_id, username, roles, device_id)
            access_token = claims.jwt_encode()
            
            self._logger.info(f"已刷新访问令牌: {user_id}")
            return Result.ok(
                data={
                    "access_token": access_token,
                    **jwt.decode(
                        access_token,
                        key=JWT_SECRET_KEY,
                        algorithms=[JWT_ALGORITHM],
                        options={'verify_exp': False}
                    )
                },
                message="访问令牌刷新成功"
            )
            
        except jwt.ExpiredSignatureError:
            self._logger.warning(f"刷新令牌已过期: {user_id}")
            return Result.fail("刷新令牌已过期")
        except Exception as e:
            self._logger.error(f"刷新访问令牌失败: {str(e)}")
            return Result.fail(f"刷新访问令牌失败: {str(e)}")
    
    def renew_access_token(self, user_id: str, username: str, roles: List[str], device_id: str) -> Result[Dict[str, Any]]:
        """续订尚未过期但即将到期的访问令牌
        
        与refresh_access_token不同，renew_access_token用于令牌尚未过期但即将到期的情况，
        不需要验证刷新令牌，直接创建新的访问令牌。
        
        Args:
            user_id: 用户ID
            username: 用户名
            roles: 用户角色列表
            device_id: 设备ID
            
        Returns:
            Result: 续订结果，包含新的访问令牌或错误信息
        """
        try:
            # 创建新的访问令牌
            claims = TokenClaims.create_access_token(user_id, username, roles, device_id)
            access_token = claims.jwt_encode()
            
            self._logger.info(f"已续订访问令牌: {user_id}")
            return Result.ok(
                data={
                    "access_token": access_token,
                    **jwt.decode(
                        access_token,
                        key=JWT_SECRET_KEY,
                        algorithms=[JWT_ALGORITHM],
                        options={'verify_exp': False}
                    )
                },
                message="访问令牌续订成功"
            )
            
        except Exception as e:
            self._logger.error(f"续订访问令牌失败: {str(e)}")
            return Result.fail(f"续订访问令牌失败: {str(e)}")
    
    def revoke_access_token(self, user_id: str, device_id: str) -> None:
        """撤销访问令牌
        
        将访问令牌加入黑名单，使其不再有效。
        通常在用户注销或更改密码时调用。
        
        Args:
            user_id: 用户ID
            device_id: 设备ID
        """
        token_id = f"{user_id}:{device_id}"
        expires_at = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
        self._token_blacklist.add(token_id, expires_at)
        self._logger.info(f"访问令牌已撤销并加入黑名单: {token_id}")
        
        # 同时撤销刷新令牌
        self.revoke_refresh_token(user_id, device_id)

class TokenBlacklist:
    """基于内存的令牌黑名单
    
    用于存储被撤销的访问令牌，防止它们被再次使用。
    黑名单条目会自动过期，避免无限增长。
    
    通常由TokensManager创建和管理，与TokenSDK协作使用。
    """
    
    def __init__(self):
        """初始化黑名单
        
        创建一个空的黑名单，并设置清理间隔。
        """
        self._blacklist = {}  # {token_id: 过期时间}
        self._logger = logging.getLogger(__name__)
        self._last_cleanup = datetime.utcnow()
        self._cleanup_interval = timedelta(minutes=5)  # 每5分钟清理一次
    
    def add(self, token_id: str, expires_at: datetime) -> None:
        """将令牌加入黑名单，并自动清理过期条目
        
        Args:
            token_id: 令牌ID，通常是user_id:device_id的格式
            expires_at: 黑名单过期时间
        """
        self._blacklist[token_id] = expires_at
        self._logger.info(f"令牌已加入黑名单: {token_id}, 过期时间: {expires_at}")
        
        # 检查是否需要清理
        now = datetime.utcnow()
        if now - self._last_cleanup > self._cleanup_interval:
            self._cleanup()
            self._last_cleanup = now
    
    def contains(self, token_id: str) -> bool:
        """检查令牌是否在黑名单中
        
        如果令牌已过期，会自动从黑名单中移除。
        
        Args:
            token_id: 令牌ID，通常是user_id:device_id的格式
            
        Returns:
            bool: 是否在黑名单中
        """
        if token_id in self._blacklist:
            # 检查是否已过期
            if datetime.utcnow() > self._blacklist[token_id]:
                del self._blacklist[token_id]
                return False
            return True
        return False
    
    def _cleanup(self) -> None:
        """清理过期的黑名单条目
        
        定期清理过期的黑名单条目，避免黑名单无限增长。
        """
        now = datetime.utcnow()
        expired_keys = [k for k, v in self._blacklist.items() if now > v]
        
        if expired_keys:
            for k in expired_keys:
                del self._blacklist[k]
            self._logger.info(f"已清理 {len(expired_keys)} 个过期的黑名单条目")