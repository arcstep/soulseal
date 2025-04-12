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
    
    def __init__(self, db: IndexedRocksDB, token_blacklist = None):
        """初始化令牌管理器

        创建一个TokensManager实例，用于管理令牌的生命周期。
        
        Args:
            db: RocksDB实例，用于持久化存储刷新令牌
            token_blacklist: 令牌黑名单实例，如果不提供则会创建一个新的

        刷新令牌持久化保存在RocksDB中，访问令牌保存在内存中。
        刷新令牌在用户登录时颁发，访问令牌在用户每次授权请求时验证，
        如果缺少合法的访问令牌就使用刷新令牌重新颁发。
        """

        self._logger = logging.getLogger(__name__)

        # 刷新令牌持久化保存在数据库中
        self._cache = CachedRocksDB(db)

        # 初始化令牌SDK - 使用本地模式，将自身作为tokens_manager传入
        self._token_sdk = TokenSDK(
            jwt_secret_key=JWT_SECRET_KEY,
            jwt_algorithm=JWT_ALGORITHM,
            access_token_expire_minutes=ACCESS_TOKEN_EXPIRE_MINUTES,
            tokens_manager=self  # 将自身传递给TokenSDK
        )

        # TokenBlacklist可以通过参数传入，便于共享和测试
        self._token_blacklist = token_blacklist or TokenBlacklist()
        
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
    
    def create_refresh_token(self, user_id: str, username: str, roles: List[str], device_id: str) -> str:
        """创建刷新令牌
        
        创建新的刷新令牌并保存到数据库中，返回JWT格式的令牌。
        这是为了适配测试用例而添加的便捷方法。
        
        Args:
            user_id: 用户ID
            username: 用户名
            roles: 用户角色列表
            device_id: 设备ID
            
        Returns:
            str: JWT格式的刷新令牌
        """
        claims = self.update_refresh_token(user_id, username, roles, device_id)
        return claims.jwt_encode()

    def verify_access_token(self, token: str) -> Result[Dict[str, Any]]:
        """验证JWT访问令牌，如果有必要就使用刷新令牌刷新
        
        验证流程：
        1. 检查签名和有效期
        2. 如果令牌即将到期，自动续订
        3. 如果令牌已过期，尝试使用刷新令牌获取新的访问令牌
        
        这是主服务验证令牌的主要入口点。
        
        Args:
            token: JWT格式的访问令牌
            
        Returns:
            Result: 验证结果，包含令牌数据或错误信息
        """
        result = self._token_sdk.verify_token(token)
        
        # 验证成功，直接返回结果
        if result.is_ok():
            return result
        
        # 验证失败但错误不是过期，直接返回错误
        if result.is_fail() and "已过期" not in result.error:
            return result
            
        # 令牌已过期，尝试使用刷新令牌
        try:
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
        except Exception as e:
            return Result.fail(f"令牌解析错误: {str(e)}")
    
    def renew_access_token(self, user_id: str, username: str, roles: List[str], device_id: str) -> Result[Dict[str, Any]]:
        """续订访问令牌，在令牌即将过期时调用
        
        与refresh_access_token不同，此方法不需要验证刷新令牌，直接创建新的访问令牌。
        用于令牌即将过期但尚未过期的情况，提前续订可以避免令牌过期导致的用户体验问题。
        
        通常由TokenSDK自动调用，也可以由客户端主动调用相应的API端点。
        
        Args:
            user_id: 用户ID
            username: 用户名
            roles: 用户角色列表
            device_id: 设备ID
            
        Returns:
            Result: 续订结果，包含新令牌数据或错误信息
        """
        try:
            # 创建新的访问令牌
            new_access_token = self._update_access_token(
                user_id,
                username,
                roles,
                device_id
            )
            self._logger.info(f"已续订访问令牌: {new_access_token}")
            return Result.ok(data=new_access_token.model_dump(), message="访问令牌续订成功")
        except Exception as e:
            return Result.fail(f"续订访问令牌错误: {str(e)}")
    
    def refresh_access_token(self, user_id: str, username: str, roles: List[Any], device_id: str) -> Result[Dict[str, Any]]:
        """使用刷新令牌颁发新的访问令牌
        
        此方法用于在访问令牌过期后，使用刷新令牌获取新的访问令牌。
        需要先验证刷新令牌是否有效，然后才能颁发新的访问令牌。
        
        通常在令牌过期后由TokenSDK自动调用，也可以由客户端主动调用相应的API端点。
        
        Args:
            user_id: 用户ID
            username: 用户名
            roles: 用户角色列表
            device_id: 设备ID
            
        Returns:
            Result: 刷新结果，包含新令牌数据或错误信息
        """
        try:
            refresh_token = self.get_refresh_token(user_id, device_id)
            if not refresh_token:
                return Result.fail("没有找到刷新令牌")

            self._logger.info(f"找到刷新令牌: {refresh_token}")
            
            # 验证刷新令牌
            jwt.decode(
                jwt=refresh_token,
                key=JWT_SECRET_KEY,
                algorithms=[JWT_ALGORITHM],
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
        """创建新的访问令牌
        
        内部方法，用于创建新的访问令牌。
        
        Args:
            user_id: 用户ID
            username: 用户名
            roles: 用户角色列表
            device_id: 设备ID
            
        Returns:
            TokenClaims: 创建的访问令牌对象
        """
        token = self._token_sdk.create_token(user_id, username, roles, device_id)
        # 转换为TokenClaims对象返回
        return TokenClaims(**jwt.decode(token, key=JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM]))

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
    
    def revoke_access_token(self, user_id: str, device_id: str = None) -> None:
        """撤销访问令牌，加入黑名单
        
        将访问令牌加入黑名单，使其无法再被使用。
        通常在用户注销或更改密码时调用。
        
        Args:
            user_id: 用户ID
            device_id: 设备ID，如果不提供则撤销用户的所有设备
        """
        token_id = f"{user_id}:{device_id}" if device_id else user_id
        # 默认一小时后过期
        exp = datetime.utcnow() + timedelta(hours=1)
        self._token_blacklist.add(token_id, exp)
        self._logger.info(f"访问令牌已加入黑名单: {token_id}")
    
    def create_access_token(self, user_id: str, username: str, roles: List[str], device_id: str) -> Result[Dict[str, Any]]:
        """创建访问令牌
        
        创建新的访问令牌，返回JWT格式的令牌。
        这是为了适配测试用例而添加的便捷方法。
        
        Args:
            user_id: 用户ID
            username: 用户名
            roles: 用户角色列表
            device_id: 设备ID
            
        Returns:
            Result: 包含访问令牌的结果对象
        """
        try:
            # 创建新的访问令牌
            token_claims = self._update_access_token(user_id, username, roles, device_id)
            token = token_claims.jwt_encode()
            
            # 返回结果
            return Result.ok({
                "access_token": token,
                "token_type": "bearer"
            }, message="访问令牌创建成功")
        except Exception as e:
            return Result.fail(f"创建访问令牌失败: {str(e)}")
    
    # 以下是与请求/响应相关的令牌处理方法，封装了TokenSDK的方法
    
    def extract_token_from_request(self, request) -> Optional[str]:
        """从请求中提取令牌
        
        封装TokenSDK的同名方法。
        
        Args:
            request: HTTP请求对象
            
        Returns:
            Optional[str]: 提取到的令牌，如果没有找到则返回None
        """
        return self._token_sdk.extract_token_from_request(request)
    
    def set_token_to_response(self, response, token: str, token_type: str = "access", max_age: int = None) -> None:
        """将令牌设置到响应中
        
        封装TokenSDK的同名方法。
        
        Args:
            response: HTTP响应对象
            token: 要设置的令牌
            token_type: 令牌类型，默认为"access"
            max_age: Cookie的最大生存期（秒），默认为None表示会话Cookie
        """
        self._token_sdk.set_token_to_response(response, token, token_type, max_age)
    
    def create_and_set_token(self, response, user_id: str, username: str, roles: List[str], device_id: str) -> Result[str]:
        """创建访问令牌并设置到响应中
        
        封装TokenSDK的同名方法。
        
        Args:
            response: HTTP响应对象
            user_id: 用户ID
            username: 用户名
            roles: 用户角色列表
            device_id: 设备ID
            
        Returns:
            Result: 包含创建的令牌的结果
        """
        return self._token_sdk.create_and_set_token(response, user_id, username, roles, device_id)
    
    def handle_token_refresh(self, request, response) -> Result[Dict[str, Any]]:
        """处理令牌刷新
        
        封装TokenSDK的同名方法。
        
        Args:
            request: HTTP请求对象
            response: HTTP响应对象
            
        Returns:
            Result: 刷新结果，包含令牌数据或错误信息
        """
        return self._token_sdk.handle_token_refresh(request, response)
    
    def verify_request_token(self, request, response=None, update_token: bool = True) -> Result[Dict[str, Any]]:
        """验证请求中的令牌
        
        1. 从请求中提取令牌
        2. 验证令牌
        3. 如果令牌有效但即将过期，自动续订
        4. 如果令牌已过期，尝试使用刷新令牌
        5. 将新令牌设置到响应中
        
        Args:
            request: HTTP请求对象
            response: HTTP响应对象，如果提供且update_token为True，会自动更新令牌
            update_token: 是否自动更新令牌，默认为True
            
        Returns:
            Result: 验证结果，包含令牌数据或错误信息
        """
        # 从请求中提取令牌
        token = self.extract_token_from_request(request)
        if not token:
            return Result.fail("令牌不存在")
        
        # 验证令牌
        verify_result = self.verify_access_token(token)
        
        # 如果提供了响应对象且需要更新令牌
        if response and update_token and verify_result.is_ok():
            # 如果返回了新的令牌数据，说明进行了自动续订
            token_data = verify_result.data
            if isinstance(token_data, dict) and token_data.get("access_token"):
                # 设置新令牌到响应
                self.set_token_to_response(response, token_data["access_token"])
        
        return verify_result

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