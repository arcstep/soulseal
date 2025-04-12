from typing import Dict, Any, Optional, Union, List, Tuple, Callable
from datetime import datetime, timedelta
from urllib.parse import urljoin
from fastapi import Response, HTTPException, Request

import logging
import os
import requests

from ..users import UserRole
from ..models import Result
from .token_models import (
    TokenType, TokenClaims, TokenResult,
    JWT_SECRET_KEY, JWT_ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES
)

import jwt

class TokenSDK:
    """令牌验证和管理SDK
    
    提供访问令牌验证和管理功能，可被多个项目共享使用。
    支持三种工作模式，适用于不同场景：
    
    1. 本地模式 (local)：
       - 用于主服务中的内部组件或同进程子服务
       - 需要提供TokensManager实例
       - 利用TokensManager管理刷新令牌和黑名单
       - 支持令牌验证、刷新和撤销的完整功能
       - 适用场景：同一进程内的服务通信

    2. 远程模式 (remote)：
       - 用于独立进程的子服务或微服务
       - 需要提供主服务的API基础URL
       - 通过HTTP请求调用主服务API验证和管理令牌
       - 支持令牌验证、刷新和撤销的完整功能
       - 适用场景：分布式系统中的服务间通信

    3. 独立模式 (standalone)：
       - 不需要提供TokensManager或API URL
       - 只提供基本的令牌创建和验证功能
       - 使用简单的内存字典作为黑名单
       - 不支持令牌刷新功能
       - 适用场景：简单应用、测试环境或不需要复杂令牌管理的场合
    """
    
    def __init__(
        self, 
        jwt_secret_key=None,
        jwt_algorithm=None,
        tokens_manager=None,  # 可选的TokensManager实例
        auth_base_url=None,    # 远程API地址
        auth_prefix="/api",    # API前缀
        auto_renew_before_expiry_seconds: int = 60,  # 提前自动续订的秒数
        token_storage_method="cookie"
    ):
        """初始化令牌SDK
        
        根据提供的参数自动选择工作模式:
        - 如果提供了tokens_manager，则使用本地模式
        - 如果提供了auth_base_url，则使用远程模式
        - 如果两者都未提供，则使用独立模式
        - 如果两者都提供，则优先使用本地模式
        
        Args:
            jwt_secret_key: JWT密钥，如果不提供则使用环境变量FASTAPI_SECRET_KEY
            jwt_algorithm: JWT算法，如果不提供则使用默认HS256
            tokens_manager: TokensManager对象，用于本地模式下验证令牌和黑名单
            auth_base_url: 远程API基础URL，用于远程模式下验证令牌和黑名单
            auth_prefix: API路径前缀，默认为"/api"
            auto_renew_before_expiry_seconds: 在令牌过期前多少秒自动续订
            token_storage_method: 令牌存储方式，默认为"cookie"
        """
        self._logger = logging.getLogger(__name__)
        self._jwt_secret_key = jwt_secret_key or JWT_SECRET_KEY
        self._jwt_algorithm = jwt_algorithm or JWT_ALGORITHM
        self._access_token_expire_minutes = ACCESS_TOKEN_EXPIRE_MINUTES
        self._auto_renew_before_expiry_seconds = auto_renew_before_expiry_seconds
        
        # 设置工作模式：本地模式、远程模式或独立模式
        self._tokens_manager = tokens_manager
        self._auth_base_url = auth_base_url
        self._auth_prefix = auth_prefix.rstrip("/") if auth_prefix else ""
        
        # 设置令牌存储方式
        self.token_storage_method = token_storage_method
        self._logger.debug(f"令牌存储方式: {self.token_storage_method}")
        
        if tokens_manager and auth_base_url:
            self._logger.warning("同时提供了tokens_manager和auth_base_url，将优先使用tokens_manager")
            self._mode = "local"
        elif tokens_manager:
            self._mode = "local"
            self._logger.info("TokenSDK初始化为本地模式")
        elif auth_base_url:
            self._mode = "remote"
            self._logger.info(f"TokenSDK初始化为远程模式，API地址：{auth_base_url}{self._auth_prefix}")
        else:
            self._mode = "standalone"
            self._logger.warning("TokenSDK初始化为独立模式，仅提供基本的令牌验证，不支持黑名单和续订")
            self._internal_blacklist = {}

    @classmethod
    def create_access_token(
        cls, user_id: str,
        username: str, roles: List[str],
        device_id: str = None, 
        jwt_secret_key: str = None,
        jwt_algorithm: str = None, 
        expire_minutes: int = None
    ) -> str:
        """创建新的访问令牌（无需实例化SDK）
        
        此方法可以在不创建TokenSDK实例的情况下创建访问令牌，
        适用于简单的令牌创建场景。
        
        Args:
            user_id: 用户ID
            username: 用户名
            roles: 用户角色列表
            device_id: 设备ID，如果不提供则自动生成
            jwt_secret_key: JWT密钥，如果不提供则使用默认值
            jwt_algorithm: JWT算法，如果不提供则使用默认值
            expire_minutes: 令牌有效期(分钟)，如果不提供则使用默认值
            
        Returns:
            str: JWT格式的访问令牌
        """
        # 使用共享TokenClaims创建访问令牌
        claims = TokenClaims.create_access_token(
            user_id=user_id,
            username=username,
            roles=roles,
            device_id=device_id
        )
        
        # 如果提供了自定义过期时间，更新过期时间
        if expire_minutes is not None:
            claims.exp = datetime.utcnow() + timedelta(minutes=expire_minutes)
            
        # 获取密钥和算法
        secret_key = jwt_secret_key or JWT_SECRET_KEY
        algorithm = jwt_algorithm or JWT_ALGORITHM
        
        # 编码为JWT
        return jwt.encode(
            payload=claims.model_dump(),
            key=secret_key,
            algorithm=algorithm
        )

    def create_token(self, user_id: str, username: str, roles: List[str], device_id: str = None) -> str:
        """创建访问令牌
        
        使用实例配置创建访问令牌，适用于需要一致配置的场景。
        在所有模式下都可用。
        
        Args:
            user_id: 用户ID
            username: 用户名
            roles: 用户角色列表
            device_id: 设备ID，如果不提供则自动生成
            
        Returns:
            str: JWT格式的访问令牌
        """
        # 使用共享TokenClaims创建访问令牌
        claims = TokenClaims.create_access_token(
            user_id=user_id,
            username=username,
            roles=roles,
            device_id=device_id
        )
        
        # 使用实例的过期时间设置
        claims.exp = datetime.utcnow() + timedelta(minutes=self._access_token_expire_minutes)
        
        # 编码为JWT
        return jwt.encode(
            payload=claims.model_dump(),
            key=self._jwt_secret_key,
            algorithm=self._jwt_algorithm
        )

    def verify_token(self, token: str) -> Result[Dict[str, Any]]:
        """验证JWT访问令牌有效性
        
        检查令牌的签名、有效期和是否在黑名单中。
        简化的验证逻辑，只负责验证令牌，不自动处理续订或刷新。
        
        Args:
            token: JWT格式的访问令牌
            
        Returns:
            Result: 验证结果，包含令牌数据或错误信息
        """
        try:
            # 先解码令牌但不验证过期时间，获取必要的信息
            unverified = jwt.decode(
                token, key=self._jwt_secret_key, 
                algorithms=[self._jwt_algorithm],
                options={'verify_exp': False}
            )
            
            user_id = unverified.get("user_id")
            device_id = unverified.get("device_id")
            
            # 检查黑名单
            if user_id and device_id and self.is_blacklisted(user_id, device_id):
                return Result.fail("令牌已被撤销")
            
            try:
                # 验证签名和过期时间
                payload = jwt.decode(
                    token,
                    key=self._jwt_secret_key,
                    algorithms=[self._jwt_algorithm],
                    options={"verify_exp": True}
                )
                
                # 令牌有效，将原始token包含在返回数据中
                payload["access_token"] = token
                return Result.ok(data=payload)
                
            except jwt.ExpiredSignatureError:
                # 令牌过期，直接返回错误
                return Result.fail("令牌已过期")
        
        except jwt.InvalidSignatureError:
            # 签名无效
            self._logger.warning(f"令牌签名无效")
            return Result.fail("令牌签名无效")
        except Exception as e:
            # 其他验证错误
            self._logger.warning(f"令牌验证错误: {str(e)}")
            return Result.fail(f"令牌验证错误: {str(e)}")

    def _build_auth_url(self, path):
        """构建认证API URL
        
        将auth_base_url和auth_prefix与给定路径组合，构建完整的API URL
        
        Args:
            path: API路径，不包含前缀
            
        Returns:
            str: 完整的API URL
        """
        # 确保路径不以/开头，避免urljoin问题
        path = path.lstrip("/")
        # 确保auth_prefix以/结尾，便于连接
        prefix = f"{self._auth_prefix}/" if self._auth_prefix and not self._auth_prefix.endswith("/") else self._auth_prefix
        
        # 使用urljoin组合基础URL和路径
        return urljoin(self._auth_base_url, f"{prefix}{path}")

    def renew_token(self, token: str, user_id: str, device_id: str, token_data: Dict[str, Any]) -> Result[Dict[str, Any]]:
        """在令牌即将过期时续订访问令牌
        
        根据工作模式选择不同的续订方式：
        - 本地模式：使用TokensManager续订令牌
        - 远程模式：调用主服务API续订令牌
        - 独立模式：不支持续订，返回失败
        
        与refresh_token不同，renew_token不需要刷新令牌，只需要当前有效的访问令牌。
        
        Args:
            token: 当前的访问令牌
            user_id: 用户ID
            device_id: 设备ID
            token_data: 令牌中的数据
            
        Returns:
            Result: 续订结果，包含新令牌数据或错误信息
        """
        if self._mode == "local" and self._tokens_manager:
            # 使用TokensManager创建新令牌
            result = self._tokens_manager.renew_access_token(
                user_id=user_id,
                username=token_data.get("username"),
                roles=token_data.get("roles"),
                device_id=device_id
            )
            if result.is_ok():
                self._logger.info(f"本地模式续订令牌成功: {user_id}")
                # 确保结果中包含access_token字段
                if isinstance(result.data, dict) and "access_token" not in result.data:
                    self._logger.warning("本地模式续订令牌成功但结果中缺少access_token字段，添加默认值")
                    new_token = self.create_token(
                        user_id=user_id,
                        username=token_data.get("username"),
                        roles=token_data.get("roles"),
                        device_id=device_id
                    )
                    return Result.ok(data={"access_token": new_token, **result.data}, message="令牌续订成功")
                return result
            return Result.fail(f"本地续订令牌失败: {result.error}")
            
        elif self._mode == "remote" and self._auth_base_url:
            # 使用远程API续订
            try:
                url = self._build_auth_url("auth/renew-token")
                response = requests.post(
                    url,
                    json={"token": token},
                    headers={"Content-Type": "application/json"},
                    timeout=5.0
                )
                
                if response.status_code == 200:
                    data = response.json()
                    if data.get("success", False):
                        new_token = data.get("data", {}).get("access_token")
                        if new_token:
                            # 解析新令牌
                            try:
                                new_token_data = jwt.decode(
                                    new_token,
                                    key=self._jwt_secret_key,
                                    algorithms=[self._jwt_algorithm],
                                    options={'verify_signature': True}
                                )
                                self._logger.info(f"远程模式续订令牌成功: {user_id}")
                                # 确保返回值包含access_token字段
                                return Result.ok(
                                    data={"access_token": new_token, **new_token_data}, 
                                    message="令牌续订成功"
                                )
                            except Exception as e:
                                self._logger.error(f"解析新令牌失败: {str(e)}")
                                # 即使解析失败也返回token
                                return Result.ok(
                                    data={"access_token": new_token},
                                    message="令牌续订成功但解析失败"
                                )
                
                error_message = f"远程续订令牌失败: {response.status_code}"
                self._logger.error(error_message)
                try:
                    error_data = response.json()
                    if isinstance(error_data, dict) and "detail" in error_data:
                        error_message = f"远程续订令牌失败: {error_data['detail']}"
                except Exception:
                    pass
                
                return Result.fail(error_message)
            
            except Exception as e:
                error_msg = f"远程续订令牌错误: {str(e)}"
                self._logger.error(error_msg)
                return Result.fail(error_msg)
        
        # 独立模式不支持续订
        return Result.fail("独立模式不支持令牌续订功能")

    def refresh_token(self, token: str, user_id: str, device_id: str, token_data: Dict[str, Any]) -> Result[Dict[str, Any]]:
        """在令牌已过期时使用刷新令牌获取新的访问令牌
        
        与renew_token不同，refresh_token用于令牌已过期的情况，
        需要使用存储的刷新令牌来获取新的访问令牌。
        
        严格遵循以下令牌颁发流程：
        1. 如果访问令牌过期，但没有刷新令牌存在，返回401要求重新登录
        2. 如果访问令牌过期，但刷新令牌存在且未过期，重新颁发令牌
        3. 如果刷新令牌不存在或已过期，返回401要求重新登录
        
        Args:
            token: 过期的访问令牌
            user_id: 用户ID
            device_id: 设备ID
            token_data: 令牌中的数据
            
        Returns:
            Result: 刷新结果，包含新令牌数据或错误信息
        """
        if self._mode == "local" and self._tokens_manager:
            # 使用TokensManager刷新令牌
            result = self._tokens_manager.refresh_access_token(
                user_id=user_id,
                username=token_data.get("username"),
                roles=token_data.get("roles"),
                device_id=device_id
            )
            if result.is_ok():
                self._logger.info(f"本地模式刷新令牌成功: {user_id}")
                return result
            
            # 刷新令牌不存在或已过期，返回错误
            self._logger.warning(f"刷新令牌失败: {result.error}")
            return result
            
        elif self._mode == "remote" and self._auth_base_url:
            # 使用远程API刷新
            try:
                url = self._build_auth_url("auth/refresh-token")
                self._logger.debug(f"尝试远程刷新令牌: {url}")
                response = requests.post(
                    url,
                    json={"token": token},
                    headers={"Content-Type": "application/json"},
                    timeout=5.0
                )
                
                if response.status_code == 200:
                    data = response.json()
                    if data.get("success", False):
                        new_token = data.get("data", {}).get("access_token")
                        if new_token:
                            # 解析新令牌
                            try:
                                new_token_data = jwt.decode(
                                    new_token,
                                    key=self._jwt_secret_key,
                                    algorithms=[self._jwt_algorithm],
                                    options={'verify_signature': True}
                                )
                                self._logger.info(f"远程模式刷新令牌成功: {user_id}")
                                
                                # 确保返回结果中包含token信息
                                # 注意：需要同时返回access_token以便caller能设置cookie
                                return Result.ok(
                                    data={
                                        "access_token": new_token,
                                        **new_token_data
                                    }, 
                                    message="令牌刷新成功"
                                )
                            except Exception as e:
                                self._logger.error(f"解析新令牌失败: {str(e)}")
                                # 即使解析失败也返回token，让客户端能够设置cookie
                                return Result.ok(
                                    data={"access_token": new_token},
                                    message="令牌刷新成功但解析失败"
                                )
                
                # 刷新令牌不存在或已过期
                if response.status_code == 401:
                    try:
                        error_data = response.json()
                        error_detail = error_data.get("detail", "刷新令牌不存在或已过期")
                    except Exception:
                        error_detail = "刷新令牌不存在或已过期"
                    
                    error_message = f"刷新令牌失败，请重新登录: {error_detail}"
                    self._logger.warning(error_message)
                    return Result.fail(error_message)
                
                # 其他错误
                error_message = f"远程刷新令牌失败: {response.status_code}"
                self._logger.error(error_message)
                try:
                    error_data = response.json()
                    if isinstance(error_data, dict) and "detail" in error_data:
                        error_message = f"远程刷新令牌失败: {error_data['detail']}"
                except Exception:
                    pass
                
                return Result.fail(error_message)
            
            except Exception as e:
                error_msg = f"远程刷新令牌错误: {str(e)}"
                self._logger.error(error_msg)
                return Result.fail(error_msg)
        
        # 独立模式不支持刷新
        return Result.fail("独立模式不支持令牌刷新功能，请重新登录")

    def is_blacklisted(self, user_id: str, device_id: str) -> bool:
        """检查令牌是否在黑名单中
        
        根据不同的工作模式有不同的实现：
        - 本地模式：检查TokensManager中的令牌黑名单
        - 远程模式：调用主服务API检查黑名单
        - 独立模式：使用内部简单字典检查
        
        Args:
            user_id: 用户ID
            device_id: 设备ID
            
        Returns:
            bool: 是否在黑名单中
        """
        token_id = f"{user_id}:{device_id}"
        
        if self._mode == "local" and self._tokens_manager:
            # 使用TokensManager中的黑名单
            return self._tokens_manager._token_blacklist.contains(token_id)
            
        elif self._mode == "remote" and self._auth_base_url:
            # 使用远程API检查黑名单
            try:
                url = self._build_auth_url("auth/blacklist/check")
                response = requests.post(
                    url,
                    json={"user_id": user_id, "device_id": device_id},
                    headers={"Content-Type": "application/json"},
                    timeout=5.0
                )
                
                if response.status_code == 200:
                    data = response.json()
                    return data.get("in_blacklist", False)
                return False
                
            except Exception as e:
                self._logger.error(f"远程黑名单检查错误: {str(e)}")
                return False
        
        # 独立模式使用内部字典
        return (token_id in self._internal_blacklist and 
                datetime.utcnow() < self._internal_blacklist.get(token_id, datetime.utcnow()))

    def revoke_token(self, user_id: str, device_id: str, expires_at: datetime = None) -> bool:
        """将令牌加入黑名单
        
        根据工作模式选择不同的撤销方式：
        - 本地模式：使用TokensManager撤销
        - 远程模式：调用主服务API撤销
        - 独立模式：使用内部简单字典撤销
        
        Args:
            user_id: 用户ID
            device_id: 设备ID
            expires_at: 黑名单过期时间，默认为1小时后
            
        Returns:
            bool: 是否成功撤销
        """
        token_id = f"{user_id}:{device_id}"
        
        if not expires_at:
            expires_at = datetime.utcnow() + timedelta(hours=1)
        
        if self._mode == "local" and self._tokens_manager:
            # 使用TokensManager撤销
            self._tokens_manager.revoke_access_token(user_id, device_id)
            return True
            
        elif self._mode == "remote" and self._auth_base_url:
            # 使用远程API撤销
            try:
                url = self._build_auth_url("auth/logout")
                response = requests.post(
                    url,
                    json={"user_id": user_id, "device_id": device_id},
                    headers={"Content-Type": "application/json"},
                    timeout=5.0
                )
                
                if response.status_code == 200:
                    self._logger.info(f"远程撤销令牌成功: {token_id}")
                    return True
                
                self._logger.warning(f"远程撤销令牌失败: {response.status_code}")
                return False
                
            except Exception as e:
                self._logger.error(f"远程撤销令牌错误: {str(e)}")
                return False
        
        # 独立模式下的简单撤销
        if self._mode == "standalone":
            self._internal_blacklist[token_id] = expires_at
            self._logger.info(f"独立模式撤销令牌: {token_id}, 过期时间: {expires_at}")
            return True
        
        return False

    def blacklist_token(self, token_id: str, expires_at: datetime) -> None:
        """将令牌加入黑名单
        
        根据不同的工作模式有不同的实现：
        - 本地模式：加入TokensManager中的令牌黑名单
        - 远程模式：调用主服务API将令牌加入黑名单
        - 独立模式：加入内部简单字典黑名单
        
        Args:
            token_id: 令牌ID，通常是"user_id:device_id"的格式
            expires_at: 黑名单过期时间
        """
        if self._mode == "local" and self._tokens_manager:
            # 使用TokensManager中的黑名单
            self._tokens_manager._token_blacklist.add(token_id, expires_at)
            
        elif self._mode == "remote" and self._auth_base_url:
            # 使用远程API将令牌加入黑名单
            try:
                url = self._build_auth_url("auth/blacklist")
                response = requests.post(
                    url,
                    json={"token_id": token_id, "expires_at": expires_at.isoformat()},
                    headers={"Content-Type": "application/json"},
                    timeout=5.0
                )
                
                if response.status_code != 200:
                    self._logger.error(f"远程黑名单添加失败: {response.status_code}")
                    
            except Exception as e:
                self._logger.error(f"远程黑名单添加错误: {str(e)}")
        
        # 独立模式使用内部字典
        else:
            self._internal_blacklist[token_id] = expires_at
            self._logger.info(f"令牌已加入黑名单: {token_id}")

    def extract_token_from_request(self, request) -> Optional[str]:
        """从请求中提取令牌
        
        支持多种提取方式:
        1. 从Cookie中提取
        2. 从Authorization头部提取
        3. 从请求参数中提取
        
        Args:
            request: HTTP请求对象，可以是FastAPI的Request或其他兼容对象
            
        Returns:
            Optional[str]: 提取到的令牌，如果没有找到则返回None
        """
        token = None
        
        # 1. 从cookie中提取
        try:
            if hasattr(request, "cookies") and callable(getattr(request.cookies, "get", None)):
                token = request.cookies.get("access_token")
                if token:
                    self._logger.debug("从Cookie中提取到令牌")
                    return token
        except Exception as e:
            self._logger.debug(f"从Cookie提取令牌失败: {str(e)}")
        
        # 2. 从Authorization头部提取
        try:
            if hasattr(request, "headers") and callable(getattr(request.headers, "get", None)):
                auth_header = request.headers.get("Authorization")
                if auth_header and auth_header.startswith("Bearer "):
                    token = auth_header.split(" ")[1]
                    self._logger.debug("从Authorization头部提取到令牌")
                    return token
        except Exception as e:
            self._logger.debug(f"从Authorization头部提取令牌失败: {str(e)}")
        
        # 3. 从请求参数中提取
        try:
            if hasattr(request, "query_params") and callable(getattr(request.query_params, "get", None)):
                token = request.query_params.get("access_token")
                if token:
                    self._logger.debug("从请求参数中提取到令牌")
                    return token
        except Exception as e:
            self._logger.debug(f"从请求参数提取令牌失败: {str(e)}")
        
        return None
    
    def set_token_to_response(self, response, token: str, token_type: str = "access", max_age: int = None) -> None:
        """将令牌设置到响应中
        
        支持将令牌设置为Cookie和/或响应头部，根据token_storage_method配置。
        
        Args:
            response: HTTP响应对象，可以是FastAPI的Response或其他兼容对象
            token: 要设置的令牌
            token_type: 令牌类型，默认为"access"
            max_age: Cookie的最大生存期（秒），默认为None表示会话Cookie
        """
        try:
            if token is None:
                # 删除cookie
                if self.token_storage_method in ["cookie", "both"]:
                    if hasattr(response, "delete_cookie"):
                        response.delete_cookie(f"{token_type}_token")
                        self._logger.debug(f"删除{token_type}令牌Cookie成功")
            else:
                # 根据存储方式设置令牌
                
                # 设置cookie
                if self.token_storage_method in ["cookie", "both"]:
                    if hasattr(response, "set_cookie"):
                        response.set_cookie(
                            key=f"{token_type}_token",
                            value=token,
                            httponly=True,
                            secure=False,  # 在生产环境应设为True
                            samesite="Lax",
                            max_age=max_age
                        )
                        self._logger.debug(f"设置{token_type}令牌Cookie成功")
                
                # 设置头部
                if self.token_storage_method in ["header", "both"]:
                    if hasattr(response, "headers"):
                        response.headers["X-Access-Token"] = token
                        self._logger.debug(f"设置{token_type}令牌到响应头部成功")
        except Exception as e:
            self._logger.error(f"设置{token_type}令牌到响应失败: {str(e)}")
    
    def create_and_set_token(self, response, user_id: str, username: str, roles: List[str], device_id: str) -> Result[str]:
        """创建访问令牌并设置到响应中
        
        封装创建令牌和设置令牌到响应的流程。
        
        Args:
            response: HTTP响应对象
            user_id: 用户ID
            username: 用户名
            roles: 用户角色列表
            device_id: 设备ID
            
        Returns:
            Result: 包含创建的令牌的结果
        """
        try:
            # 创建令牌
            token = self.create_token(user_id, username, roles, device_id)
            
            # 设置令牌到响应
            self.set_token_to_response(response, token)
            
            return Result.ok(data={"access_token": token}, message="访问令牌创建并设置成功")
        except Exception as e:
            return Result.fail(f"创建并设置访问令牌失败: {str(e)}")
    
    def handle_token_refresh(self, request, response) -> Result[Dict[str, Any]]:
        """处理令牌刷新
        
        简化的令牌刷新流程:
        1. 从请求中提取令牌
        2. 验证令牌是否已过期
        3. 如果令牌已过期，尝试使用刷新令牌获取新的访问令牌
        4. 将新令牌设置到响应中
        
        Args:
            request: HTTP请求对象
            response: HTTP响应对象
            
        Returns:
            Result: 刷新结果，包含令牌数据或错误信息
        """
        # 从请求中提取令牌
        token = self.extract_token_from_request(request)
        if not token:
            return Result.fail("令牌不存在")
        
        try:
            # 解析令牌但不验证签名和过期时间
            unverified = jwt.decode(
                token, key=None, 
                options={'verify_signature': False, 'verify_exp': False}
            )
            
            user_id = unverified.get("user_id")
            device_id = unverified.get("device_id")
            username = unverified.get("username")
            roles = unverified.get("roles")
            
            if not all([user_id, device_id, username, roles]):
                return Result.fail("令牌格式无效")
            
            # 验证令牌是否已过期
            try:
                # 验证签名和过期时间
                jwt.decode(
                    token,
                    key=self._jwt_secret_key,
                    algorithms=[self._jwt_algorithm],
                    options={"verify_exp": True}
                )
                # 令牌未过期，不需要刷新
                return Result.ok(data={"access_token": token, **unverified}, message="令牌有效，无需刷新")
            except jwt.ExpiredSignatureError:
                # 令牌已过期，尝试使用刷新令牌
                self._logger.info(f"令牌已过期，尝试使用刷新令牌: {user_id}")
                refresh_result = self.refresh_token(token, user_id, device_id, unverified)
                
                if refresh_result.is_ok():
                    # 设置新令牌到响应
                    new_token_data = refresh_result.data
                    if isinstance(new_token_data, dict) and "access_token" in new_token_data:
                        new_token = new_token_data["access_token"]
                        self.set_token_to_response(response, new_token)
                        self._logger.debug(f"设置新令牌到响应: {new_token[:10]}...")
                        return Result.ok(data=new_token_data, message="令牌已通过刷新令牌刷新")
                    else:
                        return Result.fail("刷新后的令牌无效")
                
                # 记录刷新失败原因
                self._logger.error(f"刷新令牌失败: {refresh_result.error}")
                return refresh_result
            except Exception as e:
                # 其他验证错误
                error_msg = f"令牌验证错误: {str(e)}"
                self._logger.warning(error_msg)
                return Result.fail(error_msg)
        
        except Exception as e:
            error_msg = f"处理令牌刷新失败: {str(e)}"
            self._logger.error(error_msg)
            return Result.fail(error_msg)

    def get_auth_dependency(
        self,
        require_roles: Union[UserRole, List[UserRole]] = None,
        logger: logging.Logger = None
    ) -> Callable[[Request, Response], Dict[str, Any]]:
        """创建一个强化的验证依赖，支持角色检查
        
        与get_token_verify_dependency不同，此方法还支持角色验证
        
        Args:
            require_roles: 要求的角色，如果提供，用户必须具备指定角色
            logger: 自定义日志记录器
            
        Returns:
            验证函数: 可用于FastAPI Depends的异步函数
        """
        if logger is None:
            logger = logging.getLogger(__name__)

        async def auth_dependency(request: Request, response: Response):
            token = self.extract_token_from_request(request)
            if not token:
                error = "令牌不存在"
                logger.error(error)
                raise HTTPException(status_code=401, detail=error)
            
            verify_result = self.verify_token(token)
            if verify_result.is_fail():
                error = f"令牌验证失败: {verify_result.error}"
                logger.error(error)
                raise HTTPException(status_code=401, detail=verify_result.error)
            
            token_claims = verify_result.data
            
            # 如果要求角色，则验证用户权限
            if require_roles and not UserRole.has_role(require_roles, token_claims['roles']):
                raise HTTPException(
                    status_code=403,
                    detail="权限不足。需要指定的角色。"
                )
            
            return token_claims
        
        return auth_dependency

class TokensManager:
    """令牌管理器
    
    处理API的令牌操作，如创建、黑名单管理等。
    """
    
    def __init__(self, db, token_blacklist, token_storage_method = "cookie"):
        """初始化令牌管理器
        
        Args:
            db: 数据库实例
            token_blacklist: 令牌黑名单实例
            token_storage_method: 令牌存储方式，可选值：cookie, header, both
        """
        self.db = db
        self.token_blacklist = token_blacklist
        self.token_storage_method = token_storage_method
        self._logger = logging.getLogger(__name__)
