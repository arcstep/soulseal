from typing import Dict, Any, Optional, Union, List, Tuple, Callable
from datetime import datetime, timedelta
from fastapi import Response, HTTPException, Request

import logging
import os
import jwt

from ..users import UserRole
from ..schemas import Result
from .token_schemas import (
    TokenType, TokenClaims, TokenResult,
    JWT_SECRET_KEY, JWT_ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES
)
from .blacklist import TokenBlacklistProvider, MemoryTokenBlacklist
from .tokens_manager import TokensManager

class TokenSDK:
    """令牌验证和管理SDK
    
    支持两种工作模式:
    
    1. 认证服务器模式 (auth_server=True):
       - 提供完整的令牌创建、验证、刷新和撤销功能
       - 需要提供RocksDB数据库实例用于管理刷新令牌
       - 适用场景：认证服务器后端
       
    2. 客户端模式 (auth_server=False):
       - 只提供令牌验证功能，使用共享密钥验证JWT签名
       - 不需要数据库，不处理刷新令牌
       - 可选使用黑名单验证令牌
    """
    
    def __init__(
        self, 
        jwt_secret_key=None,
        db=None,
        auth_server=True,
        blacklist_provider: TokenBlacklistProvider=None
    ):
        """初始化令牌SDK
        
        Args:
            jwt_secret_key: JWT密钥
            db: RocksDB实例(认证服务器需要)
            auth_server: 是否为认证服务器
            blacklist_provider: 黑名单提供者，两种模式都可以使用
        """
        self._logger = logging.getLogger(__name__)
        self._jwt_secret_key = jwt_secret_key or JWT_SECRET_KEY
        self._jwt_algorithm = JWT_ALGORITHM
        self._access_token_expire_minutes = ACCESS_TOKEN_EXPIRE_MINUTES
        
        # 设置工作模式
        self._auth_server = auth_server
        
        # 设置黑名单 - 两种模式都可以使用
        self._blacklist = blacklist_provider
        
        # 认证服务器模式初始化
        if auth_server:
            if not db:
                raise ValueError("认证服务器模式需要提供db参数")
                
            # 如果没有提供黑名单，创建默认内存实现
            if not self._blacklist:
                self._blacklist = MemoryTokenBlacklist()
                
            # 创建TokensManager用于刷新令牌管理
            self._tokens_manager = TokensManager(db)
            self._logger.info("TokenSDK初始化为认证服务器模式")
        else:
            # 客户端模式初始化
            self._tokens_manager = None
            self._logger.info("TokenSDK初始化为客户端模式，仅验证令牌")
            
            # 客户端模式可以使用黑名单验证撤销的令牌
            if self._blacklist:
                self._logger.info("客户端模式使用黑名单检查撤销令牌")

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
        
        # 编码为JWT
        return jwt.encode(
            payload=claims.model_dump(),
            key=self._jwt_secret_key,
            algorithm=self._jwt_algorithm
        )

    def verify_token(self, token: str, required_roles: List[str] = None) -> Result[Dict[str, Any]]:
        """验证JWT访问令牌"""
        try:
            # 先解码令牌但不验证过期时间
            unverified = jwt.decode(
                token, key=self._jwt_secret_key, 
                algorithms=[self._jwt_algorithm],
                options={'verify_exp': False}
            )
            
            # 如果提供了黑名单，检查令牌是否已撤销
            if self._blacklist:
                user_id = unverified.get("user_id")
                device_id = unverified.get("device_id")
                if user_id and device_id and self._blacklist.contains(f"{user_id}:{device_id}"):
                    return Result.fail("令牌已被撤销")
            
            # 验证签名和过期时间
            try:
                payload = jwt.decode(
                    token,
                    key=self._jwt_secret_key,
                    algorithms=[self._jwt_algorithm],
                    options={"verify_exp": True}
                )
                
                # 验证角色要求
                if required_roles and not self.verify_roles(required_roles, payload.get('roles', [])):
                    return Result.fail("权限不足")
                
                # 令牌有效
                payload["access_token"] = token
                return Result.ok(data=payload)
                
            except jwt.ExpiredSignatureError:
                return Result.fail("令牌已过期")
        
        except jwt.InvalidSignatureError:
            self._logger.warning(f"令牌签名无效")
            return Result.fail("令牌签名无效")
        except Exception as e:
            self._logger.warning(f"令牌验证错误: {str(e)}")
            return Result.fail(f"令牌验证错误: {str(e)}")

    def verify_roles(self, required_roles, user_roles):
        """验证用户角色是否满足要求"""
        # 转换为字符串列表
        if isinstance(required_roles, str):
            required_roles = [required_roles]
        
        # 确保用户角色也是列表
        if not user_roles or not isinstance(user_roles, list):
            return False
        
        # 检查每个所需角色
        for role in required_roles:
            # 将角色转换为UserRole枚举
            try:
                role_enum = UserRole(role)
                # 对每个用户角色创建集合并检查匹配
                for user_role in user_roles:
                    try:
                        user_role_enum = UserRole(user_role)
                        if UserRole.has_role(role_enum, {user_role_enum}):
                            return True
                    except (ValueError, TypeError):
                        continue
            except (ValueError, TypeError):
                continue
        
        return False

    def revoke_token(self, user_id: str, device_id: str, expires_at: float = None) -> bool:
        """撤销令牌 (将令牌加入黑名单并撤销刷新令牌)"""
        token_id = f"{user_id}:{device_id}"
        
        if not expires_at:
            # 默认令牌加入黑名单的过期时间
            from .token_schemas import REFRESH_TOKEN_EXPIRE_DAYS
            expires_at = datetime.utcnow().timestamp() + (REFRESH_TOKEN_EXPIRE_DAYS * 86400)
        
        # 加入黑名单
        if self._blacklist:
            self._blacklist.add(token_id, expires_at)
            self._logger.info(f"令牌已加入黑名单: {token_id}")
        
        # 认证服务器模式下，同时撤销刷新令牌
        if self._auth_server and self._tokens_manager:
            self._tokens_manager.revoke_refresh_token(user_id, device_id)
            
        return True

    def extract_token_from_request(self, request, token_type: str = "access") -> Optional[str]:
        """从请求中提取令牌
        
        访问令牌从Authorization头提取，刷新令牌从cookie提取
        
        Args:
            request: HTTP请求对象
            token_type: 令牌类型，"access"或"refresh"
        """
        if token_type == "refresh":
            # 刷新令牌只从cookie中提取
            try:
                if hasattr(request, "cookies") and callable(getattr(request.cookies, "get", None)):
                    token = request.cookies.get("refresh_token")
                    if token:
                        self._logger.debug("从Cookie中提取到刷新令牌")
                        return token
            except Exception as e:
                self._logger.debug(f"从Cookie提取刷新令牌失败: {str(e)}")
            return None
        else:
            # 访问令牌只从Authorization头部提取
            try:
                if hasattr(request, "headers") and callable(getattr(request.headers, "get", None)):
                    auth_header = request.headers.get("Authorization")
                    if auth_header and auth_header.startswith("Bearer "):
                        token = auth_header.split(" ")[1]
                        self._logger.debug("从Authorization头部提取到访问令牌")
                        return token
            except Exception as e:
                self._logger.debug(f"从Authorization头部提取访问令牌失败: {str(e)}")
            return None
    
    def set_token_to_response(self, response, token: str, token_type: str = "access", max_age: int = None) -> None:
        """将令牌设置到响应中
        
        访问令牌设置到Authorization头，刷新令牌设置到HTTP-only cookie
        
        Args:
            response: HTTP响应对象
            token: 要设置的令牌
            token_type: 令牌类型，"access"或"refresh"
            max_age: Cookie最大生存期(秒)，仅用于刷新令牌
        """
        try:
            if token is None:
                # 删除cookie或头部
                if token_type == "refresh" and hasattr(response, "delete_cookie"):
                    response.delete_cookie("refresh_token")
                    self._logger.debug("删除刷新令牌Cookie成功")
            else:
                if token_type == "access":
                    # 访问令牌设置到Authorization头部
                    if hasattr(response, "headers"):
                        response.headers["Authorization"] = f"Bearer {token}"
                        self._logger.debug("设置访问令牌到Authorization头部")
                else:
                    # 刷新令牌设置到cookie
                    if hasattr(response, "set_cookie"):
                        # 刷新令牌默认过期时间
                        from .token_schemas import REFRESH_TOKEN_EXPIRE_DAYS
                        refresh_max_age = max_age or REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60
                        
                        response.set_cookie(
                            key="refresh_token",
                            value=token,
                            httponly=True,
                            secure=True,  # 生产环境保持True
                            samesite="Lax",
                            max_age=refresh_max_age
                        )
                        self._logger.debug("设置刷新令牌Cookie成功")
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
        
        优化的令牌刷新流程:
        1. 尝试从请求中提取刷新令牌
        2. 如果找到刷新令牌，直接用它刷新访问令牌
        3. 如果未找到刷新令牌，尝试从过期的访问令牌中提取信息并刷新
        4. 将新访问令牌设置到响应头，将新刷新令牌（如果有）设置到cookie
        """
        # 首先尝试获取刷新令牌
        refresh_token = self.extract_token_from_request(request, "refresh")
        
        # 如果找到了刷新令牌，直接使用它
        if refresh_token:
            try:
                # 解析刷新令牌但不验证过期时间
                refresh_data = jwt.decode(
                    refresh_token, key=self._jwt_secret_key, 
                    algorithms=[self._jwt_algorithm],
                    options={'verify_exp': False}
                )
                
                user_id = refresh_data.get("user_id")
                device_id = refresh_data.get("device_id")
                username = refresh_data.get("username")
                roles = refresh_data.get("roles")
                
                if not all([user_id, device_id, username, roles]):
                    return Result.fail("刷新令牌格式无效")
                
                # 验证刷新令牌是否过期
                try:
                    jwt.decode(
                        refresh_token,
                        key=self._jwt_secret_key,
                        algorithms=[self._jwt_algorithm],
                        options={"verify_exp": True}
                    )
                    
                    # 刷新令牌有效，延长其有效期
                    if self._auth_server and self._tokens_manager:
                        extend_result = self.extend_refresh_token(user_id, device_id)
                        if extend_result.is_ok():
                            self._logger.debug(f"自动续订刷新令牌成功: {user_id}")
                        else:
                            self._logger.warning(f"自动续订刷新令牌失败: {extend_result.error}")
                    
                    # 创建新的访问令牌
                    access_token = self.create_token(user_id, username, roles, device_id)
                    
                    # 将访问令牌设置到header
                    self.set_token_to_response(response, access_token, "access")
                    
                    # 返回成功结果
                    return Result.ok(
                        data={
                            "access_token": access_token,
                            "user_id": user_id,
                            "username": username,
                            "roles": roles,
                            "device_id": device_id,
                            "token_type": "access"
                        },
                        message="使用刷新令牌创建新的访问令牌成功"
                    )
                    
                except jwt.ExpiredSignatureError:
                    # 刷新令牌已过期，需要重新登录
                    return Result.fail("刷新令牌已过期，请重新登录")
                    
            except Exception as e:
                self._logger.error(f"处理刷新令牌错误: {str(e)}")
        
        # 如果没有找到刷新令牌或刷新失败，尝试获取并解析访问令牌
        access_token = self.extract_token_from_request(request, "access")
        if not access_token:
            return Result.fail("访问令牌和刷新令牌都不存在，请重新登录")
        
        try:
            # 解析访问令牌但不验证过期时间
            unverified = jwt.decode(
                access_token, key=None, 
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
                jwt.decode(
                    access_token,
                    key=self._jwt_secret_key,
                    algorithms=[self._jwt_algorithm],
                    options={"verify_exp": True}
                )
                # 令牌未过期，不需要刷新
                return Result.ok(
                    data={
                        "access_token": access_token,
                        **unverified
                    }, 
                    message="令牌有效，无需刷新"
                )
            except jwt.ExpiredSignatureError:
                # 令牌已过期，尝试使用数据库中的刷新令牌
                if not self._auth_server or not self._tokens_manager:
                    return Result.fail("无法刷新令牌，请重新登录")
                
                self._logger.info(f"访问令牌已过期，尝试使用数据库刷新令牌: {user_id}")
                
                # 使用TokensManager刷新令牌
                refresh_result = self._tokens_manager.refresh_access_token(
                    user_id=user_id,
                    username=username,
                    roles=roles,
                    device_id=device_id
                )
                
                if refresh_result.is_ok():
                    # 刷新成功，获取新令牌
                    new_token_data = refresh_result.data
                    if isinstance(new_token_data, dict) and "access_token" in new_token_data:
                        new_token = new_token_data["access_token"]
                        
                        # 将访问令牌设置到header
                        self.set_token_to_response(response, new_token, "access")
                            
                        return Result.ok(data=new_token_data, message="访问令牌已刷新")
                
                # 记录刷新失败
                self._logger.error(f"刷新令牌失败: {refresh_result.error if hasattr(refresh_result, 'error') else '未知错误'}")
                return refresh_result
                
        except Exception as e:
            error_msg = f"处理令牌刷新失败: {str(e)}"
            self._logger.error(error_msg)
            return Result.fail(error_msg)

    def get_auth_dependency(
        self,
        require_roles: Union[UserRole, List[UserRole]] = None,
        logger: logging.Logger = None
    ) -> Callable[[Request, Response], Dict[str, Any]]:
        """创建FastAPI依赖函数进行令牌验证
        
        在认证服务器模式下，如果令牌过期会尝试使用刷新令牌自动刷新。
        
        Args:
            require_roles: 需要的角色权限
            logger: 日志记录器
        """
        if logger is None:
            logger = logging.getLogger(__name__)

        async def auth_dependency(request: Request, response: Response):
            # 提取访问令牌
            token = self.extract_token_from_request(request)
            if not token:
                raise HTTPException(status_code=401, detail="令牌不存在")
            
            # 验证令牌
            verify_result = self.verify_token(token)
            if verify_result.is_fail():
                # 仅在认证服务器模式下尝试刷新
                if self._auth_server and "过期" in verify_result.error:
                    refresh_result = self.handle_token_refresh(request, response)
                    if refresh_result.is_ok():
                        token_claims = refresh_result.data
                        
                        # 检查角色权限
                        if require_roles and not self.verify_roles(require_roles, token_claims.get('roles', [])):
                            raise HTTPException(status_code=403, detail="权限不足")
                        
                        return token_claims
                    else:
                        raise HTTPException(status_code=401, detail=refresh_result.error)
                else:
                    raise HTTPException(status_code=401, detail=verify_result.error)
            
            token_claims = verify_result.data
            
            # 验证角色
            if require_roles and not self.verify_roles(require_roles, token_claims['roles']):
                raise HTTPException(status_code=403, detail="权限不足")
            
            return token_claims
        
        return auth_dependency

    def extend_refresh_token(self, user_id: str, device_id: str, max_absolute_lifetime_days: int = 180) -> Result[bool]:
        """延长刷新令牌有效期（滑动过期机制）
        
        当用户使用刷新令牌时，自动延长其有效期，同时保证不超过最大绝对有效期
        仅在认证服务器模式下可用
        
        Args:
            user_id: 用户ID
            device_id: 设备ID
            max_absolute_lifetime_days: 刷新令牌最大绝对生命周期(天)
            
        Returns:
            Result: 操作结果
        """
        if not self._auth_server or not self._tokens_manager:
            return Result.fail("只有认证服务器模式支持刷新令牌续订")
        
        return self._tokens_manager.extend_refresh_token(
            user_id=user_id,
            device_id=device_id,
            max_absolute_lifetime_days=max_absolute_lifetime_days
        )
