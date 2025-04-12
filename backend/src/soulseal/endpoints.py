from fastapi import FastAPI, Depends, Response, HTTPException, status, Request
from typing import Dict, Any, List, Optional, Callable, Union, Tuple
from pydantic import BaseModel, EmailStr, Field
import uuid
import logging
from datetime import datetime, timedelta
from enum import Enum
import jwt

from voidring import IndexedRocksDB
from .http import handle_errors, HttpMethod
from .tokens import TokensManager, TokenBlacklist, TokenClaims, TokenSDK
from .users import UsersManager, User, UserRole
from .models import Result

def require_user(
    token_sdk: TokenSDK,
    require_roles: Union[UserRole, List[UserRole]] = None,
    update_access_token: bool = True,
    logger: logging.Logger = None
) -> Callable[[Request, Response], Dict[str, Any]]:
    """验证用户信息

    Args:
        token_sdk: 令牌SDK
        require_roles: 要求的角色
        update_access_token: 是否自动更新访问令牌
        logger: 日志记录器
    """
    if logger is None:
        logger = logging.getLogger(__name__)

    async def verified_user(
        request: Request,
        response: Response,
    ) -> Dict[str, Any]:
        """验证用户信息

        如果要求角色，则需要用户具备所有指定的角色。
        """
        # 从请求中提取令牌
        token = token_sdk.extract_token_from_request(request)
        if not token:
            error = "令牌不存在"
            logger.error(error)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, 
                detail=error
            )
        
        # 验证令牌
        verify_result = token_sdk.verify_token(token)
        
        if verify_result.is_fail():
            error = f"令牌验证失败: {verify_result.error}"
            logger.error(error)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, 
                detail=error
            )
        
        token_claims = verify_result.data
        logger.debug(f"验证用户信息: {token_claims}")
        
        # 如果提供了响应对象且需要更新令牌
        if response and update_access_token:
            # 如果令牌即将过期，自动续订
            exp_timestamp = token_claims.get("exp", 0)
            now_timestamp = datetime.timestamp(datetime.utcnow())
            seconds_to_expire = exp_timestamp - now_timestamp
            
            if seconds_to_expire < token_sdk._auto_renew_before_expiry_seconds:
                # 尝试续订令牌
                renew_result = token_sdk.renew_token(
                    token=token,
                    user_id=token_claims["user_id"],
                    device_id=token_claims["device_id"],
                    token_data=token_claims
                )
                
                if renew_result.is_ok() and isinstance(renew_result.data, dict) and "access_token" in renew_result.data:
                    # 设置新令牌到响应
                    token_sdk.set_token_to_response(response, renew_result.data["access_token"])
                    logger.debug("令牌已自动续订并设置到响应")

        # 如果要求所有角色，则需要用户具备指定的角色
        if require_roles and not UserRole.has_role(require_roles, token_claims['roles']):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="权限不足。需要指定的角色。"
            )

        return token_claims

    return verified_user

def create_auth_endpoints(
    app: FastAPI,
    tokens_manager: TokensManager = None,
    users_manager: UsersManager = None,
    token_blacklist: TokenBlacklist = None,
    prefix: str="/api",
    logger: logging.Logger = None
) -> List[Tuple[HttpMethod, str, Callable]]:
    """创建认证相关的API端点
    
    Returns:
        List[Tuple[HttpMethod, str, Callable]]: 
            元组列表 (HTTP方法, 路由路径, 处理函数)
    """
    if logger is None:
        logger = logging.getLogger(__name__)
    
    # 创建TokenSDK实例，以减少对TokensManager的直接依赖
    token_sdk = TokenSDK(
        tokens_manager=tokens_manager,
        token_storage_method=tokens_manager.token_storage_method if tokens_manager else "cookie"
    )

    def _create_browser_device_id(request: Request) -> str:
        """为浏览器创建或获取设备ID
        
        优先从cookie中获取，如果没有则创建新的
        """
        existing_device_id = request.cookies.get("device_id")
        if existing_device_id:
            return existing_device_id
        
        user_agent = request.headers.get("user-agent", "unknown")
        os_info = "unknown_os"
        browser_info = "unknown_browser"
        
        if "Windows" in user_agent:
            os_info = "Windows"
        elif "Macintosh" in user_agent:
            os_info = "Mac"
        elif "Linux" in user_agent:
            os_info = "Linux"
        
        if "Chrome" in user_agent:
            browser_info = "Chrome"
        elif "Firefox" in user_agent:
            browser_info = "Firefox"
        elif "Safari" in user_agent and "Chrome" not in user_agent:
            browser_info = "Safari"
        
        return f"{os_info}_{browser_info}_{uuid.uuid4().hex[:8]}"

    class RegisterRequest(BaseModel):
        """注册请求"""
        username: str = Field(..., description="用户名")
        password: str = Field(..., description="密码")
        email: EmailStr = Field(..., description="邮箱")

    @handle_errors()
    async def register(request: RegisterRequest):
        """用户注册接口"""
        user = User(
            username=request.username,
            email=request.email,
            password_hash=User.hash_password(request.password),
        )
        result = users_manager.create_user(user)
        if result.is_ok():
            return result
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=result.error
            )

    class LoginRequest(BaseModel):
        """登录请求
        支持用户从多个设备使用自动生成的设备ID同时登录。
        """
        username: str = Field(..., description="用户名")
        password: str = Field(..., description="密码")
        device_id: Optional[str] = Field(None, description="设备ID")

    @handle_errors()
    async def login(request: Request, response: Response, login_data: LoginRequest):
        """登录"""
        # 验证用户密码
        verify_result = users_manager.verify_password(
            username=login_data.username,
            password=login_data.password
        )
        
        if verify_result.is_fail():
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=verify_result.error or "认证失败"
            )
        
        user_info = verify_result.data
        logger.debug(f"登录结果: {user_info}")

        # 检查用户状态
        if user_info['is_locked']:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="账户已锁定"
            )                
        if not user_info['is_active']:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="账户未激活"
            )
            
        # 获取或创建设备ID
        device_id = login_data.device_id or _create_browser_device_id(request)

        # 更新设备刷新令牌
        tokens_manager.update_refresh_token(
            user_id=user_info['user_id'],
            username=user_info['username'],
            roles=user_info['roles'],
            device_id=device_id
        )
        logger.debug(f"更新设备刷新令牌: {device_id}")

        # 创建设备访问令牌并设置到响应
        result = token_sdk.create_and_set_token(
            response=response,
            user_id=user_info['user_id'],
            username=user_info['username'],
            roles=user_info['roles'],
            device_id=device_id
        )

        if result.is_fail():
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=result.error
            )

        # 将访问令牌和刷新令牌都返回，方便客户端存储
        refresh_token = tokens_manager.get_refresh_token(user_info['user_id'], device_id)
        return {
            "access_token": result.data["access_token"],
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "user": user_info
        }

    @handle_errors()
    async def logout_device(
        request: Request,
        response: Response,
        token_claims: Dict[str, Any] = Depends(require_user(token_sdk, update_access_token=False, logger=logger))
    ):
        """退出在设备上的登录"""
        logger.debug(f"要注销的用户信息: {token_claims}")

        # 撤销当前设备的刷新令牌
        tokens_manager.revoke_refresh_token(
            user_id=token_claims['user_id'],
            device_id=token_claims['device_id']
        )
        
        # 撤销当前设备的访问令牌 - 加入黑名单
        token_sdk.revoke_token(
            user_id=token_claims['user_id'],
            device_id=token_claims['device_id']
        )
        
        # 删除当前设备的cookie
        token_sdk.set_token_to_response(response, None)

        return {"message": "注销成功"}

    class ChangePasswordRequest(BaseModel):
        """修改密码请求"""
        current_password: str = Field(..., description="当前密码")
        new_password: str = Field(..., description="新密码")

    @handle_errors()
    async def change_password(
        change_password_form: ChangePasswordRequest,
        response: Response,
        token_claims: Dict[str, Any] = Depends(require_user(token_sdk, logger=logger))
    ):
        """修改密码"""
        result = users_manager.change_password(
            user_id=token_claims['user_id'],
            current_password=change_password_form.current_password,
            new_password=change_password_form.new_password
        )
        if result.is_ok():
            return result
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=result.error
            )

    @handle_errors()
    async def get_user_profile(
        token_claims: Dict[str, Any] = Depends(require_user(token_sdk, logger=logger))
    ):
        """获取当前用户信息"""
        return token_claims

    class UpdateUserProfileRequest(BaseModel):
        """更新用户个人设置请求"""
        to_update: Dict[str, Any] = Field(..., description="用户个人设置")

    @handle_errors()
    async def update_user_profile(
        update_form: UpdateUserProfileRequest,
        response: Response,
        token_claims: Dict[str, Any] = Depends(require_user(token_sdk, logger=logger))
    ):
        """更新当前用户的个人设置"""
        result = users_manager.update_user(token_claims['user_id'], **update_form.to_update)
        if result.is_ok():
            # 更新设备访问令牌
            token_result = token_sdk.create_and_set_token(
                response=response,
                user_id=result.data['user_id'],
                username=result.data['username'],
                roles=result.data['roles'],
                device_id=token_claims['device_id']
            )
            if token_result.is_fail():
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=token_result.error
                )
            return {
                "message": "用户信息更新成功",
                "user": result.data
            }
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=result.error
            )

    @handle_errors()
    async def check_blacklist(token_data: Dict[str, Any]):
        """检查令牌是否在黑名单中"""
        # 确保提供了必要字段
        user_id = token_data.get("user_id")
        device_id = token_data.get("device_id")
        
        if not user_id or not device_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="缺少必要的user_id或device_id字段"
            )
        
        # 检查是否在黑名单中
        is_blacklisted = token_sdk.is_blacklisted(user_id, device_id)
        return {"is_blacklisted": is_blacklisted}
    
    class TokenRequest(BaseModel):
        """令牌请求基类"""
        token: Optional[str] = Field(None, description="访问令牌")
        
    @handle_errors()
    async def renew_token(
        request: Request,
        response: Response,
        token_claims: Dict[str, Any] = Depends(require_user(token_sdk, update_access_token=False, logger=logger))
    ):
        """续订访问令牌
        
        在访问令牌即将过期之前主动调用该接口获取新的访问令牌，
        与通过过期的访问令牌自动刷新访问令牌不同，此方法不需要验证刷新令牌，
        只需验证当前访问令牌有效。
        """
        # 从请求中提取令牌
        token = token_sdk.extract_token_from_request(request)
        if not token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="令牌不存在"
            )
        
        # 手动续订令牌
        renew_result = token_sdk.renew_token(
            token=token,
            user_id=token_claims['user_id'],
            device_id=token_claims['device_id'],
            token_data=token_claims
        )
        
        if renew_result.is_fail():
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=renew_result.error
            )
        
        # 获取新令牌
        new_token = None
        if isinstance(renew_result.data, dict):
            if "access_token" in renew_result.data:
                new_token = renew_result.data["access_token"]
            elif "new_token" in renew_result.data:
                new_token = renew_result.data["new_token"]
        
        if not new_token:
            # 如果没有获取到新令牌，直接创建
            new_token = token_sdk.create_token(
                user_id=token_claims['user_id'],
                username=token_claims['username'],
                roles=token_claims['roles'],
                device_id=token_claims['device_id']
            )
        
        # 设置新令牌到响应
        token_sdk.set_token_to_response(response, new_token)
        
        return {"access_token": new_token, "message": "访问令牌续订成功"}
    
    @handle_errors()
    async def refresh_token(
        request: Request, 
        response: Response,
        token_request: TokenRequest = None
    ):
        """刷新过期的访问令牌
        
        使用过期的访问令牌和存储的刷新令牌获取新的访问令牌。
        此方法主要供其他服务调用，用于在访问令牌过期后获取新的访问令牌。
        """
        # 使用TokenSDK的方法处理令牌刷新
        result = token_sdk.handle_token_refresh(request, response)
        
        if result.is_fail():
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=result.error
            )
        
        # 根据请求类型返回不同格式的结果
        if request.headers.get("accept", "").find("application/json") >= 0:
            # API请求，返回访问令牌
            return result.data
        else:
            # 浏览器请求，只返回成功消息
            return {"message": "访问令牌刷新成功"}
            
    
    return [
        (HttpMethod.POST, f"{prefix}/auth/register", register),
        (HttpMethod.POST, f"{prefix}/auth/login", login),
        (HttpMethod.POST, f"{prefix}/auth/logout", logout_device),
        (HttpMethod.POST, f"{prefix}/auth/change-password", change_password),
        (HttpMethod.POST, f"{prefix}/auth/profile", update_user_profile),
        (HttpMethod.GET, f"{prefix}/auth/profile", get_user_profile),
        (HttpMethod.POST, f"{prefix}/token/blacklist/check", check_blacklist),
        (HttpMethod.POST, f"{prefix}/auth/renew-token", renew_token),
        (HttpMethod.POST, f"{prefix}/auth/refresh-token", refresh_token)
    ]
