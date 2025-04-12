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
from .tokens import TokensManager, TokenBlacklist, TokenClaims
from .users import UsersManager, User, UserRole
from .models import Result

def require_user(
    tokens_manager: TokensManager,
    require_roles: Union[UserRole, List[UserRole]] = None,
    update_access_token: bool = True,
    logger: logging.Logger = None
) -> Callable[[Request, Response], Dict[str, Any]]:
    """验证用户信息

    Args:
        tokens_manager: 令牌管理器
        require_roles: 要求的角色
    """

    async def verified_user(
        request: Request,
        response: Response,
    ) -> Dict[str, Any]:
        """验证用户信息

        如果要求角色，则需要用户具备所有指定的角色。
        """
        # 使用封装好的方法验证请求中的令牌
        verify_result = tokens_manager.verify_request_token(
            request=request,
            response=response,
            update_token=update_access_token
        )
        
        if verify_result.is_fail():
            error = f"令牌验证失败: {verify_result.error}"
            logger.error(error)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, 
                detail=error
            )

        token_claims = verify_result.data
        logger.debug(f"验证用户信息: {token_claims}")

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
) -> Dict[str, Tuple[HttpMethod, str, Callable]]:
    """创建认证相关的API端点
    
    Returns:
        Dict[str, Tuple[HttpMethod, str, Callable]]: 
            键为路由名称，
            值为元组 (HTTP方法, 路由路径, 处理函数)
    """

    logger = logging.getLogger(__name__)

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
        result = tokens_manager.create_and_set_token(
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
        token_claims: TokenClaims = Depends(require_user(tokens_manager, update_access_token=False, logger=logger))
    ):
        """退出在设备上的登录"""
        logger.debug(f"要注销的用户信息: {token_claims}")

        # 撤销当前设备的刷新令牌
        tokens_manager.revoke_refresh_token(
            user_id=token_claims['user_id'],
            device_id=token_claims['device_id']
        )
        
        # 撤销当前设备的访问令牌 - 加入黑名单
        tokens_manager.revoke_access_token(
            user_id=token_claims['user_id'],
            device_id=token_claims['device_id']
        )
        
        # 删除当前设备的cookie
        tokens_manager.set_token_to_response(response, None)

        return {"message": "注销成功"}

    class ChangePasswordRequest(BaseModel):
        """修改密码请求"""
        current_password: str = Field(..., description="当前密码")
        new_password: str = Field(..., description="新密码")

    @handle_errors()
    async def change_password(
        change_password_form: ChangePasswordRequest,
        response: Response,
        token_claims: TokenClaims = Depends(require_user(tokens_manager, logger=logger))
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
        token_claims: TokenClaims = Depends(require_user(tokens_manager, logger=logger))
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
        token_claims: TokenClaims = Depends(require_user(tokens_manager, logger=logger))
    ):
        """更新当前用户的个人设置"""
        result = users_manager.update_user(token_claims['user_id'], **update_form.to_update)
        if result.is_ok():
            # 更新设备访问令牌
            token_result = tokens_manager.create_and_set_token(
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
        
        # 直接使用user_id和device_id组合作为黑名单键
        token_id = f"{user_id}:{device_id}"
        
        # 检查是否在黑名单中
        is_blacklisted = token_blacklist.contains(token_id)
        return {"is_blacklisted": is_blacklisted}
    
    class TokenRequest(BaseModel):
        """令牌请求基类"""
        token: Optional[str] = Field(None, description="访问令牌")
        
    @handle_errors()
    async def renew_token(
        request: Request,
        response: Response,
        token_claims: Dict[str, Any] = Depends(require_user(tokens_manager, update_access_token=False, logger=logger))
    ):
        """续订访问令牌
        
        在访问令牌即将过期之前主动调用该接口获取新的访问令牌，
        与通过过期的访问令牌自动刷新访问令牌不同，此方法不需要验证刷新令牌，
        只需验证当前访问令牌有效。
        """
        # 使用当前有效的访问令牌信息创建新的访问令牌
        result = tokens_manager.renew_access_token(
            user_id=token_claims['user_id'],
            username=token_claims['username'],
            roles=token_claims['roles'],
            device_id=token_claims['device_id']
        )
        
        if result.is_ok():
            # 创建新的访问令牌
            access_token = TokenClaims.create_access_token(**result.data).jwt_encode()
            # 设置令牌到Cookie
            _set_auth_cookies(response, access_token=access_token, logger=logger)
            return {"access_token": access_token, "message": "访问令牌续订成功"}
        else:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=result.error
            )
    
    @handle_errors()
    async def refresh_token(
        request: Request, 
        response: Response,
        token_request: TokenRequest
    ):
        """刷新过期的访问令牌
        
        使用过期的访问令牌和存储的刷新令牌获取新的访问令牌。
        此方法主要供其他服务调用，用于在访问令牌过期后获取新的访问令牌。
        """
        # 使用封装的方法处理令牌刷新
        result = tokens_manager.handle_token_refresh(request, response)
        
        if result.is_fail():
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=result.error
            )
        
        # 根据请求类型返回不同格式的结果
        if "application/json" in request.headers.get("accept", ""):
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
