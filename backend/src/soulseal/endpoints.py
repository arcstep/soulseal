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
from .tokens import TokenBlacklistProvider, TokenClaims, TokenSDK
from .users import UsersManager, User, UserRole
from .schemas import Result

def create_auth_endpoints(
    app: FastAPI,
    token_sdk: TokenSDK,
    users_manager: UsersManager,
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
    
    require_user = token_sdk.get_auth_dependency(logger=logger)

    # 创建管理员专用认证依赖
    require_admin = token_sdk.get_auth_dependency(
        require_roles=[UserRole.ADMIN]
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
        device_id = _create_browser_device_id(request)

        # 创建设备访问令牌并设置到响应
        result = token_sdk.create_session(
            response=response,
            user_id=user_info['user_id'],
            username=user_info['username'],
            roles=user_info['roles'],
            device_id=device_id,
            path=f"{prefix}/auth"
        )

        if result.is_fail():
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=result.error
            )

        # 直接返回用户信息和token_type，不再根据token_storage_method判断
        return {
            "token_type": "cookie", # 假设默认使用cookie
            "user": user_info
        }

    @handle_errors()
    async def logout_device(
        request: Request,
        response: Response,
        token_claims: Dict[str, Any] = Depends(require_user)
    ):
        """退出在设备上的登录"""
        logger.debug(f"要注销的用户信息: {token_claims}")

        # 撤销当前设备的访问令牌 - 加入黑名单
        token_sdk.revoke_token(
            user_id=token_claims['user_id'],
            device_id=token_claims['device_id']
        )
        
        # 删除当前设备的cookie
        token_sdk.set_token_to_response(response, None, path=f"{prefix}/auth")

        return {"message": "注销成功"}

    class ChangePasswordRequest(BaseModel):
        """修改密码请求"""
        current_password: str = Field(..., description="当前密码")
        new_password: str = Field(..., description="新密码")

    @handle_errors()
    async def change_password(
        change_password_form: ChangePasswordRequest,
        response: Response,
        token_claims: Dict[str, Any] = Depends(require_user)
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
        token_claims: Dict[str, Any] = Depends(require_user)
    ):
        """获取当前用户信息
        
        从数据库获取完整的用户资料，包括：
        - 用户ID、用户名、角色
        - 电子邮箱、手机号及其验证状态
        - 个人资料（显示名称、个人简介等）
        """
        # 从令牌中获取用户ID
        user_id = token_claims.get("user_id")
        logger.debug(f"获取用户资料: {user_id}")
        
        # 从数据库获取完整的用户信息
        user = users_manager.get_user(user_id)
        if not user:
            logger.error(f"用户不存在: {user_id}")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="用户不存在"
            )
        
        # 记录用户对象中的字段
        logger.debug(f"用户对象字段: {[f for f in dir(user) if not f.startswith('_')]}")
        logger.debug(f"display_name: '{getattr(user, 'display_name', '<无>')}'")
        logger.debug(f"bio: '{getattr(user, 'bio', '<无>')}'")
        
        # 转换为字典并排除密码哈希
        user_data = user.model_dump(exclude={"password_hash"})
        
        # 记录序列化后的字段
        logger.debug(f"序列化后字段: {list(user_data.keys())}")
        logger.debug(f"序列化display_name: '{user_data.get('display_name', '<无>')}'")
        logger.debug(f"序列化bio: '{user_data.get('bio', '<无>')}'")
        
        # 将设备ID添加到用户数据中
        user_data["device_id"] = token_claims.get("device_id")
        
        # 确保display_name和bio字段存在
        if "display_name" not in user_data:
            logger.warning(f"用户 {user_id} 缺少display_name字段，添加默认值")
            user_data["display_name"] = user_data.get("username", "")
        
        if "bio" not in user_data:
            logger.warning(f"用户 {user_id} 缺少bio字段，添加默认值")
            user_data["bio"] = ""
        
        return user_data

    class UpdateUserProfileRequest(BaseModel):
        """更新用户个人设置请求"""
        to_update: Dict[str, Any] = Field(..., description="用户个人设置")

    @handle_errors()
    async def update_user_profile(
        update_form: UpdateUserProfileRequest,
        response: Response,
        token_claims: Dict[str, Any] = Depends(require_user)
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
    
    class TokenRequest(BaseModel):
        """令牌请求基类"""
        token: Optional[str] = Field(None, description="访问令牌")
        

    @handle_errors()
    async def refresh_token(
        request: Request, 
        response: Response
    ):
        """刷新过期的访问令牌"""
        # 记录请求信息，帮助诊断问题
        logger.debug(f"收到令牌刷新请求, Cookie: {request.cookies}, Headers: {request.headers}")

        # 使用TokenSDK的方法处理令牌刷新
        result = token_sdk.handle_token_refresh(request, response)
        
        # 如果刷新失败，返回错误
        if result.is_fail():
            logger.error(f"刷新令牌失败: {result.error}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=result.error
            )
        
        # 简化响应逻辑
        if request.headers.get("accept", "").find("application/json") >= 0:
            # API请求，始终返回消息
            resp_data = {"message": "访问令牌刷新成功"}
            # 如果结果中有access_token，也一并返回
            if "access_token" in result.data:
                resp_data["access_token"] = result.data["access_token"]
                resp_data["token_type"] = "bearer"
            return resp_data
        else:
            # 浏览器请求，只返回成功消息
            return {"message": "访问令牌刷新成功"}
            
    @handle_errors()
    async def list_all_users(
        token_claims: Dict[str, Any] = Depends(require_admin)
    ):
        """获取所有用户列表（仅管理员）"""
        users_list = users_manager.list_users()
        # 排除敏感信息
        return [user.model_dump(exclude={"password_hash"}) for user in users_list]

    class UserActionRequest(BaseModel):
        """用户操作请求"""
        user_id: str = Field(..., description="用户ID")

    @handle_errors()
    async def lock_user(
        request: UserActionRequest,
        token_claims: Dict[str, Any] = Depends(require_admin)
    ):
        """锁定用户（仅管理员）"""
        result = users_manager.lock_user(request.user_id)
        if result.is_ok():
            return {"message": f"用户 {request.user_id} 已锁定", "user": result.data}
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=result.error
            )

    @handle_errors()
    async def unlock_user(
        request: UserActionRequest,
        token_claims: Dict[str, Any] = Depends(require_admin)
    ):
        """解锁用户（仅管理员）"""
        result = users_manager.unlock_user(request.user_id)
        if result.is_ok():
            return {"message": f"用户 {request.user_id} 已解锁", "user": result.data}
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=result.error
            )

    return [
        (HttpMethod.POST, f"{prefix}/auth/register", register),
        (HttpMethod.POST, f"{prefix}/auth/login", login),
        (HttpMethod.POST, f"{prefix}/auth/logout", logout_device),
        (HttpMethod.POST, f"{prefix}/auth/change-password", change_password),
        (HttpMethod.POST, f"{prefix}/auth/profile", update_user_profile),
        (HttpMethod.GET, f"{prefix}/auth/profile", get_user_profile),
        (HttpMethod.POST, f"{prefix}/auth/refresh-token", refresh_token),
        (HttpMethod.GET, f"{prefix}/admin/users", list_all_users),
        (HttpMethod.POST, f"{prefix}/admin/users/lock", lock_user),
        (HttpMethod.POST, f"{prefix}/admin/users/unlock", unlock_user)
    ]
