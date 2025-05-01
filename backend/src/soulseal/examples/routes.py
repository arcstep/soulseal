from fastapi import APIRouter, FastAPI, Depends, Response, HTTPException, status
from typing import Dict, Any, Optional

from ..tokens import TokenSDK
from ..users import UserRole

# 示例如何使用TokenSDK的安全路由功能
def create_example_routes(app: FastAPI, token_sdk: TokenSDK, prefix: str = "/api"):
    """创建示例路由，展示三种保护路由的方式"""
    router = APIRouter(prefix=f"{prefix}/examples", tags=["示例路由"])
    
    # 方法1：使用安全路由装饰器 - 最简洁方式
    @token_sdk.secure_route(router, "/secure-route", methods=["GET"])
    async def secure_with_route():
        """使用安全路由装饰器保护的路由
        
        这个路由使用@token_sdk.secure_route装饰器自动处理路由注册、认证依赖和OpenAPI安全声明
        """
        return {"message": "您已通过认证访问此路由", "method": "安全路由方式"}
    
    # 方法1-B：安全路由装饰器 + 管理员角色要求
    # 有两种方式实现角色限制：
    
    # 1. 通过单独的依赖项参数
    @token_sdk.secure_route(
        router, 
        "/admin-route", 
        methods=["GET"],
        dependencies=[Depends(token_sdk.get_auth_dependency(require_roles=["admin"]))]
    )
    async def admin_with_route_deps():
        """需要管理员权限的路由（通过依赖项实现）
        
        这个路由使用安全路由装饰器并添加管理员角色要求依赖项
        只有具有admin角色的用户才能访问
        """
        return {"message": "您已通过管理员认证访问此路由", "method": "依赖项方式"}
    
    # 2. 直接在get_auth_dependency中指定角色
    admin_auth = token_sdk.get_auth_dependency(require_roles=["admin"])
    
    @router.get("/admin-dependency", openapi_extra={"security": [{"Bearer": []}]})
    async def admin_with_dependency(token_claims: Dict[str, Any] = Depends(admin_auth)):
        """需要管理员权限的路由（通过依赖函数实现）
        
        这个路由使用带有管理员角色要求的Depends(admin_auth)依赖
        只有具有admin角色的用户才能访问
        """
        return {
            "message": f"您已通过管理员认证访问此路由，用户名: {token_claims.get('username')}",
            "method": "直接依赖方式"
        }
    
    # 方法2：使用常规依赖注入（传统方式）
    require_user = token_sdk.get_auth_dependency()
    
    @router.get("/secure-dependency", openapi_extra={"security": [{"Bearer": []}]})
    async def secure_with_dependency(token_claims: Dict[str, Any] = Depends(require_user)):
        """使用依赖注入保护的路由
        
        这个路由使用Depends(require_user)依赖注入和手动添加openapi_extra实现认证
        """
        return {
            "message": f"您已通过认证访问此路由，用户名: {token_claims.get('username')}",
            "method": "依赖注入方式"
        }
    
    # 方法3：使用register_secure_route函数（适合编程方式添加路由）
    from ..start import register_secure_route
    
    async def secure_programmatic(token_claims: Dict[str, Any] = None):
        """以编程方式注册的安全路由
        
        这个路由使用register_secure_route函数注册，自动添加认证依赖和OpenAPI安全声明
        """
        return {
            "message": f"您已通过认证访问此路由，用户ID: {token_claims.get('user_id')}",
            "method": "编程注册方式"
        }
    
    # 注册路由，token_claims会由register_secure_route函数自动添加依赖
    register_secure_route(
        app=app,
        path=f"{prefix}/examples/secure-programmatic",
        endpoint=secure_programmatic,
        require_user=require_user,
        methods=["GET"],
        response_model=Dict[str, Any],
        summary="以编程方式注册的安全路由",
        description=secure_programmatic.__doc__,
        tags=["示例路由"]
    )
    
    # 将路由器包含到应用中
    app.include_router(router)
    
    return router 