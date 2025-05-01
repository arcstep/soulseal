from voidring import IndexedRocksDB
from .tokens import TokenSDK
from .users import UsersManager
from .endpoints import create_auth_endpoints
from .__version__ import __version__

from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from pathlib import Path
import os
from typing import Callable, Dict, Any, List, Optional, Union

def register_secure_route(
    app: FastAPI, 
    path: str, 
    endpoint: Callable,
    require_user: Callable,
    methods: List[str] = ["GET"],
    tags: List[str] = None,
    **kwargs
):
    """注册需要认证的路由，自动添加认证依赖和OpenAPI安全声明
    
    Args:
        app: FastAPI应用实例
        path: 路由路径
        endpoint: 路由处理函数
        require_user: 认证依赖函数
        methods: HTTP方法
        tags: API标签
        **kwargs: 其他路由参数
    """
    # 检查函数参数中是否已包含require_user依赖
    has_dependency = False
    for param in endpoint.__annotations__.values():
        if getattr(param, "__depends__", None) == require_user:
            has_dependency = True
            break
    
    # 如果函数参数中没有require_user依赖，自动添加
    if not has_dependency:
        endpoint.__dependencies__ = getattr(endpoint, "__dependencies__", []) + [Depends(require_user)]
    
    # 添加OpenAPI安全声明
    kwargs["openapi_extra"] = {"security": [{"Bearer": []}]}
    
    # 注册路由
    app.add_api_route(
        path=path,
        endpoint=endpoint,
        methods=methods,
        tags=tags or [],
        **kwargs
    )
    
    return endpoint

def mount_auth_api(app: FastAPI, prefix: str, token_sdk: TokenSDK, users_manager: UsersManager):
    # 用户管理和认证路由
    auth_handlers = create_auth_endpoints(
        app=app,
        token_sdk=token_sdk,
        users_manager=users_manager,
        prefix=prefix
    )
    
    # 确保OpenAPI组件已初始化
    if not hasattr(app, "openapi_components") or app.openapi_components is None:
        app.openapi_components = {"securitySchemes": {}}
    
    # 添加Bearer认证方案
    app.openapi_components["securitySchemes"]["Bearer"] = {
        "type": "http",
        "scheme": "bearer",
        "bearerFormat": "JWT"
    }
    
    # 需要认证的路径
    authenticated_paths = [
        f"{prefix}/auth/logout", 
        f"{prefix}/auth/change-password",
        f"{prefix}/auth/profile"
    ]
    
    # 获取认证依赖函数
    require_user = token_sdk.get_auth_dependency()
    
    for (method, path, handler) in auth_handlers:
        # 路由参数
        route_params = {
            "path": path,
            "endpoint": handler,
            "methods": [method],
            "response_model": getattr(handler, "__annotations__", {}).get("return"),
            "summary": getattr(handler, "__doc__", "").split("\n")[0] if handler.__doc__ else None,
            "description": getattr(handler, "__doc__", None),
            "tags": ["Illufly Backend - Auth"]
        }
        
        # 如果是需要认证的路径，使用register_secure_route
        if path in authenticated_paths:
            register_secure_route(
                app=app,
                require_user=require_user,
                **route_params
            )
        else:
            app.add_api_route(**route_params)

def create_app(
    db_path: str,
    title: str,
    description: str,
    cors_origins: list[str],
    prefix: str = "",
    include_examples: bool = False
):
    """启动soulseal
    
    Args:
        db_path: 数据库路径
        title: API标题
        description: API描述
        cors_origins: CORS允许的源
        prefix: API路由前缀
        include_examples: 是否包含示例路由
    """
    # 创建 FastAPI 应用实例
    version = __version__
    app = FastAPI(
        title=title,
        description=description,
        version=version
    )

    # 配置 CORS
    origins = cors_origins or [
        # Next.js 开发服务器默认端口
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ]

    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,  # 不再使用 ["*"]
        allow_credentials=True,  # 允许携带凭证
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=["Authorization", "Set-Cookie"]  # 暴露头，允许前端读取
    )

    # 初始化数据库
    db_path = Path(db_path)
    db_path.mkdir(parents=True, exist_ok=True)  # 创建db目录本身，而不仅是父目录
    db = IndexedRocksDB(str(db_path))

    # 创建令牌管理器，传入黑名单和JWT配置
    token_sdk = TokenSDK(db=db)    
    users_manager = UsersManager(db)
    
    # 在挂载API时同样传递黑名单
    mount_auth_api(app, prefix, token_sdk, users_manager)
    
    # 添加示例路由（如果启用）
    if include_examples:
        from .examples.routes import create_example_routes
        create_example_routes(app, token_sdk, prefix)

    return app
