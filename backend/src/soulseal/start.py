from voidring import IndexedRocksDB
from .tokens import TokensManager, TokenBlacklist, TokenSDK
from .tokens.token_models import JWT_SECRET_KEY, JWT_ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES, REFRESH_TOKEN_EXPIRE_DAYS
from .users import UsersManager
from .endpoints import create_auth_endpoints
from .__version__ import __version__

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pathlib import Path
import os

def mount_auth_api(app: FastAPI, prefix: str, tokens_manager: TokensManager, users_manager: UsersManager, blacklist: TokenBlacklist):
    # 用户管理和认证路由
    auth_handlers = create_auth_endpoints(
        app=app,
        tokens_manager=tokens_manager,
        users_manager=users_manager,
        prefix=prefix,
        token_blacklist=blacklist
    )
    for (method, path, handler) in auth_handlers:
        app.add_api_route(
            path=path,
            endpoint=handler,
            methods=[method],
            response_model=getattr(handler, "__annotations__", {}).get("return"),
            summary=getattr(handler, "__doc__", "").split("\n")[0] if handler.__doc__ else None,
            description=getattr(handler, "__doc__", None),
            tags=["Illufly Backend - Auth"])

def create_app(
    db_path: str,
    title: str,
    description: str,
    cors_origins: list[str],
    static_dir: str,
    prefix: str = "/api",
    jwt_secret_key: str = None,
    jwt_algorithm: str = None,
    access_token_expire_minutes: int = None,
    refresh_token_expire_days: int = None,
    api_base_url: str = None,
    auto_renew_before_expiry_seconds: int = 60,
    token_storage_method: str = "cookie"
):
    """启动soulseal
    
    Args:
        db_path: 数据库路径
        title: API标题
        description: API描述
        cors_origins: CORS允许的源
        static_dir: 静态文件目录
        prefix: API路由前缀
        jwt_secret_key: JWT密钥，如果不提供则使用环境变量或默认值
        jwt_algorithm: JWT算法，如果不提供则使用环境变量或默认值
        access_token_expire_minutes: 访问令牌过期时间(分钟)
        refresh_token_expire_days: 刷新令牌过期时间(天)
        api_base_url: API基础URL，用于子服务调用主服务
        auto_renew_before_expiry_seconds: 访问令牌自动续订的提前时间(秒)
        token_storage_method: 访问令牌的存储方式，可选值：cookie, header, both
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
        expose_headers=["Set-Cookie"]  # 暴露 Set-Cookie 头
    )

    # 使用提供的JWT参数或默认值
    jwt_secret = jwt_secret_key or JWT_SECRET_KEY
    jwt_algo = jwt_algorithm or JWT_ALGORITHM
    token_expire_minutes = access_token_expire_minutes or ACCESS_TOKEN_EXPIRE_MINUTES
    refresh_expire_days = refresh_token_expire_days or REFRESH_TOKEN_EXPIRE_DAYS

    # 初始化数据库
    db_path = Path(db_path)
    db_path.mkdir(parents=True, exist_ok=True)  # 创建db目录本身，而不仅是父目录
    db = IndexedRocksDB(str(db_path))
    blacklist = TokenBlacklist()

    # 创建令牌管理器，传入黑名单和JWT配置
    tokens_manager = TokensManager(
        db=db, 
        token_blacklist=blacklist,
        token_storage_method=token_storage_method
    )
    
    # 如果有API基础URL，则使用TokenSDK创建一个公共实例作为应用程序属性
    if api_base_url:
        app.state.token_sdk = TokenSDK(
            jwt_secret_key=jwt_secret,
            jwt_algorithm=jwt_algo,
            access_token_expire_minutes=token_expire_minutes,
            api_base_url=api_base_url,
            auto_renew_before_expiry_seconds=auto_renew_before_expiry_seconds,
            token_storage_method=token_storage_method
        )
    
    users_manager = UsersManager(db)
    
    # 在挂载API时同样传递黑名单
    mount_auth_api(app, prefix, tokens_manager, users_manager, blacklist)

    return app
