import uvicorn
import logging
import argparse
import asyncio
import signal
import os
import sys
from fastapi.staticfiles import StaticFiles
from pathlib import Path
import atexit

from .start import create_app

def _parse_args():
    """解析命令行参数"""
    parser = argparse.ArgumentParser(description="启动 SoulSeal 服务器")
    parser.add_argument(
        "--data-dir",
        type=str,
        default=os.environ.get("SOULSEAL_DATA_DIR", str(Path.home() / ".soulseal")),
        help="数据目录的路径"
    )
    parser.add_argument(
        "--host",
        type=str,
        default=os.environ.get("SOULSEAL_HOST", "127.0.0.1"),
        help="主机地址"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("SOULSEAL_PORT", "8000")),
        help="端口号"
    )
    parser.add_argument(
        "--prefix",
        type=str,
        default=os.environ.get("SOULSEAL_PREFIX", "/api"),
        help="API路由前缀"
    )
    parser.add_argument(
        "--cors-origins",
        type=str,
        default=os.environ.get("SOULSEAL_CORS_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000"),
        help="CORS源列表，用逗号分隔"
    )
    parser.add_argument(
        "--jwt-secret-key",
        type=str,
        default=os.environ.get("SOULSEAL_JWT_SECRET_KEY", None),
        help="JWT密钥"
    )
    parser.add_argument(
        "--jwt-algorithm",
        type=str,
        default=os.environ.get("SOULSEAL_JWT_ALGORITHM", None),
        help="JWT算法"
    )
    parser.add_argument(
        "--access-token-expire-minutes",
        type=int,
        default=int(os.environ.get("SOULSEAL_ACCESS_TOKEN_EXPIRE_MINUTES", "0")),
        help="访问令牌过期时间(分钟)，0表示使用默认值"
    )
    parser.add_argument(
        "--refresh-token-expire-days",
        type=int,
        default=int(os.environ.get("SOULSEAL_REFRESH_TOKEN_EXPIRE_DAYS", "0")),
        help="刷新令牌过期时间(天)，0表示使用默认值"
    )
    parser.add_argument(
        "--api-base-url",
        type=str,
        default=os.environ.get("SOULSEAL_API_BASE_URL", None),
        help="API基础URL，用于子服务调用主服务"
    )
    parser.add_argument(
        "--auto-renew-before-expiry-seconds",
        type=int,
        default=int(os.environ.get("SOULSEAL_AUTO_RENEW_BEFORE_EXPIRY_SECONDS", "60")),
        help="访问令牌自动续订的提前时间(秒)"
    )
    args = parser.parse_args()

    # 使用环境变量或默认值
    data_dir = Path(args.data_dir)
    db_path = data_dir / "db"
    
    # 分离CORS源
    cors_origins = args.cors_origins.split(",") if args.cors_origins else []

    # 将静态文件目录设置为data_dir下的static子目录
    static_dir = data_dir / "static"
    static_dir.mkdir(parents=True, exist_ok=True)

    return args

async def main():
    """主函数"""
    args = _parse_args()
    os.environ['LOG_LEVEL'] = "INFO"
    
    # 分离CORS源
    cors_origins = args.cors_origins.split(",") if args.cors_origins else []
    
    app = create_app(
        db_path=str(args.data_dir / "db"),
        title="SoulSeal API",
        description="SoulSeal API文档",
        cors_origins=cors_origins,
        static_dir=str(args.data_dir / "static"),
        prefix=args.prefix,
        jwt_secret_key=args.jwt_secret_key,
        jwt_algorithm=args.jwt_algorithm,
        access_token_expire_minutes=args.access_token_expire_minutes if args.access_token_expire_minutes > 0 else None,
        refresh_token_expire_days=args.refresh_token_expire_days if args.refresh_token_expire_days > 0 else None,
        api_base_url=args.api_base_url,
        auto_renew_before_expiry_seconds=args.auto_renew_before_expiry_seconds
    )

    # 挂载静态文件
    app.mount("/static", StaticFiles(directory=str(args.data_dir / "static")), name="static")

    # 处理信号
    should_exit = False

    def handle_exit(signum, frame):
        nonlocal should_exit
        print(f"收到信号 {signum}，准备关闭服务器...")
        should_exit = True

    # 为各种信号注册处理程序
    signal.signal(signal.SIGINT, handle_exit)
    signal.signal(signal.SIGTERM, handle_exit)
    
    # 在Windows上，SIGBREAK是Ctrl+Break
    if hasattr(signal, 'SIGBREAK'):
        signal.signal(signal.SIGBREAK, handle_exit)
    
    # 为了优雅关闭，我们可以添加一个退出处理程序
    def cleanup():
        if not should_exit:  # 如果尚未处理，则处理
            print("退出中，清理资源...")
            # 这里可以添加任何清理代码
    
    atexit.register(cleanup)

    # 启动服务器
    config = uvicorn.Config(
        app=app,
        host=args.host,
        port=args.port,
        reload=False
    )

    server = uvicorn.Server(config)
    await server.serve()

    return 0

if __name__ == "__main__":
    """
    启动soulseal api服务。

    # 使用方法：
    ## HTTP 开发环境
    poetry run python -m soulseal
    """
    sys.exit(asyncio.run(main())) 