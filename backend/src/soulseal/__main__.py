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

    args = parser.parse_args()

    # 使用环境变量或默认值
    data_dir = Path(args.data_dir)
    db_path = os.path.join(data_dir, "db")
    
    # 分离CORS源
    cors_origins = args.cors_origins.split(",") if args.cors_origins else []

    # 将静态文件目录设置为data_dir下的static子目录
    static_dir = os.path.join(data_dir, "static")
    os.makedirs(static_dir, exist_ok=True)

    return args

async def main():
    """主函数"""
    args = _parse_args()
    os.environ['LOG_LEVEL'] = "INFO"
    
    # 分离CORS源
    cors_origins = args.cors_origins.split(",") if args.cors_origins else []
    static_dir = os.path.join(args.data_dir, "static")
    
    app = create_app(
        db_path=os.path.join(args.data_dir, "db"),
        title="SoulSeal API",
        description="SoulSeal API文档",
        cors_origins=cors_origins,
        static_dir=static_dir,
        prefix=args.prefix
    )

    # 挂载静态文件
    app.mount("/static", StaticFiles(directory=static_dir), name="static")

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

def run_main():
    """入口点函数，用于poetry脚本执行"""
    return asyncio.run(main())

if __name__ == "__main__":
    """
    启动soulseal api服务。

    # 使用方法：
    ## HTTP 开发环境
    poetry run soulseal

    # 环境变量：
    - SOULSEAL_DATA_DIR: 数据目录路径，默认为~/.soulseal
    - SOULSEAL_HOST: 主机地址，默认为127.0.0.1
    - SOULSEAL_PORT: 端口号，默认为8000
    - SOULSEAL_PREFIX: API路由前缀，默认为/api
    - SOULSEAL_CORS_ORIGINS: CORS源列表，默认为http://localhost:3000,http://127.0.0.1:3000
    """
    sys.exit(asyncio.run(main())) 