#!/bin/bash

# 确保脚本在错误时停止执行
set -e

echo "=== 开始构建Next.js应用 ==="

# 确保使用生产环境变量构建
echo "使用生产环境变量..."
export NEXT_PUBLIC_STATIC_EXPORT=true

# 构建Next.js应用
echo "正在构建Next.js应用..."
yarn build

# 检查后端静态目录
BACKEND_STATIC_DIR="../backend/src/soulseal/static"

# 如果目录不存在，创建它
if [ ! -d "$BACKEND_STATIC_DIR" ]; then
    echo "创建后端静态目录: $BACKEND_STATIC_DIR"
    mkdir -p "$BACKEND_STATIC_DIR"
fi

# 复制构建结果到后端静态目录
echo "复制构建结果到后端静态目录..."
cp -r out/* "$BACKEND_STATIC_DIR/"

echo "=== 部署完成 ==="
echo "Next.js应用已成功构建并部署到FastAPI后端静态目录"
echo "你现在可以启动FastAPI服务器来提供完整的应用" 