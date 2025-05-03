#!/bin/bash

# 从.env.development文件加载环境变量
if [ -f .env.development ]; then
    export $(grep -v '^#' .env.development | xargs)
    echo "已加载.env.development环境变量"
else
    echo "警告: .env.development文件不存在"
fi

# 启动Next.js开发服务器
echo "启动Next.js开发服务器: http://localhost:${PORT:-3001}"
yarn dev -p ${PORT:-3001} 