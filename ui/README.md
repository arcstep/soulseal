# SoulSeal UI

SoulSeal的前端界面，基于Next.js构建。

## 开发环境设置

### 安装依赖
```bash
yarn install
```

### 启动开发服务器
```bash
# 直接启动开发服务器
yarn dev

# 或使用自定义脚本（使用环境变量）
yarn dev:custom
```

### 构建和部署
```bash
# 构建Next.js应用并部署到后端静态目录
yarn deploy
```

## 跨域开发

项目配置为在开发过程中支持跨域请求:

- 前端运行在 http://localhost:3001
- 后端运行在 http://localhost:8001
- Next.js的API路由请求会自动代理到后端API

## 环境变量

项目使用以下环境变量:

- `NEXT_PUBLIC_API_BASE_URL`: 客户端API请求的基础URL
- `API_BASE_URL`: 服务器端API请求的基础URL
- `PORT`: 开发服务器端口（默认3001）

这些变量在`.env.development`和`.env.production`文件中设置。
