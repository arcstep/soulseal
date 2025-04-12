# SoulSeal

这是一套适合Python+FastAPI快速集成的身份管理模块，SoulSeal 取自修仙小说中的「灵魂烙印」。使用RocksDB存储用户数据，无需额外配置关系型数据库。

## 快速开始

### 作为独立的身份认证中心启动

```bash
# 使用Poetry启动（推荐）
poetry run soulseal

# 使用自定义参数
poetry run soulseal --host 0.0.0.0 --port 8080 --token-storage-method header
```

### 命令行参数与环境变量

所有参数均可通过命令行或环境变量（SOULSEAL_参数名）设置：

| 参数 | 环境变量 | 说明 | 默认值 |
|-----|---------|------|-------|
| --data-dir | SOULSEAL_DATA_DIR | 数据目录 | ~/.soulseal |
| --host | SOULSEAL_HOST | 主机地址 | 127.0.0.1 |
| --port | SOULSEAL_PORT | 端口 | 8000 |
| --prefix | SOULSEAL_PREFIX | API前缀 | /api |
| --cors-origins | SOULSEAL_CORS_ORIGINS | CORS源(逗号分隔) | http://localhost:3000,... |
| --jwt-secret-key | SOULSEAL_JWT_SECRET_KEY | JWT密钥 | - |
| --token-storage-method | SOULSEAL_TOKEN_STORAGE_METHOD | 令牌存储方式 | cookie |

## API端点

SoulSeal提供以下API端点（假设前缀为`/api`）：

| 路径 | 方法 | 描述 | 授权 |
|------|------|------|-----|
| `/api/auth/register` | POST | 用户注册 | 否 |
| `/api/auth/login` | POST | 用户登录 | 否 |
| `/api/auth/logout` | POST | 用户退出 | 是 |
| `/api/auth/profile` | GET/POST | 获取/更新用户信息 | 是 |
| `/api/auth/refresh-token` | POST | 刷新访问令牌 | 否 |

## 在FastAPI应用中集成

### 1. 作为中间件集成

```python
from fastapi import FastAPI
from soulseal.start import create_app

app = create_app(
    db_path="/path/to/db",  # RocksDB数据库路径
    title="我的API",
    prefix="/api",
    jwt_secret_key="your-secret-key",
    token_storage_method="cookie"  # 可选: cookie, header, both
)

# 添加自己的路由
@app.get("/hello")
def hello():
    return {"message": "Hello World"}
```

### 2. 保护你的路由

使用TokenSDK验证令牌（推荐）：

```python
from fastapi import FastAPI, Depends, HTTPException
from soulseal.tokens import TokenSDK

app = FastAPI()
token_sdk = TokenSDK(jwt_secret_key="your-secret-key")

# 验证函数
async def verify_token(request: Request, response: Response):
    token = token_sdk.extract_token_from_request(request)
    if not token:
        raise HTTPException(status_code=401, detail="未提供令牌")
    
    verify_result = token_sdk.verify_token(token)
    if verify_result.is_fail():
        raise HTTPException(status_code=401, detail=verify_result.error)
    
    return verify_result.data

@app.get("/protected")
async def protected_route(token_data = Depends(verify_token)):
    return {"message": f"你好，{token_data['username']}!"}
```

也可以使用require_user函数（适合完整集成环境）：

```python
from fastapi import Depends
from soulseal import require_user

@app.get("/admin")
def admin_route(user_data = Depends(require_user(tokens_manager, require_roles=["admin"]))):
    return {"message": "管理员页面"}
```

## 令牌存储方式

SoulSeal支持三种令牌存储方式，可通过`token_storage_method`参数设置：

- **cookie模式**（默认）：将令牌存储在HTTP Cookie中
  - 优点：简单，前端无需处理
  - 适合：传统Web应用

- **header模式**：将令牌通过HTTP响应头返回
  - 优点：适合前后端分离、跨域应用
  - 适合：React/Vue等单页应用

- **both模式**：同时使用Cookie和Header
  - 优点：兼容性最佳
  - 缺点：略显冗余

### 前端使用示例（header模式）

```javascript
// 登录获取令牌
async function login(username, password) {
  const response = await fetch('/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password })
  });
  
  // 从响应头获取令牌
  const token = response.headers.get('X-Access-Token');
  localStorage.setItem('token', token);
  
  return token;
}

// 访问受保护资源
async function fetchProtectedResource() {
  const token = localStorage.getItem('token');
  const response = await fetch('/api/protected', {
    headers: { 'Authorization': `Bearer ${token}` }
  });
  return await response.json();
}
```

## CORS配置说明

当你在跨域环境中使用SoulSeal时，需正确配置CORS：

```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,  # 允许携带凭证（Cookie）
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["X-Access-Token"]  # 暴露令牌头（header模式必需）
)
```

## 最佳实践

1. **生产环境配置**：
   - 使用强健的JWT密钥
   - 启用HTTPS
   - 合理设置令牌过期时间

2. **令牌存储方式选择**：
   - 单域名应用：使用`cookie`模式
   - 前后端分离：使用`header`模式
   - 混合环境：使用`both`模式

3. **微服务架构**：
   - 部署一个中心SoulSeal服务
   - 各微服务使用TokenSDK远程模式验证令牌
