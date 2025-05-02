# SoulSeal

这是适合Python+FastAPI快速集成的身份管理模块，SoulSeal 取自修仙小说中的「灵魂烙印」。模块内部使用了免安装的键值数据库 RocksDB 来高效存取用户数据。

## 安装

```bash
# 使用pip安装
pip install soulseal

# 或使用Poetry安装（推荐）
poetry add soulseal
```

## 快速开始

### 命令行启动示例路由

通常你不会这样使用，但启动后的 Swagger 文档（通常在`/docs`）很方便你直观了解 API 结构。

```bash
# 直接使用Python模块运行
poetry run python -m soulseal

# 指定主机和端口
poetry run python -m soulseal --host 0.0.0.0 --port 8080

```

## 设计理念

SoulSeal 采用现代化的身份认证架构设计：

1. **JWT身份验证**：使用行业标准的JWT令牌进行身份验证和授权
2. **令牌分离设计**：
   - **访问令牌（Access Token）**：短期有效（默认5分钟），存储在内存中，用于API请求认证
   - **刷新令牌（Refresh Token）**：长期有效（默认30天），存储在HTTP-only Cookie中，用于获取新的访问令牌
3. **无感续订机制**：当访问令牌剩余有效期低于25%时，系统自动续订令牌
4. **黑名单机制**：支持令牌撤销，即使令牌未过期也能立即失效
5. **多设备支持**：同一用户可在多设备同时登录，每个设备使用独立的令牌
6. **内置用户管理**：集成了简单的用户管理模块
7. **基于角色的访问控制**：支持细粒度的权限管理

使用 JWT 令牌是前后端分离应用的最佳实践，因为访问令牌是自包含的，在内存中可以完成快速解析，不会对性能形成阻塞。
而定期使用刷新令牌重新颁发访问令牌平衡了安全性。

## API端点

SoulSeal提供以下API端点（假设前缀为`/api`）：

| 路径 | 方法 | 描述 | 授权 |
|------|------|------|-----|
| `/api/auth/register` | POST | 用户注册 | 否 |
| `/api/auth/login` | POST | 用户登录 | 否 |
| `/api/auth/logout` | POST | 用户退出 | 是 |
| `/api/auth/change-password` | POST | 修改密码 | 是 |
| `/api/auth/profile` | GET/POST | 获取/更新用户信息 | 是 |
| `/api/auth/refresh-token` | POST | 刷新访问令牌（令牌过期丢失或过期时） | 否 |

## 在FastAPI应用中集成

### 推荐集成方式

下面展示如何在自己控制的FastAPI应用中集成SoulSeal认证功能：

```python
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pathlib import Path
from voidring import IndexedRocksDB
from soulseal import TokenSDK, UsersManager, mount_auth_api

# 创建自己的FastAPI应用
app = FastAPI(
    title="我的应用",
    description="集成SoulSeal认证的API",
    version="0.1.0"
)

# 配置CORS（如果前端与后端跨域就必须设置）
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["Authorization"]  # 确保前端可以获取到Authorization头
)

# 初始化数据库和认证组件
db_path = Path.home() / ".myapp" / "db"
db_path.mkdir(parents=True, exist_ok=True)
db = IndexedRocksDB(str(db_path))

# 创建令牌SDK和用户管理器
token_sdk = TokenSDK(db=db)
users_manager = UsersManager(db)

# 挂载SoulSeal认证API
mount_auth_api(
    app=app,
    prefix="/api",
    token_sdk=token_sdk,
    users_manager=users_manager
)
```

### 保护路由的方法

SoulSeal提供了多种方式来保护您的API路由，让您可以根据需求选择最合适的方法：

#### 方法1: 安全路由装饰器（最简洁）

```python
from fastapi import FastAPI, APIRouter
from soulseal import TokenSDK

app = FastAPI()
router = APIRouter()
token_sdk = TokenSDK(db=db)

# 基本认证路由
@token_sdk.secure_route(router, "/secure-route")
async def secure_endpoint():
    return {"message": "此路由受到保护"}

# 需要管理员角色的路由
@token_sdk.secure_route(
    router, 
    "/admin-route", 
    methods=["GET", "POST"],  # 可指定多种HTTP方法
)
async def admin_endpoint(token_claims: dict):
    # token_claims包含用户信息
    return {"message": f"您好，{token_claims.get('username')}"}

# 注册路由
app.include_router(router)
```

#### 方法2: 使用依赖注入（传统方式）

```python
from fastapi import Depends

# 创建认证依赖
require_user = token_sdk.get_auth_dependency()
require_admin = token_sdk.get_auth_dependency(require_roles=["admin"])

# 基本认证
@router.get(
    "/secure-dependency", 
    openapi_extra={"security": [{"Bearer": []}]}
)
async def secure_with_dependency(user = Depends(require_user)):
    return {"message": f"您好，{user.get('username')}"}

# 管理员认证
@router.get(
    "/admin-dependency", 
    openapi_extra={"security": [{"Bearer": []}]}
)
async def admin_with_dependency(user = Depends(require_admin)):
    return {"message": "管理员专属内容"}
```

#### 方法3: 编程式注册（适合批量路由）

```python
from soulseal.start import register_secure_route

async def dynamic_endpoint(token_claims: dict = None):
    """动态创建的受保护端点"""
    return {"message": f"您已通过认证，用户ID: {token_claims.get('user_id')}"}

# 注册安全路由
register_secure_route(
    app=app,
    path="/api/dynamic-route",
    endpoint=dynamic_endpoint,
    require_user=token_sdk.get_auth_dependency(),
    methods=["GET"],
    tags=["动态路由"]
)
```

### 完整后端演示效果

您可以在启用示例路由的情况下启动应用，查看完整的使用方式：

```python
from soulseal import create_app

app = create_app(
    db_path="./data",
    title="SoulSeal演示",
    description="身份认证系统演示",
    cors_origins=["http://localhost:3000"],
    prefix="/api",
    include_examples=True  # 启用示例路由
)
```

这将添加以下示例路由：
- `/api/examples/secure-route` - 使用安全路由装饰器
- `/api/examples/admin-route` - 需要管理员权限(依赖项方式)
- `/api/examples/admin-dependency` - 需要管理员权限(直接依赖方式)
- `/api/examples/secure-dependency` - 使用依赖注入
- `/api/examples/secure-programmatic` - 以编程方式注册的路由

## 客户端使用

```javascript
// auth.js - 认证服务
const auth = {
  token: localStorage.getItem('auth_token'),
  
  // 登录并保存令牌
  async login(username, password) {
    const response = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
      credentials: 'include'
    });
    
    if (!response.ok) throw new Error('登录失败');
    
    // 保存令牌
    const authHeader = response.headers.get('Authorization');
    if (authHeader?.startsWith('Bearer ')) {
      this.token = authHeader.substring(7);
      localStorage.setItem('auth_token', this.token);
    }
    
    return await response.json();
  },
  
  // 创建带认证的请求
  async fetch(url, options = {}) {
    // 添加认证头
    const headers = { ...options.headers };
    if (this.token) {
      headers['Authorization'] = `Bearer ${this.token}`;
    }
    
    // 发送请求
    const response = await fetch(url, {
      ...options,
      headers,
      credentials: 'include'
    });
    
    // 处理自动令牌续订
    const newToken = response.headers.get('Authorization');
    if (newToken?.startsWith('Bearer ')) {
      this.token = newToken.substring(7);
      localStorage.setItem('auth_token', this.token);
    }
    
    // 处理401错误（令牌过期）
    if (response.status === 401) {
      // 尝试刷新令牌
      const refreshed = await this.refreshToken();
      if (refreshed) {
        // 使用新令牌重试请求
        return this.fetch(url, options);
      } else {
        // 刷新失败，重定向到登录页
        this.logout();
        location.href = '/login';
      }
    }
    
    return response;
  },
  
  // 刷新令牌
  async refreshToken() {
    try {
      const response = await fetch('/api/auth/refresh-token', {
        method: 'POST',
        credentials: 'include'
      });
      
      if (!response.ok) return false;
      
      const data = await response.json();
      if (data.access_token) {
        this.token = data.access_token;
        localStorage.setItem('auth_token', this.token);
        return true;
      }
      return false;
    } catch (e) {
      return false;
    }
  },
  
  // 注销
  logout() {
    fetch('/api/auth/logout', {
      method: 'POST',
      headers: this.token ? { 'Authorization': `Bearer ${this.token}` } : {},
      credentials: 'include'
    }).finally(() => {
      this.token = null;
      localStorage.removeItem('auth_token');
    });
  }
};

// 使用示例
async function getUserProfile() {
  const response = await auth.fetch('/api/auth/profile');
  if (response.ok) {
    const profile = await response.json();
    console.log('用户信息:', profile);
    return profile;
  }
  return null;
}
```

## 用户管理功能

SoulSeal提供完整的用户管理功能：

1. **用户注册与登录**：支持用户名、密码和电子邮件注册，密码加密存储
2. **多设备支持**：同一用户可以在多个设备上同时登录，互不干扰
3. **基于角色的访问控制**：支持用户角色设置（用户、管理员等）
4. **个人资料管理**：查看和更新用户信息
5. **密码管理**：支持修改密码、密码重置等功能
6. **会话管理**：查看当前登录设备，可以远程注销特定设备
7. **账号锁定与激活**：管理员可锁定或激活用户账号

## 安全注意事项

1. 默认情况下，访问令牌有效期为5分钟，刷新令牌有效期为7天
2. 访问令牌通过Authorization头部传输，刷新令牌存储在HTTP-only Cookie中，增强安全性
3. 所有密码均使用bcrypt加密存储，无法还原
4. 令牌撤销后会被加入黑名单，即使未过期也无法使用
5. 支持HTTPS，生产环境必须启用
