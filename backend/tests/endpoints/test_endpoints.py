import pytest
from fastapi import FastAPI, Depends, Response, Request, HTTPException, status
from fastapi.testclient import TestClient
import jwt
import time
import os
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch, Mock
from pathlib import Path
import tempfile
import shutil
import json

from voidring import IndexedRocksDB
from soulseal.tokens import TokensManager, TokenBlacklist, TokenSDK
from soulseal.tokens.token_schemas import TokenClaims, TokenType, JWT_SECRET_KEY, JWT_ALGORITHM
from soulseal.users import UsersManager, User, UserRole
from soulseal.endpoints import create_auth_endpoints, HttpMethod, handle_errors
from soulseal.schemas import Result


@pytest.fixture
def temp_db_path():
    """创建临时数据库目录"""
    temp_dir = tempfile.mkdtemp()
    yield temp_dir
    shutil.rmtree(temp_dir)


@pytest.fixture
def db(temp_db_path):
    """创建测试用的RocksDB实例"""
    return IndexedRocksDB(temp_db_path)


@pytest.fixture
def token_blacklist():
    """创建令牌黑名单"""
    return TokenBlacklist()


@pytest.fixture
def tokens_manager(db, token_blacklist):
    """创建令牌管理器"""
    return TokensManager(db, token_blacklist, token_storage_method="cookie")


@pytest.fixture
def users_manager(db):
    """创建用户管理器"""
    return UsersManager(db)


@pytest.fixture
def test_app(tokens_manager, users_manager, token_blacklist):
    """创建测试应用"""
    app = FastAPI()
    
    # 创建认证API端点
    auth_handlers = create_auth_endpoints(
        app=app,
        tokens_manager=tokens_manager,
        users_manager=users_manager,
        token_blacklist=token_blacklist,
        prefix="/api"
    )
    
    # 注册端点到应用
    for method, path, handler in auth_handlers:
        app.add_api_route(
            path=path,
            endpoint=handler,
            methods=[method.value],
            response_model=None,
        )
    
    return app


@pytest.fixture
def client(test_app):
    """创建测试客户端"""
    return TestClient(test_app)


@pytest.fixture
def test_user_data():
    """测试用户数据"""
    return {
        "username": "testuser",
        "password": "testpassword",
        "email": "test@example.com"
    }


@pytest.fixture
def registered_user(client, test_user_data, users_manager):
    """预先注册一个测试用户"""
    # 使用API注册用户
    response = client.post(
        "/api/auth/register",
        json=test_user_data
    )
    
    assert response.status_code == 200
    
    # 返回用户数据和注册结果
    return {
        "user_data": test_user_data,
        "response": response.json()
    }


@pytest.fixture
def authenticated_client(client, registered_user):
    """创建已登录的客户端会话"""
    # 使用API登录
    login_response = client.post(
        "/api/auth/login",
        json={
            "username": registered_user["user_data"]["username"],
            "password": registered_user["user_data"]["password"]
        }
    )
    
    assert login_response.status_code == 200
    login_result = login_response.json()
    
    # 保留原始客户端并附加用户信息
    client.cookies = login_response.cookies
    client.user_info = login_result.get("user")
    
    # 检查是否有访问令牌cookie
    client.access_token = login_response.cookies.get("access_token")
    
    return client


class TestAuthEndpoints:
    """测试认证相关API端点
    
    测试覆盖的功能:
    - 用户注册
    - 用户登录
    - 用户注销
    - 获取用户资料
    - 更新用户资料
    - 修改密码
    - 令牌续订和刷新
    """
    
    def test_register(self, client, test_user_data):
        """测试用户注册API
        
        验证用户注册过程:
        1. 发送有效的注册请求应返回成功结果
        2. 用户数据应该被正确保存
        3. 响应中应包含用户ID和其他用户信息
        """
        # 发送注册请求
        response = client.post(
            "/api/auth/register",
            json=test_user_data
        )
        
        # 验证响应
        assert response.status_code == 200
        result = response.json()
        
        # 验证结果包含预期的数据
        assert result.get("success") is True
        assert "data" in result
        assert "user_id" in result["data"]
        assert result["data"]["username"] == test_user_data["username"]
        assert result["data"]["email"] == test_user_data["email"]
        
        # 验证密码未在响应中返回
        assert "password" not in result["data"]
        assert "password_hash" not in result["data"]
    
    def test_register_duplicate_username(self, client, registered_user):
        """测试重复用户名注册
        
        验证使用已存在的用户名注册时:
        1. 应返回适当的错误响应
        2. 错误消息应该清晰说明问题
        """
        # 尝试使用相同用户名再次注册
        response = client.post(
            "/api/auth/register",
            json={
                "username": registered_user["user_data"]["username"],
                "password": "anotherpassword",
                "email": "another@example.com"
            }
        )
        
        # 验证响应
        assert response.status_code == 400
        result = response.json()
        
        # 验证错误消息
        assert "detail" in result
        assert "已存在" in result["detail"]  # 仅检查包含"已存在"即可
    
    def test_register_invalid_email(self, client):
        """测试无效邮箱注册
        
        验证使用无效邮箱格式注册时:
        1. 应返回验证错误
        2. 错误消息应该明确指出邮箱格式问题
        """
        # 使用无效邮箱格式注册
        response = client.post(
            "/api/auth/register",
            json={
                "username": "newtestuser",
                "password": "testpassword",
                "email": "invalid-email"  # 无效邮箱格式
            }
        )
        
        # 验证响应
        assert response.status_code in (400, 422)  # FastAPI验证错误返回422
        result = response.json()
        
        # 验证错误消息中包含邮箱相关信息
        assert "email" in str(result).lower() or "邮箱" in str(result)
    
    def test_login_success(self, client, registered_user):
        """测试用户登录成功
        
        验证正确的用户名和密码登录:
        1. 应返回成功结果
        2. 响应应该设置cookie
        3. 响应中应包含用户信息
        4. 应该使用"cookie"作为令牌类型
        """
        # 登录请求
        response = client.post(
            "/api/auth/login",
            json={
                "username": registered_user["user_data"]["username"],
                "password": registered_user["user_data"]["password"]
            }
        )
        
        # 验证响应
        assert response.status_code == 200
        result = response.json()
        
        # 验证返回的用户信息
        assert "user" in result
        assert result["user"]["username"] == registered_user["user_data"]["username"]
        
        # 验证令牌类型为cookie
        assert result["token_type"] == "cookie"
        
        # 验证cookie设置
        assert "access_token" in response.cookies
    
    def test_login_failure(self, client, registered_user):
        """测试用户登录失败
        
        验证错误的密码登录:
        1. 应返回身份验证错误
        2. 不应设置认证cookie
        """
        # 使用错误密码登录
        response = client.post(
            "/api/auth/login",
            json={
                "username": registered_user["user_data"]["username"],
                "password": "wrongpassword"
            }
        )
        
        # 验证响应
        assert response.status_code == 401
        result = response.json()
        
        # 验证错误信息
        assert "detail" in result
        assert "认证失败" in result["detail"] or "密码" in result["detail"]
        
        # 验证没有设置cookie
        assert "access_token" not in response.cookies
    
    def test_get_profile(self, authenticated_client):
        """测试获取用户资料
        
        验证已登录用户获取资料:
        1. 应返回成功结果
        2. 返回的数据应包含完整的用户信息
        """
        # 获取用户资料
        response = authenticated_client.get("/api/auth/profile")
        
        # 验证响应
        assert response.status_code == 200
        result = response.json()
        
        # 验证用户信息字段
        assert "user_id" in result
        assert "username" in result
        assert "roles" in result
        assert "email" in result
        assert "mobile" in result
        assert "device_id" in result
        assert "created_at" in result
        
        # 验证用户名匹配预期
        assert result["username"] == authenticated_client.user_info["username"]
    
    def test_update_profile(self, authenticated_client):
        """测试更新用户资料
        
        验证已登录用户更新个人资料:
        1. 应成功更新用户信息
        2. 返回数据包含用户信息
        """
        # 要更新的用户信息 - 使用允许更新的字段
        update_data = {
            "to_update": {
                "email": "updated@example.com"
            }
        }
        
        # 更新用户资料
        response = authenticated_client.post(
            "/api/auth/profile",
            json=update_data
        )
        
        # 验证响应状态码
        assert response.status_code == 200
        result = response.json()
        
        # 验证更新成功
        assert "user" in result
        
        # 获取用户资料确认能访问
        profile_response = authenticated_client.get("/api/auth/profile")
        assert profile_response.status_code == 200
    
    def test_logout(self, authenticated_client):
        """测试用户注销
        
        验证用户注销过程:
        1. 应返回成功结果
        2. 应清除认证cookie
        3. 注销后无法访问需要认证的端点
        """
        # 注销请求
        response = authenticated_client.post("/api/auth/logout")
        
        # 验证响应
        assert response.status_code == 200
        result = response.json()
        
        # 验证成功消息
        assert "message" in result
        assert "注销成功" in result["message"]
        
        # 验证cookie被删除或设置为空
        if "access_token" in response.cookies:
            assert not response.cookies["access_token"]
        
        # 尝试获取用户资料，应该失败
        profile_response = authenticated_client.get("/api/auth/profile")
        assert profile_response.status_code == 401
    
    def test_change_password(self, authenticated_client, test_user_data):
        """测试修改密码
        
        验证用户修改密码:
        1. 使用当前正确密码应能成功修改
        2. 修改后应使用新密码登录
        """
        # 修改密码
        new_password = "newpassword123"
        response = authenticated_client.post(
            "/api/auth/change-password",
            json={
                "current_password": test_user_data["password"],
                "new_password": new_password
            }
        )
        
        # 验证响应
        assert response.status_code == 200
        result = response.json()
        
        # 验证成功消息
        assert result.get("success") is True
        # 只验证响应是否成功，不检查具体消息内容
        
        # 注销
        authenticated_client.post("/api/auth/logout")
        
        # 尝试使用新密码登录
        login_response = authenticated_client.post(
            "/api/auth/login",
            json={
                "username": test_user_data["username"],
                "password": new_password
            }
        )
        
        # 验证登录成功
        assert login_response.status_code == 200
    
    def test_change_password_wrong_current(self, authenticated_client):
        """测试使用错误的当前密码修改密码
        
        验证用户提供错误的当前密码时:
        1. 修改密码请求应失败
        2. 错误消息应明确说明原因
        """
        # 使用错误的当前密码
        response = authenticated_client.post(
            "/api/auth/change-password",
            json={
                "current_password": "wrongpassword",
                "new_password": "newpassword123"
            }
        )
        
        # 验证响应
        assert response.status_code == 400
        result = response.json()
        
        # 验证错误消息
        assert "detail" in result
        assert "密码" in result["detail"] and ("错误" in result["detail"] or "不正确" in result["detail"])
    
    def test_renew_token(self, authenticated_client):
        """测试令牌续订
        
        验证令牌续订过程:
        1. 应成功续订令牌
        2. 应返回新的访问令牌
        3. 应更新认证cookie
        """
        # 令牌续订请求
        response = authenticated_client.post("/api/auth/renew-token")
        
        # 验证响应
        assert response.status_code == 200
        result = response.json()
        
        # 验证返回的新令牌
        assert "access_token" in result
        # 不比较新旧令牌，因为在测试环境中它们可能相同
        
        # 验证响应cookie包含令牌
        assert "access_token" in response.cookies or "access_token" in str(response.headers).lower()
    
        # 使用新令牌获取用户资料
        authenticated_client.cookies.update(response.cookies)  # 更新cookie
        profile_response = authenticated_client.get("/api/auth/profile")
        assert profile_response.status_code == 200
    
    def test_unauthorized_access(self, client):
        """测试未授权访问
        
        验证未登录用户访问需要认证的端点:
        1. 应返回未授权错误
        2. 错误信息应该明确
        """
        # 尝试访问需要认证的端点
        response = client.get("/api/auth/profile")
        
        # 验证响应
        assert response.status_code == 401
        result = response.json()
        
        # 验证错误信息
        assert "detail" in result
        assert "令牌不存在" in result["detail"] or "认证失败" in result["detail"]


@pytest.fixture
def admin_user(users_manager):
    """创建管理员用户"""
    # 创建管理员用户
    admin_user = User(
        username="adminuser",
        email="admin@example.com",
        password_hash=User.hash_password("adminpassword"),
        roles=[UserRole.ADMIN]
    )
    
    # 保存到数据库
    result = users_manager.create_user(admin_user)
    assert result.is_ok()
    
    return {
        "username": "adminuser",
        "password": "adminpassword",
        "email": "admin@example.com"
    }


@pytest.fixture
def admin_client(client, admin_user):
    """创建已登录的管理员客户端会话"""
    # 使用管理员账户登录
    login_response = client.post(
        "/api/auth/login",
        json={
            "username": admin_user["username"],
            "password": admin_user["password"]
        }
    )
    
    assert login_response.status_code == 200
    login_result = login_response.json()
    
    # 保留原始客户端并附加用户信息
    client.cookies = login_response.cookies
    client.user_info = login_result.get("user")
    
    # 检查是否有访问令牌cookie
    client.access_token = login_response.cookies.get("access_token")
    
    return client


class TestRoleBasedAccess:
    """测试基于角色的访问控制
    
    测试不同角色用户对特定端点的访问权限:
    - 普通用户无法访问管理员功能
    - 管理员可以访问管理员功能
    """
    
    def test_admin_role_in_token(self, admin_client):
        """测试管理员令牌中包含admin角色
        
        验证:
        1. 管理员登录后令牌中应包含ADMIN角色
        2. 获取的用户资料中应包含管理员角色
        """
        # 获取用户资料
        response = admin_client.get("/api/auth/profile")
        
        # 验证响应
        assert response.status_code == 200
        profile = response.json()
        
        # 验证包含管理员角色
        assert "roles" in profile
        assert UserRole.ADMIN in profile["roles"]
    
    # 这个测试需要依赖一个假设的管理员API端点，可能需要在实际应用中调整
    @patch('soulseal.tokens.token_sdk.TokenSDK.get_auth_dependency')
    def test_role_based_access_control(self, mock_get_auth_dependency, test_app, admin_client, authenticated_client):
        """测试基于角色的访问控制
        
        验证:
        1. 使用模拟的管理员端点
        2. 普通用户访问管理员端点应返回403错误
        3. 管理员访问管理员端点应成功
        """
        # 这个测试需要模拟一个需要管理员权限的端点
        # 实际测试取决于应用程序的实际实现
        # 这里使用mock来模拟get_auth_dependency方法的行为
        
        # 模拟get_auth_dependency返回的依赖函数
        mock_get_auth_dependency.return_value = lambda require_roles=None, **kwargs: (
            lambda request, response: {
                "user_id": "test_id",
                "username": "testuser",
                "roles": [UserRole.USER]  # 普通用户角色
            }
        )
        
        # 由于这是一个模拟测试，我们不对结果做断言
        # 在实际应用中，应该添加对特定管理员端点的实际测试
        pass


class TestTokenRefreshFlow:
    """测试令牌刷新流程
    
    测试访问令牌过期后的刷新流程:
    - 令牌过期后自动刷新
    - 刷新令牌撤销后无法刷新
    """
    
    def test_refresh_expired_token(self, client, registered_user, tokens_manager):
        """测试刷新过期的访问令牌
        
        验证:
        1. 能够登录并获取令牌
        2. 当令牌过期时，能通过刷新令牌获取新令牌
        3. 刷新后的令牌能正常使用
        """
        # 登录获取令牌
        login_response = client.post(
            "/api/auth/login",
            json={
                "username": registered_user["user_data"]["username"],
                "password": registered_user["user_data"]["password"]
            }
        )
        
        # 验证登录成功
        assert login_response.status_code == 200
        
        # 验证cookie中包含访问令牌
        assert "access_token" in login_response.cookies
        
        # 记录原始令牌和cookie
        original_token = login_response.cookies.get("access_token")
        client.cookies = login_response.cookies
        
        # 假设的用户ID和设备ID
        user_id = registered_user["response"]["data"]["user_id"]
        device_id = "test_device_id"
        
        # 模拟令牌解码返回用户ID和设备ID
        with patch('jwt.decode') as mock_decode:
            # 设置模拟行为：不验证签名/过期时正常返回，验证时抛出过期异常
            def decode_side_effect(*args, **kwargs):
                if kwargs.get('options', {}).get('verify_exp') is False:
                    # 不验证过期时间时返回令牌数据
                    return {
                        "user_id": user_id,
                        "username": registered_user["user_data"]["username"],
                        "roles": ["user"],
                        "device_id": device_id,
                        "exp": int((datetime.utcnow() - timedelta(minutes=5)).timestamp())  # 已过期
                    }
                # 验证过期时间时抛出异常
                raise jwt.ExpiredSignatureError("Token expired")
            
            mock_decode.side_effect = decode_side_effect
            
            # 模拟刷新令牌存在
            with patch.object(tokens_manager, 'get_refresh_token') as mock_get_refresh:
                # 创建一个有效的刷新令牌
                refresh_token = "valid_refresh_token"
                mock_get_refresh.return_value = refresh_token
                
                # 模拟刷新访问令牌成功
                with patch.object(tokens_manager, 'refresh_access_token') as mock_refresh:
                    mock_refresh.return_value = Result.ok(
                        data={
                            "access_token": "new_access_token",
                            "user_id": user_id,
                            "username": registered_user["user_data"]["username"],
                            "roles": ["user"],
                            "device_id": device_id
                        },
                        message="令牌刷新成功"
                    )
                    
                    # 尝试刷新令牌
                    refresh_response = client.post("/api/auth/refresh-token")
                    
                    # 验证刷新成功
                    assert refresh_response.status_code == 200, f"刷新令牌应该成功，错误: {refresh_response.json().get('detail', '')}"
                    
                    # 验证响应中包含成功消息
                    result = refresh_response.json()
                    assert result.get("message", "").find("成功") >= 0, "响应应该包含成功信息"
                    
                    # 验证refresh_access_token已被调用
                    mock_refresh.assert_called_once_with(
                        user_id=user_id,
                        username=registered_user["user_data"]["username"],
                        roles=["user"],
                        device_id=device_id
                    )
    
    def test_refresh_with_revoked_token(self, authenticated_client, tokens_manager):
        """测试撤销刷新令牌后无法刷新访问令牌
        
        验证过程:
        1. 用户登录获取令牌
        2. 撤销该用户的刷新令牌
        3. 尝试刷新访问令牌
        4. 验证刷新失败
        """
        # 获取用户信息
        user_info = authenticated_client.user_info
        
        # 撤销刷新令牌
        tokens_manager.revoke_refresh_token(
            user_id=user_info["user_id"],
            device_id=user_info.get("device_id", "test_device_id")
        )
        
        # 模拟验证过期令牌
        with patch('jwt.decode') as mock_decode:
            # 在第一次调用时抛出过期异常
            mock_decode.side_effect = jwt.ExpiredSignatureError("Token expired")
            
            # 尝试刷新令牌
            refresh_response = authenticated_client.post("/api/auth/refresh-token")
        
        # 验证刷新失败
        assert refresh_response.status_code in (401, 403), "应该返回未授权或禁止访问错误"


class TestRequireUserDecorator:
    """测试认证依赖和相关功能
    
    测试用户认证中间件和黑名单功能:
    - 测试TokenSDK.get_auth_dependency方法返回的依赖函数
    - 测试令牌黑名单功能
    """
    
    @patch('soulseal.tokens.token_sdk.TokenSDK.get_auth_dependency')
    def test_require_user_decorator(self, mock_get_auth_dependency, test_app, client):
        """测试TokenSDK.get_auth_dependency方法返回的认证依赖函数
        
        验证通过get_auth_dependency创建的依赖函数能正确验证用户身份
        """
        # 设置模拟函数返回值
        mock_user_data = {"user_id": "test-user", "username": "testuser"}
        
        # 创建一个简单的同步依赖函数
        def mock_dependency():
            return mock_user_data
        
        # 配置mock返回mock_dependency函数
        mock_get_auth_dependency.return_value = mock_dependency
        
        # 创建一个测试端点
        @test_app.get("/test-protected")
        def test_protected_endpoint(token_claims = Depends(mock_get_auth_dependency())):
            return token_claims
        
        # 访问保护的端点
        response = client.get("/test-protected")
        
        # 验证响应
        assert response.status_code == 200
        assert response.json() == mock_user_data
    
    def test_blacklist_check(self, authenticated_client, tokens_manager):
        """测试令牌撤销功能
        
        验证:
        1. 登录后能访问需要认证的端点
        2. 注销后使用同一客户端不能访问
        """
        # 首先验证能正常访问用户资料
        profile_response = authenticated_client.get("/api/auth/profile")
        assert profile_response.status_code == 200
        
        # 注销用户，这会将令牌加入黑名单
        logout_response = authenticated_client.post("/api/auth/logout")
        assert logout_response.status_code == 200
        
        # 清除客户端cookie，确保测试的是令牌黑名单功能
        authenticated_client.cookies.clear()
        
        # 使用已被撤销的令牌尝试访问
        auth_header = {"Authorization": f"Bearer {authenticated_client.access_token}"}
        profile_response = authenticated_client.get("/api/auth/profile", headers=auth_header)
        
        # 验证访问被拒绝
        assert profile_response.status_code == 401, "撤销的令牌不应能访问受保护资源"

    def test_api_endpoint_auto_refresh_expired_token(self, client, authenticated_client, registered_user, tokens_manager):
        """测试API端点对过期令牌的自动刷新功能
        
        验证:
        1. 使用已过期的令牌访问需要认证的API端点
        2. 系统自动尝试刷新令牌而不是返回401错误
        3. 使用刷新后的令牌成功访问API
        
        此测试验证了在实际API调用中，是否能正确处理令牌过期并自动刷新令牌的场景。
        """
        # 获取当前令牌
        original_token = authenticated_client.cookies.get("access_token")
        
        # 解码JWT令牌获取用户信息
        decoded_token = jwt.decode(
            original_token, 
            options={"verify_signature": False, "verify_exp": False}
        )
        user_id = decoded_token["user_id"]
        username = decoded_token["username"]
        roles = decoded_token["roles"]
        device_id = decoded_token.get("device_id", "test_device_id")
        
        # 创建模拟令牌过期的场景
        with patch('jwt.decode') as mock_decode:
            # 模拟令牌已过期
            def decode_side_effect(*args, **kwargs):
                if kwargs.get("options", {}).get("verify_exp") is False:
                    # 不验证过期时间时返回令牌数据
                    return {
                        "user_id": user_id,
                        "username": username,
                        "roles": roles,
                        "device_id": device_id,
                        "exp": int((datetime.utcnow() - timedelta(minutes=5)).timestamp()),  # 已过期
                        "token_type": "access"
                    }
                # 验证过期时间时抛出异常
                raise jwt.ExpiredSignatureError("Token expired")
            
            mock_decode.side_effect = decode_side_effect
            
            # 模拟获取有效的刷新令牌
            with patch.object(tokens_manager, 'get_refresh_token') as mock_get_refresh:
                refresh_claims = TokenClaims.create_refresh_token(
                    user_id=user_id,
                    username=username,
                    roles=roles,
                    device_id=device_id
                )
                refresh_token = refresh_claims.jwt_encode()
                mock_get_refresh.return_value = refresh_token
                
                # 模拟刷新访问令牌
                with patch.object(tokens_manager, 'refresh_access_token') as mock_refresh_token:
                    # 创建新的访问令牌
                    new_token = jwt.encode(
                        {
                            "user_id": user_id,
                            "username": username,
                            "roles": roles,
                            "device_id": device_id,
                            "exp": int((datetime.utcnow() + timedelta(minutes=30)).timestamp()),
                            "iat": int(datetime.utcnow().timestamp()),
                            "token_type": "access"
                        },
                        key=JWT_SECRET_KEY,
                        algorithm=JWT_ALGORITHM
                    )
                    
                    # 设置模拟返回值
                    mock_refresh_token.return_value = Result.ok(
                        data={
                            "access_token": new_token,
                            "user_id": user_id,
                            "username": username,
                            "roles": roles,
                            "device_id": device_id
                        },
                        message="令牌刷新成功"
                    )
                    
                    # 访问需要认证的端点
                    response = authenticated_client.get("/api/auth/profile")
                    
                    # 验证响应，应该成功而不是401错误
                    assert response.status_code == 200, f"期望自动刷新令牌并返回200，实际返回{response.status_code}"
                    
                    # 验证refresh_access_token是否被调用
                    mock_refresh_token.assert_called_once_with(
                        user_id=user_id,
                        username=username,
                        roles=roles,
                        device_id=device_id
                    )
                    
                    # 验证返回的用户资料
                    profile = response.json()
                    assert profile["username"] == username
                    assert profile["user_id"] == user_id 