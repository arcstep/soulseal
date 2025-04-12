import pytest
import os
import time
import jwt
from datetime import datetime, timedelta
from fastapi import FastAPI, Request, Response
from fastapi.testclient import TestClient
import logging

from soulseal.tokens import TokenSDK, TokensManager, TokenBlacklist
from soulseal.users import UsersManager
from soulseal.models import Result
from soulseal.endpoints import create_auth_endpoints

# 简化的测试配置
@pytest.fixture
def jwt_secret_key():
    return "test_secret_key_for_testing_only"

@pytest.fixture
def jwt_algorithm():
    return "HS256"

@pytest.fixture
def test_db_path(tmp_path):
    """创建临时数据库路径"""
    return os.path.join(tmp_path, "test_db")

@pytest.fixture
def token_blacklist(test_db_path):
    """创建令牌黑名单"""
    return TokenBlacklist()

@pytest.fixture(params=["cookie", "header", "both"])
def token_storage_method(request):
    """参数化token存储方式，测试所有三种方式"""
    return request.param

@pytest.fixture
def tokens_manager(token_blacklist, jwt_secret_key, jwt_algorithm, token_storage_method):
    """创建令牌管理器"""
    class MockDB:
        def __init__(self):
            self.refresh_tokens = {}
            self._logger = logging.getLogger(__name__)
            
        def get(self, key, default=None):
            return self.refresh_tokens.get(key, default)
            
        def put(self, key, value):
            self._logger.debug(f"存储键值对: {key} = {value}")
            self.refresh_tokens[key] = value
            
        def delete(self, key):
            if key in self.refresh_tokens:
                del self.refresh_tokens[key]
                return True
            return False
            
        def keys_by_prefix(self, prefix):
            return [k for k in self.refresh_tokens.keys() if k.startswith(prefix)]
    
    mock_db = MockDB()
    return TokensManager(
        db=mock_db,
        token_blacklist=token_blacklist,
        token_storage_method=token_storage_method
    )

@pytest.fixture
def token_sdk(tokens_manager, jwt_secret_key, jwt_algorithm):
    """创建令牌SDK"""
    return TokenSDK(
        tokens_manager=tokens_manager,
        jwt_secret_key=jwt_secret_key,
        jwt_algorithm=jwt_algorithm,
        token_storage_method=tokens_manager.token_storage_method
    )

@pytest.fixture
def users_manager():
    """创建模拟用户管理器"""
    class MockUsersManager:
        def __init__(self):
            self.users = {}
            
        def create_user(self, user):
            self.users[user.user_id] = user
            return Result.ok(data=user.model_dump())
            
        def get_user(self, user_id):
            return self.users.get(user_id)
            
        def verify_password(self, username, password):
            """模拟密码验证"""
            return Result.ok(data={
                'user_id': 'test_user_id',
                'username': username,
                'roles': ['user'],
                'is_locked': False,
                'is_active': True
            })
    
    return MockUsersManager()

@pytest.fixture
def test_app(tokens_manager, users_manager, token_blacklist):
    """创建测试FastAPI应用"""
    app = FastAPI()
    
    # 添加认证端点
    auth_endpoints = create_auth_endpoints(
        app=app,
        tokens_manager=tokens_manager,
        users_manager=users_manager,
        token_blacklist=token_blacklist
    )
    
    # 手动注册端点
    for method, path, handler in auth_endpoints:
        app.add_api_route(
            path=path,
            endpoint=handler,
            methods=[method.value]
        )
        
    return app

@pytest.fixture
def client(test_app):
    """创建测试客户端"""
    return TestClient(test_app)

@pytest.fixture
def logged_in_client(client, token_storage_method, tokens_manager):
    """创建已登录的客户端"""
    login_data = {
        "username": "test_user",
        "password": "test_password",
        "device_id": "test_device"
    }
    
    # 准备刷新令牌
    tokens_manager.update_refresh_token(
        user_id="test_user_id",
        username="test_user",
        roles=["user"],
        device_id="test_device"
    )
    
    # 进行登录
    login_response = client.post("/api/auth/login", json=login_data)
    assert login_response.status_code == 200
    
    # 记录原始客户端的cookie
    client_with_login = TestClient(client.app)
    
    # 如果是cookie存储，需要保存并携带cookie
    if token_storage_method in ["cookie", "both"]:
        for cookie in client.cookies:
            client_with_login.cookies.set(cookie.name, cookie.value)
    
    # 如果是header存储，需要设置Authorization头
    if token_storage_method in ["header", "both"]:
        token = login_response.json().get("access_token")
        if token:
            client_with_login.headers["Authorization"] = f"Bearer {token}"
    
    # 保存token信息便于测试使用
    client_with_login.token_info = {
        "token_type": login_response.json().get("token_type", ""),
        "access_token": login_response.json().get("access_token", "")
    }
    
    return client_with_login

@pytest.fixture
def expired_token(jwt_secret_key, jwt_algorithm):
    """创建一个已过期的访问令牌"""
    payload = {
        "user_id": "test_user_id",
        "username": "test_user",
        "roles": ["user"],
        "device_id": "test_device",
        "exp": datetime.utcnow() - timedelta(minutes=5)  # 5分钟前已过期
    }
    return jwt.encode(payload, jwt_secret_key, algorithm=jwt_algorithm)

def test_token_storage_in_login_response(client, token_storage_method):
    """测试登录响应中的token存储方式"""
    login_data = {
        "username": "test_user",
        "password": "test_password"
    }
    
    response = client.post("/api/auth/login", json=login_data)
    assert response.status_code == 200
    
    # 检查响应中的token_type
    if token_storage_method == "cookie":
        assert response.json()["token_type"] == "cookie"
        assert "access_token" not in response.json()
        assert "access_token" in [cookie.name for cookie in client.cookies]
    else:
        assert response.json()["token_type"] == "bearer"
        assert "access_token" in response.json()

def test_refresh_token_with_cookie_storage(client, tokens_manager, expired_token, token_storage_method):
    """测试使用Cookie存储方式下的令牌刷新"""
    # 只在cookie或both模式下执行此测试
    if token_storage_method not in ["cookie", "both"]:
        pytest.skip(f"跳过非cookie存储方式: {token_storage_method}")
    
    # 设置刷新令牌（模拟有效的刷新令牌）
    tokens_manager.update_refresh_token(
        user_id="test_user_id",
        username="test_user",
        roles=["user"],
        device_id="test_device"
    )
    
    # 使用cookie发送过期的令牌
    client.cookies.set("access_token", expired_token)
    
    # 请求刷新令牌
    response = client.post("/api/auth/refresh-token")
    assert response.status_code == 200
    
    # 验证响应
    assert response.json()["message"] == "访问令牌刷新成功"
    
    # 验证新令牌已设置在cookie中
    assert "access_token" in [cookie.name for cookie in client.cookies]
    
    # 验证响应中没有直接返回令牌
    assert "access_token" not in response.json()
    assert response.json()["token_type"] == "cookie"

def test_refresh_token_with_header_storage(client, tokens_manager, expired_token, token_storage_method):
    """测试使用Header存储方式下的令牌刷新"""
    # 只在header或both模式下执行此测试
    if token_storage_method not in ["header", "both"]:
        pytest.skip(f"跳过非header存储方式: {token_storage_method}")
    
    # 设置刷新令牌（模拟有效的刷新令牌）
    tokens_manager.update_refresh_token(
        user_id="test_user_id",
        username="test_user",
        roles=["user"],
        device_id="test_device"
    )
    
    # 使用Authorization头发送过期的令牌
    headers = {"Authorization": f"Bearer {expired_token}"}
    
    # 请求刷新令牌
    response = client.post("/api/auth/refresh-token", headers=headers)
    assert response.status_code == 200
    
    # 验证响应
    assert response.json()["message"] == "访问令牌刷新成功"
    
    # 验证响应中直接返回了新令牌
    assert "access_token" in response.json()
    assert response.json()["token_type"] == "bearer"

def test_refresh_token_with_json_body(client, tokens_manager, expired_token):
    """测试使用请求体中的令牌进行刷新"""
    # 设置刷新令牌（模拟有效的刷新令牌）
    tokens_manager.update_refresh_token(
        user_id="test_user_id",
        username="test_user",
        roles=["user"],
        device_id="test_device"
    )
    
    # 使用请求体发送过期的令牌
    request_data = {"token": expired_token}
    
    # 请求刷新令牌
    response = client.post("/api/auth/refresh-token", json=request_data)
    assert response.status_code == 200
    
    # 验证响应
    assert response.json()["message"] == "访问令牌刷新成功"

def test_remote_mode_token_refresh(jwt_secret_key, jwt_algorithm, token_storage_method):
    """测试远程模式下的令牌刷新，模拟子服务调用主服务"""
    import responses
    
    # 创建远程模式的TokenSDK
    remote_token_sdk = TokenSDK(
        jwt_secret_key=jwt_secret_key,
        jwt_algorithm=jwt_algorithm,
        auth_base_url="http://main-service",
        token_storage_method=token_storage_method
    )
    
    # 创建一个过期的访问令牌
    payload = {
        "user_id": "test_user_id",
        "username": "test_user",
        "roles": ["user"],
        "device_id": "test_device", 
        "exp": datetime.utcnow() - timedelta(minutes=5)  # 5分钟前已过期
    }
    expired_token = jwt.encode(payload, jwt_secret_key, algorithm=jwt_algorithm)
    
    # 模拟HTTP请求和响应
    with responses.RequestsMock() as rsps:
        # 创建新的访问令牌作为刷新结果
        new_payload = {
            "user_id": "test_user_id",
            "username": "test_user",
            "roles": ["user"],
            "device_id": "test_device",
            "exp": datetime.utcnow() + timedelta(minutes=15)  # 15分钟后过期
        }
        new_token = jwt.encode(new_payload, jwt_secret_key, algorithm=jwt_algorithm)
        
        # 模拟主服务的刷新令牌响应
        rsps.add(
            responses.POST, 
            "http://main-service/api/auth/refresh-token",
            json={
                "success": True,
                "data": {
                    "access_token": new_token,
                    "token_storage_method": token_storage_method
                },
                "message": "令牌刷新成功"
            },
            status=200
        )
        
        # 创建模拟请求和响应对象
        class MockRequest:
            def __init__(self, headers={}, cookies={}):
                self.headers = headers
                self.cookies = cookies
                
            def json(self):
                return {}
        
        class MockResponse:
            def __init__(self):
                self.headers = {}
                self.cookies_to_set = {}
                
            def set_cookie(self, key, value, **kwargs):
                self.cookies_to_set[key] = value
        
        # 根据存储方式设置请求
        mock_request = None
        if token_storage_method == "cookie":
            mock_request = MockRequest(cookies={"access_token": expired_token})
        elif token_storage_method == "header":
            mock_request = MockRequest(headers={"Authorization": f"Bearer {expired_token}"})
        else:  # both
            mock_request = MockRequest(
                headers={"Authorization": f"Bearer {expired_token}"},
                cookies={"access_token": expired_token}
            )
            
        mock_response = MockResponse()
        
        # 执行令牌刷新
        result = remote_token_sdk.handle_token_refresh(mock_request, mock_response)
        
        # 验证结果
        assert result.is_ok()
        assert "access_token" in result.data
        assert result.data["token_storage_method"] == token_storage_method
        
        # 验证响应设置
        if token_storage_method in ["cookie", "both"]:
            assert "access_token" in mock_response.cookies_to_set

def test_logout_properly_removes_token(logged_in_client, token_storage_method):
    """测试注销功能在不同存储方式下正确移除令牌"""
    # 执行注销
    response = logged_in_client.post("/api/auth/logout")
    assert response.status_code == 200
    
    # 检查cookie是否被删除
    if token_storage_method in ["cookie", "both"]:
        # FastAPI TestClient不支持检查删除的cookie，但可以检查响应中的头部
        if "Set-Cookie" in response.headers:
            cookie_header = response.headers["Set-Cookie"]
            assert "access_token=;" in cookie_header or "access_token=" in cookie_header
    
    # 验证是否可以访问需要认证的端点
    profile_response = logged_in_client.get("/api/auth/profile")
    assert profile_response.status_code == 401, "注销后仍能访问需要认证的端点"

def test_token_refresh_from_child_service():
    """测试子服务调用主服务刷新令牌的场景（集成测试）"""
    # 这个测试需要启动两个服务或使用更复杂的模拟，暂时跳过
    # 在实际项目中可以使用工厂方法或上下文管理器来管理测试服务
    pytest.skip("需要更复杂的测试设置，此示例暂时跳过")

def test_child_service_refresh_failure_scenarios(jwt_secret_key, jwt_algorithm):
    """测试子服务中令牌刷新失败的情况"""
    import responses
    
    # 测试不同的存储方式
    for storage_method in ["cookie", "header", "both"]:
        # 创建远程模式的TokenSDK
        remote_token_sdk = TokenSDK(
            jwt_secret_key=jwt_secret_key,
            jwt_algorithm=jwt_algorithm,
            auth_base_url="http://main-service",
            token_storage_method=storage_method
        )
        
        # 创建一个过期的访问令牌
        payload = {
            "user_id": "test_user_id",
            "username": "test_user",
            "roles": ["user"],
            "device_id": "test_device", 
            "exp": datetime.utcnow() - timedelta(minutes=5)  # 5分钟前已过期
        }
        expired_token = jwt.encode(payload, jwt_secret_key, algorithm=jwt_algorithm)
        
        # 模拟HTTP请求和响应 - 模拟401未授权错误
        with responses.RequestsMock() as rsps:
            # 模拟主服务返回401错误
            rsps.add(
                responses.POST, 
                "http://main-service/api/auth/refresh-token",
                json={
                    "success": False,
                    "detail": "刷新令牌已过期或不存在"
                },
                status=401
            )
            
            # 创建模拟请求和响应对象
            class MockRequest:
                def __init__(self, headers={}, cookies={}):
                    self.headers = headers
                    self.cookies = cookies
                    
                def json(self):
                    return {}
            
            class MockResponse:
                def __init__(self):
                    self.headers = {}
                    self.cookies_to_set = {}
                    
                def set_cookie(self, key, value, **kwargs):
                    self.cookies_to_set[key] = value
            
            # 根据存储方式设置请求
            mock_request = None
            if storage_method == "cookie":
                mock_request = MockRequest(cookies={"access_token": expired_token})
            elif storage_method == "header":
                mock_request = MockRequest(headers={"Authorization": f"Bearer {expired_token}"})
            else:  # both
                mock_request = MockRequest(
                    headers={"Authorization": f"Bearer {expired_token}"},
                    cookies={"access_token": expired_token}
                )
                
            mock_response = MockResponse()
            
            # 执行令牌刷新
            result = remote_token_sdk.handle_token_refresh(mock_request, mock_response)
            
            # 验证结果是失败的
            assert result.is_fail()
            assert "刷新令牌失败" in result.error

def test_multiple_refresh_token_methods(jwt_secret_key, jwt_algorithm):
    """测试同时使用多种方式传递令牌进行刷新的情况"""
    import responses
    
    # 使用both模式，同时支持cookie和header
    remote_token_sdk = TokenSDK(
        jwt_secret_key=jwt_secret_key,
        jwt_algorithm=jwt_algorithm,
        auth_base_url="http://main-service",
        token_storage_method="both"
    )
    
    # 创建一个过期的访问令牌
    payload = {
        "user_id": "test_user_id",
        "username": "test_user",
        "roles": ["user"],
        "device_id": "test_device", 
        "exp": datetime.utcnow() - timedelta(minutes=5)  # 5分钟前已过期
    }
    expired_token = jwt.encode(payload, jwt_secret_key, algorithm=jwt_algorithm)
    
    # 模拟HTTP请求和响应
    with responses.RequestsMock() as rsps:
        # 创建新的访问令牌作为刷新结果
        new_payload = {
            "user_id": "test_user_id",
            "username": "test_user",
            "roles": ["user"],
            "device_id": "test_device",
            "exp": datetime.utcnow() + timedelta(minutes=15)  # 15分钟后过期
        }
        new_token = jwt.encode(new_payload, jwt_secret_key, algorithm=jwt_algorithm)
        
        # 直接添加模拟响应，不使用回调
        rsps.add(
            responses.POST, 
            "http://main-service/api/auth/refresh-token",
            json={
                "success": True,
                "data": {
                    "access_token": new_token,
                    "token_storage_method": "both"
                },
                "message": "令牌刷新成功"
            },
            status=200
        )
        
        # 创建模拟请求和响应对象
        class MockRequest:
            def __init__(self, headers={}, cookies={}):
                self.headers = headers
                self.cookies = cookies
                
            def json(self):
                return {"token": expired_token, "token_storage_method": "both"}
        
        class MockResponse:
            def __init__(self):
                self._headers = {}  # 使用_headers作为内部属性
                self.cookies_to_set = {}
                
            def set_cookie(self, key, value, **kwargs):
                self.cookies_to_set[key] = value
                
            # 使用属性装饰器来访问_headers
            @property
            def headers(self):
                return self._headers
                
            # 设置器方法
            @headers.setter
            def headers(self, value):
                self._headers = value
        
        # 同时使用cookie和header方式传递令牌
        mock_request = MockRequest(
            headers={"Authorization": f"Bearer {expired_token}"},
            cookies={"access_token": expired_token}
        )
            
        mock_response = MockResponse()
        
        # 执行令牌刷新
        result = remote_token_sdk.handle_token_refresh(mock_request, mock_response)
        
        # 验证结果
        assert result.is_ok()
        assert "access_token" in result.data
        assert result.data["token_storage_method"] == "both"
        
        # 验证响应包含cookie
        assert "access_token" in mock_response.cookies_to_set 