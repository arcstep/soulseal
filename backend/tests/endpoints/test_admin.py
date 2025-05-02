# backend/tests/endpoints/test_admin.py
import pytest
import tempfile
import shutil
import json
import logging
from fastapi import FastAPI, status
from fastapi.testclient import TestClient
from unittest.mock import patch

from voidring import IndexedRocksDB
from soulseal.users import UsersManager, User, UserRole
from soulseal.tokens import TokensManager, TokenSDK, MemoryTokenBlacklist
from soulseal.endpoints import create_auth_endpoints

# 设置日志级别为DEBUG
logger = logging.getLogger(__name__)


@pytest.fixture
def temp_db_path():
    """创建临时数据库目录"""
    temp_dir = tempfile.mkdtemp()
    yield temp_dir
    try:
        shutil.rmtree(temp_dir)
    except Exception as e:
        print(f"清理临时目录失败: {str(e)}")


@pytest.fixture
def db(temp_db_path):
    """创建测试用的RocksDB实例"""
    db = IndexedRocksDB(temp_db_path)
    yield db
    try:
        db.close()
    except:
        pass


@pytest.fixture
def blacklist():
    """创建黑名单实例"""
    return MemoryTokenBlacklist()


@pytest.fixture
def token_sdk(db, blacklist):
    """创建令牌SDK"""
    return TokenSDK(
        jwt_secret_key="test-secret-key",
        db=db,
        auth_server=True,
        blacklist_provider=blacklist
    )


@pytest.fixture
def users_manager(db):
    """创建用户管理器"""
    return UsersManager(db)


@pytest.fixture
def test_app(token_sdk, users_manager):
    """创建测试应用"""
    app = FastAPI()
    
    # 创建认证API端点
    auth_handlers = create_auth_endpoints(
        app=app,
        token_sdk=token_sdk,
        users_manager=users_manager,
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
def admin_user(users_manager):
    """创建一个管理员用户"""
    admin = User(
        username="adminuser",
        password_hash=User.hash_password("adminpassword"),
        email="admin@example.com",
        roles=[UserRole.ADMIN]
    )
    
    result = users_manager.create_user(admin)
    assert result.is_ok()
    return admin


@pytest.fixture
def regular_user(users_manager):
    """创建一个普通用户"""
    user = User(
        username="regularuser",
        password_hash=User.hash_password("userpassword"),
        email="user@example.com",
        roles=[UserRole.USER]
    )
    
    result = users_manager.create_user(user)
    assert result.is_ok()
    return user


@pytest.fixture
def admin_client(client, admin_user):
    """创建已认证的管理员客户端"""
    response = client.post(
        "/api/auth/login",
        json={
            "username": admin_user.username,
            "password": "adminpassword"
        }
    )
    
    assert response.status_code == 200
    
    token = response.headers.get("Authorization", "")
    if token.startswith("Bearer "):
        token = token.split(" ")[1]
    else:
        data = response.json()
        token = data.get("access_token", "")
    
    assert token, "登录响应中没有获取到访问令牌"
    
    client.headers.update({"Authorization": f"Bearer {token}"})
    client.cookies.update(response.cookies)
    
    return client


@pytest.fixture
def user_client(client, regular_user):
    """创建已认证的普通用户客户端"""
    response = client.post(
        "/api/auth/login",
        json={
            "username": regular_user.username,
            "password": "userpassword"
        }
    )
    
    assert response.status_code == 200
    
    token = response.headers.get("Authorization", "")
    if token.startswith("Bearer "):
        token = token.split(" ")[1]
    else:
        data = response.json()
        token = data.get("access_token", "")
    
    assert token, "登录响应中没有获取到访问令牌"
    
    client.headers.update({"Authorization": f"Bearer {token}"})
    client.cookies.update(response.cookies)
    
    return client


class TestAdminUserManagement:
    """管理员用户管理API测试"""
    
    def test_list_all_users(self, admin_client, admin_user, regular_user):
        """测试管理员列举所有用户"""
        response = admin_client.get("/api/admin/users")
        
        assert response.status_code == 200
        users_list = response.json()
        
        assert isinstance(users_list, list)
        assert len(users_list) >= 2  # 至少包含管理员和普通用户
        
        # 验证返回的用户信息中包含admin_user和regular_user
        usernames = [user["username"] for user in users_list]
        assert admin_user.username in usernames
        assert regular_user.username in usernames
        
        # 验证不包含敏感信息
        for user in users_list:
            assert "password_hash" not in user
    
    def test_lock_user(self, admin_client, regular_user, users_manager, client):
        """测试管理员锁定用户"""
        response = admin_client.post(
            "/api/admin/users/lock",
            json={"user_id": regular_user.user_id}
        )
        
        assert response.status_code == 200
        result = response.json()
        
        assert "message" in result
        assert f"用户 {regular_user.user_id} 已锁定" in result["message"]
        assert "user" in result
        assert result["user"]["is_locked"] == True
        
        # 验证数据库中用户状态已更新
        updated_user = users_manager.get_user(regular_user.user_id)
        assert updated_user.is_locked == True
        
        # 尝试使用被锁定的用户登录
        login_response = client.post(
            "/api/auth/login",
            json={
                "username": regular_user.username,
                "password": "userpassword"
            }
        )
        
        # 锁定用户登录应该失败，返回403状态码
        assert login_response.status_code == 403
        assert "账户已锁定" in login_response.json()["detail"]
    
    def test_unlock_user(self, admin_client, regular_user, users_manager, client):
        """测试管理员解锁用户"""
        # 先锁定用户
        lock_response = admin_client.post(
            "/api/admin/users/lock",
            json={"user_id": regular_user.user_id}
        )
        assert lock_response.status_code == 200
        
        # 然后解锁用户
        unlock_response = admin_client.post(
            "/api/admin/users/unlock",
            json={"user_id": regular_user.user_id}
        )
        
        assert unlock_response.status_code == 200
        result = unlock_response.json()
        
        assert "message" in result
        assert f"用户 {regular_user.user_id} 已解锁" in result["message"]
        assert "user" in result
        assert result["user"]["is_locked"] == False
        
        # 验证数据库中用户状态已更新
        updated_user = users_manager.get_user(regular_user.user_id)
        assert updated_user.is_locked == False
        
        # 尝试使用解锁后的用户登录
        login_response = client.post(
            "/api/auth/login",
            json={
                "username": regular_user.username,
                "password": "userpassword"
            }
        )
        
        # 解锁用户登录应该成功
        assert login_response.status_code == 200
    
    def test_regular_user_cannot_access_admin_api(self, user_client, regular_user):
        """测试普通用户无法访问管理员API"""
        # 尝试列举所有用户
        list_response = user_client.get("/api/admin/users")
        assert list_response.status_code == 403
        
        # 尝试锁定用户
        lock_response = user_client.post(
            "/api/admin/users/lock",
            json={"user_id": regular_user.user_id}
        )
        assert lock_response.status_code == 403
        
        # 尝试解锁用户
        unlock_response = user_client.post(
            "/api/admin/users/unlock",
            json={"user_id": regular_user.user_id}
        )
        assert unlock_response.status_code == 403