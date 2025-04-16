import pytest
import tempfile
import shutil
import json
import logging
from fastapi import FastAPI, status
from fastapi.testclient import TestClient

from voidring import IndexedRocksDB
from soulseal.users import UsersManager, User
from soulseal.tokens import TokensManager, TokenBlacklist
from soulseal.endpoints import create_auth_endpoints

# 设置日志级别为DEBUG，以便观察更详细的信息
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
def test_user(users_manager):
    """创建一个测试用户，并设置display_name和bio字段"""
    logger.info("创建测试用户...")
    # 创建用户对象
    user = User(
        username="testprofile",
        password_hash=User.hash_password("password123"),
        email="test_profile@example.com",
        display_name="测试显示名称",
        bio="这是一个测试用户简介"
    )
    
    # 检查用户对象中是否有display_name和bio字段
    user_dict = user.model_dump()
    logger.info(f"创建的用户对象字段: {list(user_dict.keys())}")
    logger.info(f"display_name: '{user.display_name}'")
    logger.info(f"bio: '{user.bio}'")
    
    # 创建用户
    result = users_manager.create_user(user)
    logger.info(f"创建用户结果: {result.data if result.is_ok() else result.error}")
    
    if result.is_ok():
        # 检查结果中是否包含display_name和bio字段
        logger.info(f"创建用户API返回字段: {list(result.data.keys())}")
        logger.info(f"API返回的display_name: '{result.data.get('display_name', '')}'")
        logger.info(f"API返回的bio: '{result.data.get('bio', '')}'")
    
    return user


@pytest.fixture
def debug_db_state(users_manager, test_user):
    """调试数据库中用户对象的状态"""
    logger.info(f"从数据库获取用户: {test_user.user_id}")
    user = users_manager.get_user(test_user.user_id)
    
    if user:
        user_dict = user.model_dump(exclude={"password_hash"})
        logger.info(f"数据库中的用户对象字段: {list(user_dict.keys())}")
        logger.info(f"数据库中的display_name: '{user.display_name}'")
        logger.info(f"数据库中的bio: '{user.bio}'")
        return user_dict
    
    logger.error(f"无法从数据库获取用户: {test_user.user_id}")
    return None


@pytest.fixture
def authenticated_client(client, test_user):
    """登录并获取已认证的客户端"""
    logger.info("登录测试用户...")
    # 登录请求
    login_response = client.post(
        "/api/auth/login",
        json={
            "username": test_user.username,
            "password": "password123"
        }
    )
    
    assert login_response.status_code == 200
    login_data = login_response.json()
    
    # 检查登录响应中的字段
    logger.info(f"登录响应中的用户字段: {list(login_data['user'].keys())}")
    logger.info(f"登录响应中的display_name: '{login_data['user'].get('display_name', '')}'")
    logger.info(f"登录响应中的bio: '{login_data['user'].get('bio', '')}'")
    
    # 保存cookie以维持会话状态
    client.cookies = login_response.cookies
    return client


def test_display_name_and_bio_in_db(debug_db_state):
    """测试数据库中是否包含display_name和bio字段"""
    logger.info("测试数据库中的用户字段...")
    assert debug_db_state is not None
    assert "display_name" in debug_db_state
    assert "bio" in debug_db_state
    assert debug_db_state["display_name"] == "测试显示名称"
    assert debug_db_state["bio"] == "这是一个测试用户简介"


def test_login_response_fields(client, test_user):
    """测试登录响应中是否包含display_name和bio字段"""
    logger.info("测试登录响应字段...")
    response = client.post(
        "/api/auth/login",
        json={
            "username": test_user.username,
            "password": "password123"
        }
    )
    
    assert response.status_code == 200
    data = response.json()
    
    logger.info(f"登录响应完整内容: {json.dumps(data, indent=2, ensure_ascii=False)}")
    logger.info(f"用户信息字段: {list(data['user'].keys())}")
    
    assert "user" in data
    user_data = data["user"]
    assert "display_name" in user_data
    assert "bio" in user_data
    assert user_data["display_name"] == "测试显示名称"
    assert user_data["bio"] == "这是一个测试用户简介"


def test_profile_endpoint_fields(authenticated_client, test_user):
    """测试用户资料接口是否返回display_name和bio字段"""
    logger.info("测试获取用户资料API...")
    response = authenticated_client.get("/api/auth/profile")
    
    assert response.status_code == 200
    data = response.json()
    
    logger.info(f"资料API响应字段: {list(data.keys())}")
    logger.info(f"资料API中的display_name: '{data.get('display_name', '')}'")
    logger.info(f"资料API中的bio: '{data.get('bio', '')}'")
    
    assert "display_name" in data
    assert "bio" in data
    assert data["display_name"] == "测试显示名称"
    assert data["bio"] == "这是一个测试用户简介"


def test_update_profile_fields(authenticated_client, test_user):
    """测试更新用户资料字段"""
    logger.info("测试更新用户资料...")
    update_data = {
        "to_update": {
            "display_name": "更新后的显示名称",
            "bio": "更新后的个人简介"
        }
    }
    
    # 更新资料
    update_response = authenticated_client.post(
        "/api/auth/profile",
        json=update_data
    )
    
    assert update_response.status_code == 200
    update_result = update_response.json()
    
    logger.info(f"更新资料响应字段: {list(update_result.get('user', {}).keys())}")
    logger.info(f"更新后的display_name: '{update_result.get('user', {}).get('display_name', '')}'")
    logger.info(f"更新后的bio: '{update_result.get('user', {}).get('bio', '')}'")
    
    assert "user" in update_result
    assert update_result["user"]["display_name"] == "更新后的显示名称"
    assert update_result["user"]["bio"] == "更新后的个人简介"
    
    # 获取资料验证更新成功
    profile_response = authenticated_client.get("/api/auth/profile")
    assert profile_response.status_code == 200
    profile = profile_response.json()
    
    logger.info(f"更新后获取资料字段: {list(profile.keys())}")
    
    assert profile["display_name"] == "更新后的显示名称"
    assert profile["bio"] == "更新后的个人简介" 