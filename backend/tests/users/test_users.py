import pytest
import tempfile
import shutil
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock
import re
import uuid

from voidring import IndexedRocksDB
from soulseal.users import UsersManager, User, UserRole
from soulseal.schemas import Result


@pytest.fixture
def temp_db_path():
    """创建临时数据库目录"""
    temp_dir = tempfile.mkdtemp()
    yield temp_dir
    try:
        shutil.rmtree(temp_dir)
    except Exception as e:
        print(f"清理临时目录失败: {str(e)}")
        # 这里不抛出异常，避免测试失败


@pytest.fixture
def db(temp_db_path):
    """创建测试用的RocksDB实例"""
    db = IndexedRocksDB(temp_db_path)
    yield db
    # 确保关闭数据库连接
    try:
        db.close()
    except:
        pass


@pytest.fixture
def users_manager(db):
    """创建用户管理器"""
    return UsersManager(db)


@pytest.fixture
def test_user():
    """创建测试用户对象"""
    return User(
        username="testuser",
        password_hash=User.hash_password("testpassword"),
        email="test@example.com"
    )


@pytest.fixture
def admin_user():
    """创建管理员用户对象"""
    return User(
        username="adminuser",
        password_hash=User.hash_password("adminpassword"),
        email="admin@example.com",
        roles=[UserRole.ADMIN]
    )


class TestUserModel:
    """测试User模型类
    
    测试的功能包括：
    - 用户对象创建和验证
    - 密码哈希和验证
    - 用户名验证规则
    - 角色验证和管理
    - 随机密码生成
    - 密码过期检查
    - 登录尝试记录
    """
    
    def test_create_user(self):
        """测试创建用户对象
        
        验证:
        1. 可以成功创建用户对象
        2. 默认值正确设置
        3. 自动生成的字段（如user_id）格式正确
        """
        user = User(
            username="testuser",
            password_hash="hashed_password",
            email="test@example.com"
        )
        
        # 验证基本属性
        assert user.username == "testuser"
        assert user.password_hash == "hashed_password"
        assert user.email == "test@example.com"
        
        # 验证默认值
        assert user.is_active is True
        assert user.is_locked is False
        assert user.failed_login_attempts == 0
        assert UserRole.USER in user.roles  # 默认角色是普通用户
        
        # 验证生成的user_id格式
        assert re.match(r'^u-[0-9a-f]{8}$', user.user_id)
    
    def test_password_hash_and_verify(self):
        """测试密码哈希和验证
        
        验证:
        1. hash_password能生成正确的密码哈希
        2. verify_password能正确验证密码
        3. 错误密码会被拒绝
        """
        password = "secure_password123"
        
        # 哈希密码
        hashed = User.hash_password(password)
        
        # 验证哈希值不等于原始密码
        assert hashed != password
        
        # 创建用户并设置密码哈希
        user = User(
            username="testuser",
            password_hash=hashed
        )
        
        # 验证正确密码
        verify_result = user.verify_password(password)
        assert isinstance(verify_result, dict)
        assert "rehash" in verify_result
        
        # 验证错误密码
        with pytest.raises(Exception):
            user.verify_password("wrong_password")
    
    def test_username_validation(self):
        """测试用户名验证规则
        
        验证:
        1. 用户名必须以字母开头
        2. 用户名只能包含字母、数字和下划线
        3. 无效的用户名会抛出异常
        """
        # 有效的用户名
        valid_usernames = ["user1", "admin_user", "TestUser"]
        for username in valid_usernames:
            user = User(username=username, password_hash="hash")
            assert user.username == username
        
        # 无效的用户名 - 不以字母开头
        with pytest.raises(ValueError):
            User(username="1user", password_hash="hash")
        
        # 无效的用户名 - 包含特殊字符
        with pytest.raises(ValueError):
            User(username="user@name", password_hash="hash")
    
    def test_role_hierarchy(self):
        """测试角色层级关系
        
        验证:
        1. 管理员拥有所有角色的权限
        2. 操作员拥有用户和访客权限
        3. 用户拥有访客权限
        4. 角色层级关系正确
        """
        # 测试管理员角色
        admin_roles = UserRole.get_role_hierarchy({UserRole.ADMIN})
        assert UserRole.ADMIN in admin_roles
        assert UserRole.OPERATOR in admin_roles
        assert UserRole.USER in admin_roles
        assert UserRole.GUEST in admin_roles
        
        # 测试操作员角色
        operator_roles = UserRole.get_role_hierarchy({UserRole.OPERATOR})
        assert UserRole.ADMIN not in operator_roles
        assert UserRole.OPERATOR in operator_roles
        assert UserRole.USER in operator_roles
        assert UserRole.GUEST in operator_roles
        
        # 测试用户角色
        user_roles = UserRole.get_role_hierarchy({UserRole.USER})
        assert UserRole.ADMIN not in user_roles
        assert UserRole.OPERATOR not in user_roles
        assert UserRole.USER in user_roles
        assert UserRole.GUEST in user_roles
        
        # 测试访客角色
        guest_roles = UserRole.get_role_hierarchy({UserRole.GUEST})
        assert UserRole.ADMIN not in guest_roles
        assert UserRole.OPERATOR not in guest_roles
        assert UserRole.USER not in guest_roles
        assert UserRole.GUEST in guest_roles
    
    def test_has_role(self):
        """测试角色检查功能
        
        验证:
        1. has_role方法能正确检查用户是否拥有指定角色
        2. 考虑角色继承关系
        """
        # 测试管理员拥有所有角色权限
        assert UserRole.has_role(UserRole.ADMIN, {UserRole.ADMIN})
        assert UserRole.has_role(UserRole.OPERATOR, {UserRole.ADMIN})
        assert UserRole.has_role(UserRole.USER, {UserRole.ADMIN})
        assert UserRole.has_role(UserRole.GUEST, {UserRole.ADMIN})
        
        # 测试普通用户只有用户和访客权限
        assert not UserRole.has_role(UserRole.ADMIN, {UserRole.USER})
        assert not UserRole.has_role(UserRole.OPERATOR, {UserRole.USER})
        assert UserRole.has_role(UserRole.USER, {UserRole.USER})
        assert UserRole.has_role(UserRole.GUEST, {UserRole.USER})
    
    def test_generate_random_password(self):
        """测试随机密码生成
        
        验证:
        1. 生成的密码长度符合要求
        2. 生成的密码包含字母、数字和特殊字符
        3. 每次生成的密码都不同
        """
        # 生成多个密码
        passwords = [User.generate_random_password() for _ in range(5)]
        
        for password in passwords:
            # 验证长度
            assert len(password) == 12  # 默认长度
            
            # 验证包含字母、数字和特殊字符
            assert re.search(r'[a-zA-Z]', password)
            assert re.search(r'[0-9]', password)
            assert re.search(r'[!@#$%^&*]', password)
        
        # 验证密码唯一性
        assert len(set(passwords)) == 5
    
    def test_password_expiry(self):
        """测试密码过期检查
        
        验证:
        1. is_password_expired能正确检测密码是否过期
        2. 密码过期期限设置有效
        """
        user = User(
            username="testuser",
            password_hash="hashed_password"
        )
        
        # 初始情况下密码不应过期
        assert not user.is_password_expired()
        
        # 设置密码修改时间为90天前（默认过期时间）
        past_time = datetime.now() - timedelta(days=91)
        user.last_password_change = past_time
        
        # 验证密码已过期
        assert user.is_password_expired()
        
        # 修改过期期限
        user.password_expires_days = 180
        
        # 验证密码未过期（因为修改了过期期限）
        assert not user.is_password_expired()
    
    def test_record_login_attempt(self):
        """测试登录尝试记录
        
        验证:
        1. 成功登录会清除失败计数
        2. 失败登录会增加失败计数
        3. 多次失败登录会导致账户锁定
        """
        user = User(
            username="testuser",
            password_hash="hashed_password"
        )
        
        # 记录失败登录
        user.record_login_attempt(success=False)
        assert user.failed_login_attempts == 1
        assert user.last_failed_login is not None
        assert user.last_login is None
        assert not user.is_locked
        
        # 多次失败登录导致锁定
        for _ in range(4):
            user.record_login_attempt(success=False)
        
        assert user.failed_login_attempts == 5
        assert user.is_locked
        
        # 成功登录应重置失败计数并解锁
        user.record_login_attempt(success=True)
        assert user.failed_login_attempts == 0
        assert user.last_login is not None
        assert user.last_failed_login is None
        assert not user.is_locked


class TestUsersManager:
    """测试UsersManager类
    
    测试的功能包括：
    - 用户创建和获取
    - 密码验证
    - 用户角色管理
    - 用户信息更新
    - 用户删除
    - 密码修改和重置
    - 管理员用户确保存在
    """
    
    def test_create_user(self, users_manager, test_user):
        """测试创建用户
        
        验证:
        1. 可以成功创建用户
        2. 返回Result包含用户信息
        3. 用户信息不包含密码哈希
        """
        # 创建用户
        result = users_manager.create_user(test_user)
        
        # 验证结果
        assert result.is_ok()
        assert "user_id" in result.data
        assert result.data["username"] == test_user.username
        assert result.data["email"] == test_user.email
        assert "password_hash" not in result.data
    
    def test_create_duplicate_user(self, users_manager, test_user):
        """测试创建重复用户
        
        验证:
        1. 不能创建重复用户名的用户
        2. 返回包含明确错误信息的Result
        """
        # 先创建一个用户
        users_manager.create_user(test_user)
        
        # 尝试创建同名用户
        duplicate_user = User(
            username=test_user.username,
            password_hash="different_hash",
            email="another@example.com"
        )
        
        result = users_manager.create_user(duplicate_user)
        
        # 验证结果
        assert result.is_fail()
        assert "已存在" in result.error
    
    def test_get_user(self, users_manager, test_user):
        """测试获取用户
        
        验证:
        1. 可以通过ID获取已创建的用户
        2. 返回完整的用户对象
        3. 不存在的用户ID返回None
        """
        # 创建用户
        create_result = users_manager.create_user(test_user)
        user_id = create_result.data["user_id"]
        
        # 获取用户
        retrieved_user = users_manager.get_user(user_id)
        
        # 验证结果
        assert retrieved_user is not None
        assert retrieved_user.user_id == user_id
        assert retrieved_user.username == test_user.username
        assert retrieved_user.email == test_user.email
        assert retrieved_user.password_hash == test_user.password_hash
        
        # 测试获取不存在的用户
        non_existent_user = users_manager.get_user("non_existent_id")
        assert non_existent_user is None
    
    def test_verify_password(self, users_manager, test_user):
        """测试密码验证
        
        验证:
        1. 使用正确密码验证返回成功
        2. 使用错误密码验证返回失败
        3. 验证不存在的用户返回失败
        """
        # 创建用户
        users_manager.create_user(test_user)
        
        # 使用正确密码验证
        result = users_manager.verify_password(
            username=test_user.username,
            password="testpassword"  # 与test_user创建时使用的密码相同
        )
        
        # 验证结果
        assert result.is_ok()
        assert result.data["username"] == test_user.username
        assert "password_hash" not in result.data
        
        # 使用错误密码验证
        result = users_manager.verify_password(
            username=test_user.username,
            password="wrongpassword"
        )
        
        # 验证结果
        assert result.is_fail()
        
        # 验证不存在的用户
        result = users_manager.verify_password(
            username="nonexistentuser",
            password="anypassword"
        )
        
        # 验证结果
        assert result.is_fail()
        assert "用户不存在" in result.error
    
    def test_update_user_roles(self, users_manager, test_user):
        """测试更新用户角色
        
        验证:
        1. 可以成功更新用户角色
        2. 更新后用户拥有新角色
        3. 无效角色值返回失败
        """
        # 创建用户
        create_result = users_manager.create_user(test_user)
        user_id = create_result.data["user_id"]
        
        # 更新用户角色
        result = users_manager.update_user_roles(
            user_id=user_id,
            roles=["admin", "operator"]
        )
        
        # 验证结果
        assert result.is_ok()
        assert set(result.data["roles"]) == {UserRole.ADMIN, UserRole.OPERATOR}
        
        # 获取用户验证角色更新
        updated_user = users_manager.get_user(user_id)
        assert UserRole.ADMIN in updated_user.roles
        assert UserRole.OPERATOR in updated_user.roles
        
        # 测试无效角色值
        result = users_manager.update_user_roles(
            user_id=user_id,
            roles=["invalid_role"]
        )
        
        # 验证结果
        assert result.is_fail()
        assert "无效的角色值" in result.error
    
    def test_update_user(self, users_manager, test_user):
        """测试更新用户信息
        
        验证:
        1. 可以成功更新用户基本信息
        2. 不可更新的字段被忽略
        3. 不能更新为已存在的用户名
        """
        # 创建两个用户
        create_result1 = users_manager.create_user(test_user)
        user_id1 = create_result1.data["user_id"]
        
        other_user = User(
            username="otheruser",
            password_hash=User.hash_password("otherpassword"),
            email="other@example.com"
        )
        users_manager.create_user(other_user)
        
        # 更新用户信息 - 允许的字段
        result = users_manager.update_user(
            user_id=user_id1,
            username="newusername",
            email="newemail@example.com"
        )
        
        # 验证结果
        assert result.is_ok()
        assert result.data["username"] == "newusername"
        assert result.data["email"] == "newemail@example.com"
        
        # 获取用户验证更新
        updated_user = users_manager.get_user(user_id1)
        assert updated_user.username == "newusername"
        assert updated_user.email == "newemail@example.com"
        
        # 尝试更新为已存在的用户名
        result = users_manager.update_user(
            user_id=user_id1,
            username="otheruser"
        )
        
        # 验证结果
        assert result.is_fail()
        assert "已存在" in result.error
        
        # 尝试更新不允许的字段
        result = users_manager.update_user(
            user_id=user_id1,
            password_hash="直接修改密码哈希"
        )
        
        # 验证结果
        assert result.is_fail()
        assert "不允许更新" in result.error
    
    def test_delete_user(self, users_manager, test_user):
        """测试删除用户
        
        验证:
        1. 可以成功删除用户
        2. 删除后无法获取用户
        3. 删除不存在的用户返回失败
        """
        # 创建用户
        create_result = users_manager.create_user(test_user)
        user_id = create_result.data["user_id"]
        
        # 删除用户
        result = users_manager.delete_user(user_id)
        
        # 验证结果
        assert result.is_ok()
        
        # 尝试获取已删除的用户
        deleted_user = users_manager.get_user(user_id)
        assert deleted_user is None
        
        # 尝试删除不存在的用户
        result = users_manager.delete_user("non_existent_id")
        
        # 验证结果
        assert result.is_fail()
        assert "用户不存在" in result.error
    
    def test_list_users(self, users_manager, test_user, admin_user):
        """测试列出所有用户
        
        验证:
        1. 可以获取所有用户列表
        2. 列表包含所有创建的用户
        """
        # 创建多个用户
        users_manager.create_user(test_user)
        users_manager.create_user(admin_user)
        
        # 列出所有用户
        users = users_manager.list_users()
        
        # 验证结果 - 至少有两个用户(测试用户和管理员用户)
        # 注意：ensure_admin_user会自动创建一个管理员用户
        assert len(users) >= 2
        
        # 验证用户名列表包含已创建的用户
        usernames = [user.username for user in users]
        assert test_user.username in usernames
        assert admin_user.username in usernames
    
    def test_change_password(self, users_manager, test_user):
        """测试修改密码
        
        验证:
        1. 使用正确的当前密码可以成功修改密码
        2. 使用错误的当前密码无法修改密码
        3. 修改后可以使用新密码验证
        """
        # 创建用户
        create_result = users_manager.create_user(test_user)
        user_id = create_result.data["user_id"]
        
        # 使用错误的当前密码尝试修改
        result = users_manager.change_password(
            user_id=user_id,
            current_password="wrongpassword",
            new_password="newpassword"
        )
        
        # 验证失败
        assert result.is_fail()
        assert "密码错误" in result.error
        
        # 使用正确的当前密码修改
        result = users_manager.change_password(
            user_id=user_id,
            current_password="testpassword",
            new_password="newpassword"
        )
        
        # 验证成功
        assert result.is_ok()
        
        # 验证新密码
        verify_result = users_manager.verify_password(
            username=test_user.username,
            password="newpassword"
        )
        
        assert verify_result.is_ok()
        
        # 验证旧密码不再有效
        verify_result = users_manager.verify_password(
            username=test_user.username,
            password="testpassword"
        )
        
        assert verify_result.is_fail()
    
    def test_reset_password(self, users_manager, test_user):
        """测试重置密码
        
        验证:
        1. 可以直接重置密码而不验证当前密码
        2. 重置后使用新密码可以验证成功
        3. 重置后的用户标记为需要修改密码
        """
        # 创建用户
        create_result = users_manager.create_user(test_user)
        user_id = create_result.data["user_id"]
        
        # 重置密码
        result = users_manager.reset_password(
            user_id=user_id,
            new_password="resetpassword"
        )
        
        # 验证结果
        assert result.is_ok()
        
        # 获取用户
        user = users_manager.get_user(user_id)
        
        # 验证用户状态
        assert user.require_password_change is True
        
        # 验证新密码
        verify_result = users_manager.verify_password(
            username=test_user.username,
            password="resetpassword"
        )
        
        assert verify_result.is_ok()
    
    def test_ensure_admin_user(self, users_manager):
        """测试确保管理员用户存在
        
        验证:
        1. UsersManager初始化时会自动创建管理员用户
        2. 如果管理员用户已存在则不会创建新的
        """
        # UsersManager在初始化时已经调用了ensure_admin_user
        
        # 获取管理员用户
        admin = users_manager.get_user("admin")
        
        # 验证管理员用户存在
        assert admin is not None
        assert admin.username == "admin"
        assert UserRole.ADMIN in admin.roles
        
        # 再次调用ensure_admin_user不应创建新的管理员用户
        users_manager.ensure_admin_user()
        
        # 验证管理员用户数量
        admins = [user for user in users_manager.list_users() if user.user_id == "admin"]
        assert len(admins) == 1
    
    def test_existing_index_field(self, users_manager, test_user):
        """测试检查字段是否存在
        
        验证:
        1. 可以正确检测已存在的索引字段
        2. 不存在的字段返回成功结果
        """
        # 创建用户
        users_manager.create_user(test_user)
        
        # 检查已存在的用户名
        result = users_manager.existing_index_field(
            field_path="username",
            field_value=test_user.username
        )
        
        # 验证结果
        assert result.is_fail()
        assert "已存在" in result.error
        
        # 检查不存在的用户名
        result = users_manager.existing_index_field(
            field_path="username",
            field_value="nonexistentuser"
        )
        
        # 验证结果
        assert result.is_ok() 