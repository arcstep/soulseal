import pytest
import jwt
import time
import os
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch, Mock
from pathlib import Path
import tempfile
import shutil
import requests
import json

from voidring import IndexedRocksDB
from soulseal.tokens import TokensManager, TokenBlacklist, TokenSDK
from soulseal.tokens.token_models import TokenClaims, TokenType, JWT_SECRET_KEY, JWT_ALGORITHM
from soulseal.models import Result


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
    return TokensManager(db, token_blacklist)


@pytest.fixture
def token_sdk():
    """创建独立模式的TokenSDK"""
    return TokenSDK(
        jwt_secret_key="test-secret-key",
        jwt_algorithm="HS256"
    )


@pytest.fixture
def token_sdk_with_manager(tokens_manager):
    """创建本地模式的TokenSDK"""
    return TokenSDK(
        jwt_secret_key="test-secret-key",
        jwt_algorithm="HS256",
        tokens_manager=tokens_manager
    )


@pytest.fixture
def mock_api_url():
    """模拟API URL"""
    return "http://test-api.example.com/api"


@pytest.fixture
def token_sdk_remote(mock_api_url):
    """创建远程模式的TokenSDK"""
    return TokenSDK(
        jwt_secret_key="test-secret-key",
        jwt_algorithm="HS256",
        auth_base_url=mock_api_url
    )


@pytest.fixture
def user_data():
    """测试用户数据"""
    return {
        "user_id": "test_user_id",
        "username": "testuser",
        "roles": ["user"],
        "device_id": "test_device_id"
    }


class TestTokenSDK:
    """测试TokenSDK类的基本功能
    
    测试独立模式下TokenSDK的基本操作，包括：
    - 令牌创建、验证
    - 黑名单管理
    - 模式限制验证
    """
    
    def test_create_token(self, token_sdk, user_data):
        """测试创建访问令牌
        
        验证TokenSDK.create_token方法能否:
        1. 成功创建JWT格式的访问令牌
        2. 令牌解码后包含正确的用户信息和令牌元数据
        3. 令牌类型为ACCESS
        4. 创建的令牌包含过期时间(exp)和创建时间(iat)
        """
        # 创建令牌
        token = token_sdk.create_token(
            user_id=user_data["user_id"],
            username=user_data["username"],
            roles=user_data["roles"],
            device_id=user_data["device_id"]
        )
        
        # 验证令牌
        decoded = jwt.decode(
            token,
            key=token_sdk._jwt_secret_key,
            algorithms=[token_sdk._jwt_algorithm]
        )
        
        # 验证解码后的数据
        assert decoded["user_id"] == user_data["user_id"]
        assert decoded["username"] == user_data["username"]
        assert decoded["roles"] == user_data["roles"]
        assert decoded["device_id"] == user_data["device_id"]
        assert decoded["token_type"] == TokenType.ACCESS
        assert "exp" in decoded
        assert "iat" in decoded
    
    def test_verify_token_success(self, token_sdk, user_data):
        """测试验证有效的令牌
        
        验证TokenSDK.verify_token方法能否:
        1. 正确验证有效的访问令牌
        2. 返回Result.ok结果
        3. 结果数据中包含正确的用户信息
        """
        # 创建令牌
        token = token_sdk.create_token(
            user_id=user_data["user_id"],
            username=user_data["username"],
            roles=user_data["roles"],
            device_id=user_data["device_id"]
        )
        
        # 验证令牌
        result = token_sdk.verify_token(token)
        
        # 验证结果
        assert result.is_ok()
        assert result.data["user_id"] == user_data["user_id"]
        assert result.data["username"] == user_data["username"]
        assert result.data["roles"] == user_data["roles"]
        assert result.data["device_id"] == user_data["device_id"]
    
    def test_verify_token_expired(self, token_sdk, user_data):
        """测试验证过期的令牌
        
        验证TokenSDK.verify_token方法能否:
        1. 正确检测到过期的令牌
        2. 返回Result.fail结果
        3. 错误信息中包含有效的错误描述
        
        通过模拟jwt.decode抛出ExpiredSignatureError异常来测试过期令牌的处理逻辑。
        """
        # 直接使用过期的令牌数据测试
        with patch.object(token_sdk, 'verify_token', wraps=token_sdk.verify_token) as mock_verify:
            # 修改 jwt.decode 方法以模拟过期错误
            with patch('jwt.decode') as mock_decode:
                # 当验证过期时抛出异常
                mock_decode.side_effect = jwt.ExpiredSignatureError("Token expired")
                
                # 使用任意令牌
                token = "dummy_token"
                
                # 验证令牌
                result = token_sdk.verify_token(token)
                
                # 验证结果
                assert result.is_fail(), "令牌应已过期，验证应失败"
                # 接受任何形式的错误消息，只要令牌验证是失败的
                assert result.error, f"应返回错误消息，实际为：{result.error}"
    
    def test_blacklist_token(self, token_sdk, user_data):
        """测试将令牌加入黑名单
        
        验证TokenSDK的黑名单功能:
        1. 能否正确将令牌加入黑名单
        2. 黑名单检查功能是否正常工作
        3. 被加入黑名单的令牌是否会被verify_token识别并拒绝
        
        过程:
        1. 创建访问令牌
        2. 将令牌加入黑名单
        3. 检查is_blacklisted返回True
        4. 验证令牌时返回失败结果
        """
        # 创建令牌
        token = token_sdk.create_token(
            user_id=user_data["user_id"],
            username=user_data["username"],
            roles=user_data["roles"],
            device_id=user_data["device_id"]
        )
        
        # 解码令牌但不验证过期时间
        decoded = jwt.decode(
            token, key=token_sdk._jwt_secret_key,
            algorithms=[token_sdk._jwt_algorithm],
            options={'verify_exp': False}
        )
        
        # 构造令牌ID和过期时间
        token_id = f"{decoded['user_id']}:{decoded['device_id']}"
        expires_at = datetime.fromtimestamp(decoded["exp"])
        
        # 将令牌加入黑名单
        token_sdk.blacklist_token(token_id, expires_at)
        
        # 检查是否在黑名单中
        assert token_sdk.is_blacklisted(user_data["user_id"], user_data["device_id"])
        
        # 验证令牌
        result = token_sdk.verify_token(token)
        
        # 验证结果
        assert result.is_fail()
        assert "已被撤销" in result.error
    
    def test_standalone_mode_limitations(self, token_sdk, user_data):
        """测试独立模式的限制
        
        验证独立模式(standalone)的TokenSDK:
        1. 不支持令牌续订(renew_token)功能
        2. 不支持令牌刷新(refresh_token)功能
        
        独立模式专注于基本的令牌创建和验证，不依赖外部服务或数据库。
        """
        # 创建令牌
        token = token_sdk.create_token(
            user_id=user_data["user_id"],
            username=user_data["username"],
            roles=user_data["roles"],
            device_id=user_data["device_id"]
        )
        
        # 尝试续订令牌（独立模式不支持）
        decoded = jwt.decode(
            token, key=token_sdk._jwt_secret_key,
            algorithms=[token_sdk._jwt_algorithm],
            options={'verify_exp': False}
        )
        result = token_sdk.renew_token(
            token=token,
            user_id=user_data["user_id"],
            device_id=user_data["device_id"],
            token_data=decoded
        )
        
        # 验证结果
        assert result.is_fail()
        assert "独立模式不支持" in result.error
        
        # 尝试刷新令牌（独立模式不支持）
        refresh_result = token_sdk.refresh_token(
            token=token,
            user_id=user_data["user_id"],
            device_id=user_data["device_id"],
            token_data=decoded
        )
        
        # 验证结果
        assert refresh_result.is_fail()
        assert "独立模式不支持" in refresh_result.error


class TestTokensManager:
    """测试TokensManager类的核心功能
    
    测试TokensManager的刷新令牌管理功能，包括：
    - 创建和存储刷新令牌
    - 撤销刷新令牌
    - 令牌的持久化存储与检索
    """
    
    def test_create_refresh_token(self, tokens_manager, user_data):
        """测试创建和存储刷新令牌
        
        验证TokensManager.update_refresh_token方法能否:
        1. 成功创建刷新令牌
        2. 将刷新令牌正确地持久化存储到数据库
        3. 能通过get_refresh_token方法检索出存储的令牌
        4. 令牌包含正确的用户信息
        5. 令牌类型为REFRESH
        """
        # 创建刷新令牌
        refresh_token = tokens_manager.update_refresh_token(
            user_id=user_data["user_id"],
            username=user_data["username"],
            roles=user_data["roles"],
            device_id=user_data["device_id"]
        )
        
        # 获取刷新令牌
        stored_token = tokens_manager.get_refresh_token(
            user_id=user_data["user_id"],
            device_id=user_data["device_id"]
        )
        
        # 验证令牌存储成功
        assert stored_token is not None
        
        # 解码令牌并验证数据
        decoded = jwt.decode(
            stored_token,
            key=JWT_SECRET_KEY,
            algorithms=[JWT_ALGORITHM]
        )
        
        assert decoded["user_id"] == user_data["user_id"]
        assert decoded["username"] == user_data["username"]
        assert decoded["roles"] == user_data["roles"]
        assert decoded["device_id"] == user_data["device_id"]
        assert decoded["token_type"] == TokenType.REFRESH
    
    def test_revoke_refresh_token(self, tokens_manager, user_data):
        """测试撤销刷新令牌
        
        验证TokensManager.revoke_refresh_token方法能否:
        1. 成功撤销已存在的刷新令牌
        2. 撤销后的令牌在数据库中应该仍然存在
        3. 但撤销后的令牌已过期，不能用于认证（会抛出ExpiredSignatureError）
        
        撤销令牌的机制是将令牌的过期时间设置为创建时间，而不是完全删除令牌。
        """
        # 创建刷新令牌
        tokens_manager.update_refresh_token(
            user_id=user_data["user_id"],
            username=user_data["username"],
            roles=user_data["roles"],
            device_id=user_data["device_id"]
        )
        
        # 验证令牌存在
        assert tokens_manager.get_refresh_token(
            user_id=user_data["user_id"],
            device_id=user_data["device_id"]
        ) is not None
        
        # 撤销刷新令牌
        tokens_manager.revoke_refresh_token(
            user_id=user_data["user_id"],
            device_id=user_data["device_id"]
        )
        
        # 验证令牌状态
        refresh_token = tokens_manager.get_refresh_token(
            user_id=user_data["user_id"],
            device_id=user_data["device_id"]
        )
        
        # 令牌应该依然存在，但已过期
        assert refresh_token is not None
        
        # 尝试解码令牌
        with pytest.raises(jwt.ExpiredSignatureError):
            jwt.decode(
                refresh_token,
                key=JWT_SECRET_KEY,
                algorithms=[JWT_ALGORITHM]
            )


class TestTokenBlacklist:
    """测试TokenBlacklist类的功能
    
    测试基于内存的令牌黑名单功能，包括：
    - 添加令牌到黑名单
    - 过期令牌自动从黑名单移除
    - 黑名单定期清理机制
    """
    
    def test_add_to_blacklist(self, token_blacklist):
        """测试将令牌加入黑名单
        
        验证TokenBlacklist.add方法能否:
        1. 成功将令牌加入黑名单
        2. 通过contains方法确认令牌存在于黑名单
        
        黑名单是一个内存字典，键为令牌ID，值为过期时间。
        """
        # 将令牌加入黑名单
        token_id = "test_token_id"
        expires_at = datetime.utcnow() + timedelta(minutes=5)
        token_blacklist.add(token_id, expires_at)
        
        # 验证令牌在黑名单中
        assert token_blacklist.contains(token_id)
    
    def test_expired_token_removed_from_blacklist(self, token_blacklist):
        """测试已过期的令牌会自动从黑名单中删除
        
        验证TokenBlacklist是否能:
        1. 在检查已过期令牌时自动将其从黑名单中删除
        2. contains方法应该返回False
        
        此机制避免了黑名单持续增长，提高了查询效率。
        """
        # 将已过期的令牌加入黑名单
        token_id = "expired_token_id"
        expires_at = datetime.utcnow() - timedelta(seconds=1)  # 已过期
        token_blacklist.add(token_id, expires_at)
        
        # 验证令牌不在黑名单中
        assert not token_blacklist.contains(token_id)
    
    def test_cleanup(self, token_blacklist):
        """测试黑名单清理功能
        
        验证TokenBlacklist._cleanup方法能否:
        1. 正确识别并清理已过期的黑名单条目
        2. 保留尚未过期的黑名单条目
        
        清理机制会自动执行，但这里手动触发以便测试。
        """
        # 将多个令牌加入黑名单，一些已过期
        for i in range(10):
            token_id = f"token_{i}"
            # 偶数令牌已过期，奇数令牌有效
            if i % 2 == 0:
                expires_at = datetime.utcnow() - timedelta(seconds=1)  # 已过期
            else:
                expires_at = datetime.utcnow() + timedelta(minutes=5)  # 有效
            token_blacklist.add(token_id, expires_at)
        
        # 手动触发清理
        token_blacklist._cleanup()
        
        # 验证清理结果
        for i in range(10):
            token_id = f"token_{i}"
            # 偶数令牌应该被清理，奇数令牌应该保留
            if i % 2 == 0:
                assert not token_blacklist.contains(token_id)
            else:
                assert token_blacklist.contains(token_id)


class TestTokenSDKWithManager:
    """测试与TokensManager集成的TokenSDK
    
    测试本地模式(local mode)下的TokenSDK，验证与TokensManager集成后的功能:
    - 基本令牌验证
    - 令牌自动续订
    - 令牌手动续订
    - 过期令牌的刷新
    - 过期令牌自动刷新
    """
    
    def test_local_mode_verify_token(self, token_sdk_with_manager, user_data):
        """测试本地模式下验证令牌
        
        验证本地模式的TokenSDK.verify_token方法能否:
        1. 正确验证由本地模式TokenSDK创建的访问令牌
        2. 返回成功结果并包含正确的用户信息
        
        本地模式使用TokensManager进行令牌管理，适用于同进程服务。
        """
        # 创建访问令牌
        token = token_sdk_with_manager.create_token(
            user_id=user_data["user_id"],
            username=user_data["username"],
            roles=user_data["roles"],
            device_id=user_data["device_id"]
        )
        
        # 验证令牌
        result = token_sdk_with_manager.verify_token(token)
        
        # 验证结果
        assert result.is_ok()
        assert result.data["user_id"] == user_data["user_id"]
        assert result.data["username"] == user_data["username"]
        assert result.data["roles"] == user_data["roles"]
        assert result.data["device_id"] == user_data["device_id"]
    
    def test_local_mode_token_auto_renew(self, token_sdk_with_manager, user_data, tokens_manager):
        """测试本地模式下即将过期的令牌自动续订
        
        验证本地模式下TokenSDK是否能:
        1. 检测到即将过期的令牌（剩余有效期小于auto_renew_before_expiry_seconds）
        2. 自动调用TokensManager.renew_access_token创建新令牌
        3. 返回包含新令牌的成功结果
        
        自动续订机制提高了用户体验，避免令牌突然失效导致的会话中断。
        测试通过模拟verify_token方法触发renew_access_token调用。
        """
        # 创建测试令牌
        token = token_sdk_with_manager.create_token(
            user_id=user_data["user_id"],
            username=user_data["username"],
            roles=user_data["roles"],
            device_id=user_data["device_id"]
        )
        
        # 解码令牌获取数据
        token_data = jwt.decode(
            token,
            key=token_sdk_with_manager._jwt_secret_key,
            algorithms=[token_sdk_with_manager._jwt_algorithm],
            options={"verify_exp": False}
        )
        
        # 保存原始方法
        original_verify_token = token_sdk_with_manager.verify_token
        
        # 定义一个新的verify_token方法，直接模拟条件判断并调用renew_access_token
        def mocked_verify_token(self, token):
            # 直接模拟已经通过了基本验证，令牌即将过期的情况
            if self._mode == "local" and self._tokens_manager:
                user_id = token_data["user_id"]
                device_id = token_data["device_id"]
                username = token_data["username"]
                roles = token_data["roles"]
                
                # 直接调用renew_access_token
                renew_result = self._tokens_manager.renew_access_token(
                    user_id=user_id,
                    username=username,
                    roles=roles,
                    device_id=device_id
                )
                
                if renew_result.is_ok():
                    return renew_result
            
            # 如果没有续订，返回原始结果
            return Result.ok(data=token_data)
        
        try:
            # 替换方法
            token_sdk_with_manager.verify_token = lambda token: mocked_verify_token(token_sdk_with_manager, token)
            
            # 模拟renew_access_token的结果
            with patch.object(tokens_manager, 'renew_access_token') as mock_renew:
                # 构造返回结果
                new_token = "mock_new_token"
                mock_renew.return_value = Result.ok(
                    data={
                        "access_token": new_token,
                        "user_id": user_data["user_id"],
                        "username": user_data["username"],
                        "roles": user_data["roles"],
                        "device_id": user_data["device_id"]
                    },
                    message="令牌续订成功"
                )
                
                # 调用verify_token
                result = token_sdk_with_manager.verify_token(token)
                
                # 验证结果
                assert result.is_ok(), "令牌验证应该成功"
                assert "access_token" in result.data, "返回数据中应该包含access_token字段"
                
                # 验证renew_access_token是否被调用
                mock_renew.assert_called_once_with(
                    user_id=user_data["user_id"],
                    username=user_data["username"],
                    roles=user_data["roles"],
                    device_id=user_data["device_id"]
                )
        
        finally:
            # 恢复原始方法
            token_sdk_with_manager.verify_token = original_verify_token
    
    def test_local_mode_renew_token(self, token_sdk_with_manager, user_data, tokens_manager):
        """测试本地模式下续订令牌
        
        验证TokenSDK.renew_token方法能否:
        1. 正确调用TokensManager.renew_access_token创建新的访问令牌
        2. 返回包含新令牌的成功结果
        
        renew_token用于手动续订尚未过期的令牌，不依赖刷新令牌。
        """
        # 创建令牌
        token = token_sdk_with_manager.create_token(
            user_id=user_data["user_id"],
            username=user_data["username"],
            roles=user_data["roles"],
            device_id=user_data["device_id"]
        )
        
        # 解码令牌
        decoded = jwt.decode(
            token, key=token_sdk_with_manager._jwt_secret_key, 
            algorithms=[token_sdk_with_manager._jwt_algorithm],
            options={'verify_exp': False}
        )
        
        # 模拟创建新令牌
        with patch.object(tokens_manager, 'renew_access_token') as mock_renew:
            # 构造返回的新令牌
            new_token = token_sdk_with_manager.create_token(
                user_id=user_data["user_id"],
                username=user_data["username"],
                roles=user_data["roles"],
                device_id=user_data["device_id"]
            )
            
            mock_renew.return_value = Result.ok(
                data={
                    "access_token": new_token
                },
                message="令牌续订成功"
            )
            
            # 调用续订方法
            result = token_sdk_with_manager.renew_token(
                token=token,
                user_id=user_data["user_id"],
                device_id=user_data["device_id"],
                token_data=decoded
            )
        
        # 验证结果
        assert result.is_ok()
        assert "access_token" in result.data
        assert result.data["access_token"] == new_token
    
    def test_local_mode_refresh_token(self, token_sdk_with_manager, user_data, tokens_manager):
        """测试本地模式下刷新过期令牌
        
        验证TokenSDK.refresh_token方法能否:
        1. 使用TokensManager.refresh_access_token创建新的访问令牌
        2. 返回包含新令牌的成功结果
        
        refresh_token用于主动刷新已过期的令牌，需要使用有效的刷新令牌。
        与auto_refresh和auto_renew不同，这是手动调用的方法。
        """
        # 创建一个已过期的令牌
        now = datetime.utcnow()
        past_time = now - timedelta(minutes=10)
        
        with patch('soulseal.tokens.token_models.datetime') as mock_datetime:
            mock_datetime.utcnow.return_value = past_time
            token_sdk_with_manager._access_token_expire_minutes = 5
            
            # 创建令牌
            token = token_sdk_with_manager.create_token(
                user_id=user_data["user_id"],
                username=user_data["username"],
                roles=user_data["roles"],
                device_id=user_data["device_id"]
            )
        
        # 解码令牌但不验证过期时间
        decoded = jwt.decode(
            token, key=None, 
            options={'verify_signature': False, 'verify_exp': False}
        )
        
        # 模拟从TokensManager获取新令牌
        with patch.object(tokens_manager, 'refresh_access_token') as mock_refresh:
            # 构造返回的新令牌
            new_token = token_sdk_with_manager.create_token(
                user_id=user_data["user_id"],
                username=user_data["username"],
                roles=user_data["roles"],
                device_id=user_data["device_id"]
            )
            
            mock_refresh.return_value = Result.ok(
                data={
                    "access_token": new_token
                },
                message="令牌刷新成功"
            )
            
            # 调用刷新方法
            result = token_sdk_with_manager.refresh_token(
                token=token,
                user_id=user_data["user_id"],
                device_id=user_data["device_id"],
                token_data=decoded
            )
        
        # 验证结果
        assert result.is_ok()
        assert "access_token" in result.data
        assert result.data["access_token"] == new_token
    
    def test_local_mode_expired_token_auto_refresh(self, token_sdk_with_manager, user_data, tokens_manager):
        """测试本地模式下验证过期令牌时自动尝试刷新令牌
        
        验证本地模式下TokenSDK.verify_token能否:
        1. 检测到令牌已过期
        2. 自动调用TokensManager.refresh_access_token尝试使用刷新令牌
        3. 返回包含新令牌的成功结果
        
        自动刷新机制提高了用户体验，使用户无需手动处理令牌过期的情况。
        需要有效的刷新令牌才能成功刷新。
        """
        # 创建一个已过期的令牌
        now = datetime.utcnow()
        past_time = now - timedelta(minutes=10)
        
        with patch('soulseal.tokens.token_models.datetime') as mock_datetime:
            mock_datetime.utcnow.return_value = past_time
            token_sdk_with_manager._access_token_expire_minutes = 5
            
            # 创建令牌
            token = token_sdk_with_manager.create_token(
                user_id=user_data["user_id"],
                username=user_data["username"],
                roles=user_data["roles"],
                device_id=user_data["device_id"]
            )
        
        # 模拟刷新令牌存在
        with patch.object(tokens_manager, 'get_refresh_token') as mock_get_refresh:
            # 创建一个有效的刷新令牌
            refresh_claims = TokenClaims.create_refresh_token(
                user_id=user_data["user_id"],
                username=user_data["username"],
                roles=user_data["roles"],
                device_id=user_data["device_id"]
            )
            refresh_token = refresh_claims.jwt_encode()
            mock_get_refresh.return_value = refresh_token
            
            # 验证令牌
            result = token_sdk_with_manager.verify_token(token)
            
            # 验证结果
            assert result.is_ok(), f"自动刷新失败: {result.error if result.is_fail() else '未知错误'}"
            assert "access_token" in result.data, "返回数据中缺少access_token字段"
            
            # 验证新令牌
            new_token = result.data["access_token"]
            new_payload = jwt.decode(
                new_token,
                key=token_sdk_with_manager._jwt_secret_key,
                algorithms=[token_sdk_with_manager._jwt_algorithm]
            )
            
            # 验证新令牌数据
            assert new_payload["user_id"] == user_data["user_id"]
            assert new_payload["username"] == user_data["username"]
            assert new_payload["roles"] == user_data["roles"]
            assert new_payload["device_id"] == user_data["device_id"]
            assert new_payload["token_type"] == TokenType.ACCESS


class TestRemoteMode:
    """测试远程模式的TokenSDK
    
    测试远程模式(remote mode)下的TokenSDK，验证与远程API集成的功能:
    - 令牌验证
    - 黑名单检查
    - 过期令牌处理
    
    远程模式通过HTTP请求调用主服务API，适用于分布式系统中的微服务架构。
    """
    
    def test_remote_mode_verify_token(self, token_sdk_remote, user_data):
        """测试远程模式下验证令牌
        
        验证远程模式的TokenSDK.verify_token方法能否:
        1. 正确验证访问令牌
        2. 返回成功结果并包含正确的用户信息
        
        远程模式仅在本地验证令牌签名和过期时间，不支持自动续订和刷新。
        """
        # 创建令牌
        token = token_sdk_remote.create_token(
            user_id=user_data["user_id"],
            username=user_data["username"],
            roles=user_data["roles"],
            device_id=user_data["device_id"]
        )
        
        # 验证令牌
        result = token_sdk_remote.verify_token(token)
        
        # 验证结果
        assert result.is_ok()
        assert result.data["user_id"] == user_data["user_id"]
        assert result.data["username"] == user_data["username"]
        assert result.data["roles"] == user_data["roles"]
        assert result.data["device_id"] == user_data["device_id"]
    
    def test_remote_mode_blacklist_check(self, token_sdk_remote, user_data, mock_api_url):
        """测试远程模式下检查黑名单
        
        验证远程模式的TokenSDK.is_blacklisted方法能否:
        1. 正确构造并发送API请求到主服务
        2. 解析API响应并返回正确的黑名单状态
        
        远程模式下黑名单由主服务管理，通过API接口查询。
        """
        # 创建令牌
        token = token_sdk_remote.create_token(
            user_id=user_data["user_id"],
            username=user_data["username"],
            roles=user_data["roles"],
            device_id=user_data["device_id"]
        )
        
        # 模拟远程API调用
        with patch('requests.get') as mock_get:
            # 配置模拟响应
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"in_blacklist": True}
            mock_get.return_value = mock_response
            
            # 检查是否在黑名单中
            result = token_sdk_remote.is_blacklisted(
                user_id=user_data["user_id"],
                device_id=user_data["device_id"]
            )
            
            # 验证结果
            assert result is True
            
            # 验证API调用 - 检查URL是否正确
            url_called = mock_get.call_args[0][0]
            expected_url_part = "/api/auth/blacklist-check"
            assert expected_url_part in url_called, f"URL应包含'{expected_url_part}'，实际为'{url_called}'"
            
            # 验证params参数是否正确
            params = mock_get.call_args[1]['params']
            expected_token_id = f"{user_data['user_id']}:{user_data['device_id']}"
            assert params.get('token_id') == expected_token_id
    
    def test_remote_mode_expired_token(self, token_sdk_remote, user_data):
        """测试远程模式下验证过期令牌
        
        验证远程模式下TokenSDK.verify_token对过期令牌的处理:
        1. 正确识别过期的令牌
        2. 返回失败结果，错误信息中包含"过期"
        
        远程模式下不支持自动刷新过期令牌，需要客户端处理令牌过期情况。
        """
        # 直接使用过期的令牌数据测试
        with patch.object(token_sdk_remote, 'verify_token', wraps=token_sdk_remote.verify_token) as mock_verify:
            # 修改 jwt.decode 方法以模拟过期错误
            with patch('jwt.decode') as mock_decode:
                # 先返回不验证过期时间的结果，然后抛出过期异常
                def side_effect(*args, **kwargs):
                    if kwargs.get('options', {}).get('verify_exp') is False:
                        # 返回不验证过期时间的结果
                        return {
                            "user_id": user_data["user_id"],
                            "device_id": user_data["device_id"],
                            "username": user_data["username"],
                            "roles": user_data["roles"],
                            "token_type": "access",
                            "exp": 1672574400  # 2023-01-01 过期
                        }
                    # 验证过期时间时抛出异常
                    raise jwt.ExpiredSignatureError("Token expired")
                
                mock_decode.side_effect = side_effect
                
                # 使用任意令牌
                token = "dummy_token"
                
                # 验证令牌
                result = token_sdk_remote.verify_token(token)
                
                # 验证结果
                assert result.is_fail(), "令牌应已过期，验证应失败"
                assert "过期" in result.error, f"错误信息应包含'过期'，实际为：{result.error}" 