import pytest
import jwt
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch
import tempfile
import shutil
import time

from voidring import IndexedRocksDB
from soulseal.tokens import TokensManager
from soulseal.tokens.token_schemas import TokenClaims, TokenType, JWT_SECRET_KEY, JWT_ALGORITHM, get_current_timestamp
from soulseal.tokens.blacklist import MemoryTokenBlacklist

@pytest.fixture
def temp_db_path():
    """创建临时数据库目录"""
    temp_dir = tempfile.mkdtemp()
    yield temp_dir
    shutil.rmtree(temp_dir)

@pytest.fixture
def db(temp_db_path):
    """创建测试用RocksDB实例"""
    return IndexedRocksDB(temp_db_path)

@pytest.fixture
def tokens_manager(db):
    """创建令牌管理器"""
    return TokensManager(db)

@pytest.fixture
def user_data():
    """测试用户数据"""
    return {
        "user_id": "test_user_id",
        "username": "testuser",
        "roles": ["user"],
        "device_id": "test_device_id"
    }

@pytest.fixture
def blacklist():
    """创建实际黑名单实例"""
    return MemoryTokenBlacklist()

class TestTokensManager:
    def test_create_refresh_token(self, tokens_manager, user_data):
        """测试创建和存储刷新令牌"""
        # 创建刷新令牌
        refresh_claims = tokens_manager.update_refresh_token(
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
        
        # 验证令牌存储成功且包含正确数据
        assert stored_token is not None
        decoded = jwt.decode(
            stored_token,
            key=JWT_SECRET_KEY,
            algorithms=[JWT_ALGORITHM]
        )
        assert decoded["token_type"] == TokenType.REFRESH
        assert decoded["user_id"] == user_data["user_id"]
        
    def test_revoke_refresh_token(self, tokens_manager, user_data):
        """测试撤销刷新令牌"""
        # 创建并撤销刷新令牌
        tokens_manager.update_refresh_token(
            user_id=user_data["user_id"],
            username=user_data["username"],
            roles=user_data["roles"],
            device_id=user_data["device_id"]
        )
        
        tokens_manager.revoke_refresh_token(
            user_id=user_data["user_id"],
            device_id=user_data["device_id"]
        )
        
        # 获取被撤销的令牌
        revoked_token = tokens_manager.get_refresh_token(
            user_id=user_data["user_id"],
            device_id=user_data["device_id"]
        )
        
        # 令牌应该存在但已过期
        assert revoked_token is not None
        with pytest.raises(jwt.ExpiredSignatureError):
            jwt.decode(
                revoked_token,
                key=JWT_SECRET_KEY,
                algorithms=[JWT_ALGORITHM]
            )
    
    def test_refresh_access_token(self, tokens_manager, user_data):
        """测试刷新访问令牌"""
        # 创建刷新令牌
        tokens_manager.update_refresh_token(
            user_id=user_data["user_id"],
            username=user_data["username"],
            roles=user_data["roles"],
            device_id=user_data["device_id"]
        )
        
        # 刷新访问令牌
        result = tokens_manager.refresh_access_token(
            user_id=user_data["user_id"],
            username=user_data["username"],
            roles=user_data["roles"],
            device_id=user_data["device_id"]
        )
        
        # 验证刷新成功并返回新令牌
        assert result.is_ok()
        assert "access_token" in result.data
        
    def test_extend_refresh_token(self, tokens_manager, user_data):
        """测试延长刷新令牌有效期"""
        # 创建刷新令牌
        tokens_manager.update_refresh_token(
            user_id=user_data["user_id"],
            username=user_data["username"],
            roles=user_data["roles"],
            device_id=user_data["device_id"]
        )
        
        # 获取原始过期时间
        original_token = tokens_manager.get_refresh_token(
            user_id=user_data["user_id"],
            device_id=user_data["device_id"]
        )
        original_decoded = jwt.decode(
            original_token,
            key=JWT_SECRET_KEY,
            algorithms=[JWT_ALGORITHM],
            options={'verify_exp': False}
        )
        original_exp = original_decoded["exp"]
        
        # 延长令牌有效期
        with patch('soulseal.tokens.token_schemas.get_current_timestamp') as mock_time:
            fixed_time = time.time() + 86400  # 当前时间加一天
            mock_time.return_value = fixed_time
            result = tokens_manager.extend_refresh_token(
                user_id=user_data["user_id"],
                device_id=user_data["device_id"]
            )
        
        # 获取延长后的令牌
        extended_token = tokens_manager.get_refresh_token(
            user_id=user_data["user_id"],
            device_id=user_data["device_id"]
        )
        extended_decoded = jwt.decode(
            extended_token,
            key=JWT_SECRET_KEY,
            algorithms=[JWT_ALGORITHM],
            options={'verify_exp': False}
        )
        
        # 验证有效期已延长
        assert result.is_ok()
        assert extended_decoded["exp"] > original_exp
    
    def test_multi_device_refresh_tokens(self, tokens_manager, user_data):
        """测试同一用户多个设备的刷新令牌互不干扰"""
        # 两个不同设备ID
        device_id1 = "device_1"
        device_id2 = "device_2"
        
        # 创建两个设备的刷新令牌
        tokens_manager.update_refresh_token(
            user_id=user_data["user_id"],
            username=user_data["username"],
            roles=user_data["roles"],
            device_id=device_id1
        )
        
        tokens_manager.update_refresh_token(
            user_id=user_data["user_id"],
            username=user_data["username"],
            roles=user_data["roles"],
            device_id=device_id2
        )
        
        # 撤销设备1的令牌
        tokens_manager.revoke_refresh_token(
            user_id=user_data["user_id"],
            device_id=device_id1
        )
        
        # 验证设备1的令牌已撤销
        token1 = tokens_manager.get_refresh_token(
            user_id=user_data["user_id"],
            device_id=device_id1
        )
        with pytest.raises(jwt.ExpiredSignatureError):
            jwt.decode(token1, key=JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        
        # 验证设备2的令牌仍然有效
        token2 = tokens_manager.get_refresh_token(
            user_id=user_data["user_id"],
            device_id=device_id2
        )
        decoded2 = jwt.decode(token2, key=JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        assert decoded2["device_id"] == device_id2

    def test_revoke_access_and_refresh_tokens(self, tokens_manager, user_data, blacklist):
        """测试同时撤销访问令牌和刷新令牌"""
        tokens_manager._token_blacklist = blacklist
        
        # 创建刷新令牌
        tokens_manager.update_refresh_token(
            user_id=user_data["user_id"],
            username=user_data["username"],
            roles=user_data["roles"],
            device_id=user_data["device_id"]
        )
        
        # 撤销访问令牌（同时会撤销刷新令牌）
        tokens_manager.revoke_access_token(
            user_id=user_data["user_id"],
            device_id=user_data["device_id"]
        )
        
        # 验证黑名单添加被调用
        token_id = f"{user_data['user_id']}:{user_data['device_id']}"
        assert blacklist.contains(token_id)
        
        # 验证刷新令牌已撤销
        token = tokens_manager.get_refresh_token(
            user_id=user_data["user_id"],
            device_id=user_data["device_id"]
        )
        with pytest.raises(jwt.ExpiredSignatureError):
            jwt.decode(token, key=JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])

    def test_blacklist_prevents_token_use(self, tokens_manager, user_data):
        """测试黑名单阻止已撤销令牌的使用"""
        # 使用真实黑名单实例
        real_blacklist = MemoryTokenBlacklist()
        tokens_manager._token_blacklist = real_blacklist
        
        # 创建刷新令牌
        tokens_manager.update_refresh_token(**user_data)
        
        # 将用户令牌加入黑名单
        token_id = f"{user_data['user_id']}:{user_data['device_id']}"
        future_time = get_current_timestamp() + 3600  # 当前时间加1小时
        real_blacklist.add(token_id, future_time)
        
        # 验证令牌确实在黑名单中
        assert real_blacklist.contains(token_id) == True
        
        # 尝试刷新令牌 - 应该失败
        result = tokens_manager.refresh_access_token(**user_data)
        
        # 验证结果
        assert result.is_fail()
        assert "已经撤销" in result.error

    def test_renew_vs_refresh_token(self, tokens_manager, user_data):
        """测试令牌续订与刷新的区别"""
        # 创建刷新令牌
        tokens_manager.update_refresh_token(
            user_id=user_data["user_id"],
            username=user_data["username"],
            roles=user_data["roles"],
            device_id=user_data["device_id"]
        )
        
        # 使用续订方法（不需要刷新令牌）
        renew_result = tokens_manager.renew_access_token(
            user_id=user_data["user_id"],
            username=user_data["username"],
            roles=user_data["roles"],
            device_id=user_data["device_id"]
        )
        
        # 验证续订成功
        assert renew_result.is_ok()
        assert "access_token" in renew_result.data
        
        # 模拟刷新令牌不存在的情况
        with patch.object(tokens_manager, 'get_refresh_token', return_value=None):
            # 使用刷新方法（需要刷新令牌）
            refresh_result = tokens_manager.refresh_access_token(
                user_id=user_data["user_id"],
                username=user_data["username"],
                roles=user_data["roles"],
                device_id=user_data["device_id"]
            )
            
            # 验证刷新失败（因为刷新令牌不存在）
            assert refresh_result.is_fail()
            assert "刷新令牌不存在" in refresh_result.error

    def test_user_isolation(self, tokens_manager):
        """测试不同用户之间的令牌隔离性"""
        # 两个不同用户
        user1 = {"user_id": "user1", "username": "user1", "roles": ["user"], "device_id": "device1"}
        user2 = {"user_id": "user2", "username": "user2", "roles": ["user"], "device_id": "device1"}
        
        # 为两个用户创建刷新令牌
        tokens_manager.update_refresh_token(**user1)
        tokens_manager.update_refresh_token(**user2)
        
        # 撤销用户1的令牌
        tokens_manager.revoke_refresh_token(user_id=user1["user_id"], device_id=user1["device_id"])
        
        # 验证用户1的令牌已撤销
        token1 = tokens_manager.get_refresh_token(user_id=user1["user_id"], device_id=user1["device_id"])
        with pytest.raises(jwt.ExpiredSignatureError):
            jwt.decode(token1, key=JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        
        # 验证用户2的令牌仍然有效
        token2 = tokens_manager.get_refresh_token(user_id=user2["user_id"], device_id=user2["device_id"])
        decoded2 = jwt.decode(token2, key=JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        assert decoded2["user_id"] == user2["user_id"]

    def test_blacklist_prevents_token_renewal(self, tokens_manager, user_data):
        """测试黑名单阻止令牌续订"""
        real_blacklist = MemoryTokenBlacklist()
        tokens_manager._token_blacklist = real_blacklist
        
        tokens_manager.update_refresh_token(**user_data)
        
        token_id = f"{user_data['user_id']}:{user_data['device_id']}"
        future_time = get_current_timestamp() + 3600  # 当前时间加1小时
        real_blacklist.add(token_id, future_time)
        
        result = tokens_manager.renew_access_token(**user_data)
        
        assert result.is_fail()
        assert "已经撤销" in result.error

    def test_blacklist_prevents_refresh_token_extension(self, tokens_manager, user_data):
        """测试黑名单阻止延长刷新令牌有效期"""
        real_blacklist = MemoryTokenBlacklist()
        tokens_manager._token_blacklist = real_blacklist
        
        # 创建刷新令牌
        tokens_manager.update_refresh_token(**user_data)
        
        # 将用户令牌加入黑名单
        token_id = f"{user_data['user_id']}:{user_data['device_id']}"
        future_time = get_current_timestamp() + 3600  # 当前时间加1小时
        real_blacklist.add(token_id, future_time)
        
        # 只传入必要的参数
        result = tokens_manager.extend_refresh_token(
            user_id=user_data["user_id"],
            device_id=user_data["device_id"]
        )
        
        # 验证结果
        assert result.is_fail()
        assert "已被撤销" in result.error

    def test_extend_refresh_token_max_lifetime(self, tokens_manager, user_data):
        """测试刷新令牌最大绝对有效期限制"""
        with patch('soulseal.tokens.token_schemas.get_current_timestamp') as mock_time:
            # 设置初始时间
            initial_timestamp = 1672574400.0  # 2023-01-01 12:00:00
            mock_time.return_value = initial_timestamp
            
            # 创建初始令牌
            tokens_manager.update_refresh_token(**user_data)
            
            # 获取令牌并修改它的过期时间和首次发行时间
            token_key = TokenClaims.get_refresh_token_key(user_data["user_id"], user_data["device_id"])
            token_claims = tokens_manager._cache.get(token_key)
            token_claims = TokenClaims(**token_claims)
            
            # 修改令牌有效期为一年后，这样不会因过期而失败
            token_claims.exp = initial_timestamp + (365 * 86400)  # 设置过期时间为一年后
            token_claims.first_issued_at = initial_timestamp
            tokens_manager._cache.put(token_key, token_claims.model_dump())
            
            # 模拟时间流逝到181天后（超过最大有效期但未超过令牌过期时间）
            mock_time.return_value = initial_timestamp + (181 * 86400)
            
            # 尝试延长
            result = tokens_manager.extend_refresh_token(
                user_id=user_data["user_id"],
                device_id=user_data["device_id"],
                max_absolute_lifetime_days=180
            )
        
        assert result.is_fail()
        assert "超过最大" in result.error
