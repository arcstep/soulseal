import pytest
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock
import time

from soulseal.tokens import TokenBlacklist


@pytest.fixture
def token_blacklist():
    """创建令牌黑名单"""
    return TokenBlacklist()


@pytest.fixture
def token_data():
    """测试令牌数据"""
    return {
        "token_id": "test_user:device123",
        "expires_at": datetime.utcnow() + timedelta(minutes=5)
    }


class TestTokenBlacklist:
    """测试TokenBlacklist类"""
    
    def test_add_and_contains(self, token_blacklist, token_data):
        """测试添加令牌到黑名单"""
        # 添加令牌到黑名单
        token_blacklist.add(token_data["token_id"], token_data["expires_at"])
        
        # 验证令牌在黑名单中
        assert token_blacklist.contains(token_data["token_id"])
    
    def test_expired_token_not_contained(self, token_blacklist):
        """测试过期令牌会自动从黑名单中移除"""
        # 添加已过期的令牌
        token_id = "expired_token"
        expires_at = datetime.utcnow() - timedelta(seconds=1)
        token_blacklist.add(token_id, expires_at)
        
        # 验证令牌不在黑名单中
        assert not token_blacklist.contains(token_id)
    
    def test_cleanup_removes_expired_tokens(self, token_blacklist):
        """测试清理功能会移除过期令牌"""
        # 添加10个令牌，其中一半过期
        for i in range(10):
            token_id = f"token_{i}"
            # 偶数令牌过期，奇数令牌有效
            if i % 2 == 0:
                expires_at = datetime.utcnow() - timedelta(seconds=1)
            else:
                expires_at = datetime.utcnow() + timedelta(minutes=5)
            token_blacklist.add(token_id, expires_at)
        
        # 手动触发清理
        token_blacklist._cleanup()
        
        # 验证结果
        for i in range(10):
            token_id = f"token_{i}"
            if i % 2 == 0:
                assert not token_blacklist.contains(token_id)
            else:
                assert token_blacklist.contains(token_id)
    
    def test_blacklist_size_after_cleanup(self, token_blacklist):
        """测试清理后黑名单的大小"""
        # 添加10个令牌，其中一半过期
        for i in range(10):
            token_id = f"token_{i}"
            if i % 2 == 0:
                expires_at = datetime.utcnow() - timedelta(seconds=1)
            else:
                expires_at = datetime.utcnow() + timedelta(minutes=5)
            token_blacklist.add(token_id, expires_at)
        
        # 手动触发清理
        token_blacklist._cleanup()
        
        # 验证黑名单大小
        assert len(token_blacklist._blacklist) == 5  # 应该只剩下5个有效令牌
    
    def test_auto_cleanup_after_interval(self, token_blacklist):
        """测试在间隔时间后自动清理"""
        # 设置更短的清理间隔
        token_blacklist._cleanup_interval = timedelta(milliseconds=100)
        
        # 添加一个过期令牌
        token_id = "auto_cleanup_test"
        expires_at = datetime.utcnow() - timedelta(seconds=1)
        token_blacklist.add(token_id, expires_at)
        
        # 记录最后清理时间
        original_cleanup_time = token_blacklist._last_cleanup
        
        # 等待足够的时间
        time.sleep(0.2)
        
        # 添加另一个令牌，应该触发自动清理
        token_blacklist.add("another_token", datetime.utcnow() + timedelta(minutes=5))
        
        # 验证清理时间已更新
        assert token_blacklist._last_cleanup > original_cleanup_time
        
        # 验证过期令牌已被清理
        assert not token_blacklist.contains(token_id)
    
    def test_mocked_cleanup(self, token_blacklist):
        """使用模拟对象测试清理逻辑"""
        # 模拟清理方法
        with patch.object(token_blacklist, '_cleanup') as mock_cleanup:
            # 设置短清理间隔
            token_blacklist._cleanup_interval = timedelta(milliseconds=1)
            token_blacklist._last_cleanup = datetime.utcnow() - timedelta(seconds=1)
            
            # 添加令牌，应该触发清理
            token_blacklist.add("test_token", datetime.utcnow() + timedelta(minutes=5))
            
            # 验证清理方法被调用
            mock_cleanup.assert_called_once()
    
    def test_concurrent_access(self, token_blacklist):
        """测试并发访问场景"""
        # 添加一个有效令牌
        token_id = "concurrent_test"
        expires_at = datetime.utcnow() + timedelta(minutes=5)
        token_blacklist.add(token_id, expires_at)
        
        # 模拟并发检查和删除
        # 首先检查令牌是否存在
        assert token_blacklist.contains(token_id)
        
        # 在检查后但在可能的删除前，模拟另一个线程删除了该令牌
        token_blacklist._blacklist.pop(token_id)
        
        # 再次检查，应该返回False
        assert not token_blacklist.contains(token_id)
    
    def test_long_term_behavior(self, token_blacklist):
        """测试长期使用行为"""
        # 添加100个令牌，设置不同的过期时间
        for i in range(100):
            token_id = f"long_term_{i}"
            # 设置一些已过期，一些即将过期，一些在未来过期
            if i < 30:  # 已过期
                expires_at = datetime.utcnow() - timedelta(seconds=i)
            elif i < 60:  # 即将过期
                expires_at = datetime.utcnow() + timedelta(seconds=i-30)
            else:  # 未来过期
                expires_at = datetime.utcnow() + timedelta(minutes=i-50)
            
            token_blacklist.add(token_id, expires_at)
        
        # 手动触发清理
        token_blacklist._cleanup()
        
        # 验证已过期的令牌都被清理
        for i in range(30):
            assert not token_blacklist.contains(f"long_term_{i}")
        
        # 有些即将过期的令牌应该仍然存在
        assert any(token_blacklist.contains(f"long_term_{i}") for i in range(30, 60))
        
        # 未来过期的令牌应该都存在
        for i in range(60, 100):
            assert token_blacklist.contains(f"long_term_{i}")
    
    def test_empty_blacklist(self, token_blacklist):
        """测试空黑名单的行为"""
        # 黑名单为空时应该正确处理contains请求
        assert not token_blacklist.contains("nonexistent_token")
        
        # 触发清理不应该出错
        token_blacklist._cleanup()
        
        # 仍然应该正确处理contains请求
        assert not token_blacklist.contains("nonexistent_token") 