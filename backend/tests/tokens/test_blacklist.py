import pytest
from datetime import datetime, timedelta
import time
from unittest.mock import MagicMock, patch

from soulseal.tokens.blacklist import (
    TokenBlacklistProvider,
    MemoryTokenBlacklist,
    RedisTokenBlacklist,
    get_current_timestamp,
    get_expires_timestamp
)

# MemoryTokenBlacklist 测试

class TestMemoryTokenBlacklist:
    @pytest.fixture
    def blacklist(self):
        """创建内存黑名单实例"""
        return MemoryTokenBlacklist()
    
    def test_add_token(self, blacklist):
        """测试添加令牌到黑名单"""
        # 同时模拟两处时间函数
        with patch('soulseal.tokens.blacklist.get_current_timestamp', 
                  return_value=1000000.0), \
             patch('soulseal.tokens.token_schemas.get_current_timestamp', 
                  return_value=1000000.0):
            
            # 设置过期时间为未来
            expires_at = 1000000.0 + 3600  # 比当前时间晚1小时
            token_id = "user1:device1"
            
            blacklist.add(token_id, expires_at)
            assert blacklist.contains(token_id) is True
            assert token_id in blacklist._tokens
    
    def test_contains_valid_token(self, blacklist):
        """测试检查有效令牌是否在黑名单中"""
        with patch('soulseal.tokens.blacklist.get_current_timestamp', 
                  return_value=1000000.0), \
             patch('soulseal.tokens.token_schemas.get_current_timestamp', 
                  return_value=1000000.0):
            
            # 添加未过期的令牌（使用固定时间而非当前时间）
            token_id = "user1:device1"
            expires_at = 1000000.0 + 3600  # 过期时间比当前时间晚1小时
            blacklist.add(token_id, expires_at)
            
            # 验证令牌在黑名单中
            assert blacklist.contains(token_id) is True
    
    def test_contains_expired_token(self, blacklist):
        """测试检查过期令牌是否在黑名单中"""
        with patch('soulseal.tokens.blacklist.get_current_timestamp',
                  return_value=1000000.0), \
             patch('soulseal.tokens.token_schemas.get_current_timestamp',
                  return_value=1000000.0):
            
            # 添加已过期的令牌（过期时间设为过去）
            token_id = "user1:device1"
            expires_at = 1000000.0 - 60  # 过期1分钟
            blacklist.add(token_id, expires_at)
            
            # 验证令牌不在黑名单中(过期后应自动判定为不在黑名单)
            assert blacklist.contains(token_id) is False
    
    def test_contains_nonexistent_token(self, blacklist):
        """测试检查不存在的令牌"""
        assert blacklist.contains("nonexistent") is False
    
    def test_cleanup(self, blacklist):
        """测试清理过期令牌"""
        with patch('soulseal.tokens.blacklist.get_current_timestamp', 
                  return_value=1000000.0), \
             patch('soulseal.tokens.token_schemas.get_current_timestamp', 
                  return_value=1000000.0):
            
            # 添加一个未过期的令牌
            valid_token = "user1:device1"
            valid_expires = 1000000.0 + 3600  # 过期时间比当前时间晚1小时
            blacklist.add(valid_token, valid_expires)
            
            # 添加一个已过期的令牌
            expired_token = "user2:device2"
            expired_expires = 1000000.0 - 60  # 过期时间比当前时间早1分钟
            blacklist.add(expired_token, expired_expires)
            
            # 执行清理
            blacklist.cleanup()
            
            # 验证：未过期的令牌保留，过期的令牌被删除
            assert blacklist.contains(valid_token) is True
            assert blacklist.contains(expired_token) is False
            assert valid_token in blacklist._tokens
            assert expired_token not in blacklist._tokens
    
    def test_auto_cleanup(self, blacklist):
        """测试自动清理功能"""
        with patch('soulseal.tokens.blacklist.get_current_timestamp', 
                  return_value=1000000.0), \
             patch('soulseal.tokens.token_schemas.get_current_timestamp', 
                  return_value=1000000.0):
            
            # 修改清理间隔为0，确保每次add都会触发清理
            blacklist._cleanup_interval = timedelta(seconds=0)
            
            # 添加一个已过期的令牌
            expired_token = "user2:device2"
            expired_expires = 1000000.0 - 60  # 过期1分钟
            blacklist.add(expired_token, expired_expires)
            
            # 添加一个未过期的令牌，这应该触发自动清理
            valid_token = "user1:device1"
            valid_expires = 1000000.0 + 3600  # 晚1小时过期
            blacklist.add(valid_token, valid_expires)
            
            # 验证过期令牌被清理
            assert blacklist.contains(expired_token) is False
            assert blacklist.contains(valid_token) is True


# RedisTokenBlacklist 测试

class TestRedisTokenBlacklist:
    @pytest.fixture
    def redis_mock(self):
        """创建Redis客户端的模拟"""
        redis_client = MagicMock()
        # 默认返回值，避免未配置mock方法出错
        redis_client.exists.return_value = 0
        redis_client.ttl.return_value = 3600  # 1小时
        return redis_client
    
    @pytest.fixture
    def blacklist(self, redis_mock):
        """创建基于Redis的黑名单实例"""
        return RedisTokenBlacklist(redis_client=redis_mock)
    
    def test_add_token(self, blacklist, redis_mock):
        """测试添加令牌到Redis黑名单"""
        with patch('soulseal.tokens.blacklist.get_current_timestamp',
                  return_value=1000000.0), \
             patch('soulseal.tokens.token_schemas.get_current_timestamp',
                  return_value=1000000.0):
            
            # 设置过期时间为1小时后
            token_id = "user1:device1"
            expires_at = 1000000.0 + 3600
            
            blacklist.add(token_id, expires_at)
            
            # 验证Redis setex方法被正确调用，TTL应为3600
            key = f"{blacklist._prefix}{token_id}"
            redis_mock.setex.assert_called_once_with(key, 3600, "1")
    
    def test_contains_token(self, blacklist, redis_mock):
        """测试检查令牌是否在Redis黑名单中"""
        token_id = "user1:device1"
        key = f"{blacklist._prefix}{token_id}"
        
        # 设置mock返回值
        redis_mock.exists.return_value = 1
        
        # 验证令牌在黑名单中
        assert blacklist.contains(token_id) is True
        redis_mock.exists.assert_called_once_with(key)
        
        # 重置mock并测试不存在的令牌
        redis_mock.exists.reset_mock()
        redis_mock.exists.return_value = 0
        
        assert blacklist.contains(token_id) is False
        redis_mock.exists.assert_called_once_with(key)
    
    def test_cleanup_does_nothing(self, blacklist, redis_mock):
        """测试Redis黑名单的cleanup方法不执行任何操作"""
        # cleanup应该是个空操作
        blacklist.cleanup()
        
        # 验证没有调用任何Redis方法
        redis_mock.assert_not_called()
    
    def test_add_expired_token(self, blacklist, redis_mock):
        """测试添加已过期的令牌到Redis黑名单"""
        with patch('soulseal.tokens.blacklist.get_current_timestamp', 
                  return_value=1000000.0), \
             patch('soulseal.tokens.token_schemas.get_current_timestamp', 
                  return_value=1000000.0):
            
            token_id = "user1:device1"
            # 设置过期时间为过去
            expires_at = 1000000.0 - 3600  # 过期1小时
            
            # 添加令牌到黑名单
            blacklist.add(token_id, expires_at)
            
            # 验证Redis setex被调用，TTL为0
            key = f"{blacklist._prefix}{token_id}"
            redis_mock.setex.assert_called_once_with(key, 0, "1")
    
    def test_custom_prefix(self, redis_mock):
        """测试自定义前缀"""
        with patch('soulseal.tokens.blacklist.get_current_timestamp', 
                  return_value=1000000.0), \
             patch('soulseal.tokens.token_schemas.get_current_timestamp', 
                  return_value=1000000.0):
            
            custom_prefix = "test_blacklist:"
            blacklist = RedisTokenBlacklist(redis_client=redis_mock, prefix=custom_prefix)
            
            token_id = "user1:device1"
            expires_at = 1000000.0 + 3600  # 过期时间为1小时后
            
            # 添加令牌到黑名单
            blacklist.add(token_id, expires_at)
            
            # 验证使用了自定义前缀
            key = f"{custom_prefix}{token_id}"
            redis_mock.setex.assert_called_once()
            assert redis_mock.setex.call_args[0][0] == key

    def test_contains_token_with_fixed_time(self, blacklist, redis_mock):
        """测试检查令牌是否在Redis黑名单中，使用固定时间"""
        token_id = "user1:device1"
        key = f"{blacklist._prefix}{token_id}"
        
        # 设置mock返回值
        redis_mock.exists.return_value = 1
        
        with patch('soulseal.tokens.token_schemas.get_current_timestamp') as mock_time:
            mock_time.return_value = time.time()  # 使用固定时间
            # 验证令牌在黑名单中
            assert blacklist.contains(token_id) is True
            redis_mock.exists.assert_called_once_with(key)
        
        # 重置mock并测试不存在的令牌
        redis_mock.exists.reset_mock()
        redis_mock.exists.return_value = 0
        
        assert blacklist.contains(token_id) is False
        redis_mock.exists.assert_called_once_with(key)
