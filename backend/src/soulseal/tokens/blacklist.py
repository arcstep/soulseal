import logging
from datetime import datetime, timedelta
from typing import Union, Optional
from .token_schemas import get_current_timestamp, get_expires_timestamp

# 黑名单提供者抽象基类
class TokenBlacklistProvider:
    """令牌黑名单抽象接口
    
    不同的黑名单实现必须继承此类并实现所有方法
    """
    def __init__(self):
        self._logger = logging.getLogger(__name__)
    
    def _normalize_expiry(self, expires_at: Union[float, datetime]) -> float:
        """标准化过期时间为时间戳格式"""
        if isinstance(expires_at, datetime):
            return expires_at.timestamp()
        return expires_at
    
    def _is_expired(self, expiry_timestamp: float) -> bool:
        """检查时间戳是否已过期"""
        # 添加调试日志
        now = get_current_timestamp()
        self._logger.debug(f"比较时间: 当前={now}, 过期={expiry_timestamp}, 差值={expiry_timestamp - now}秒")
        # 调试后发现可能是本地系统时间与转换的UTC时间之间有差异
        return now > expiry_timestamp
    
    def _get_ttl_seconds(self, expiry_timestamp: float) -> int:
        """计算从现在到过期时间的秒数"""
        now = get_current_timestamp()
        return max(0, int(expiry_timestamp - now))
    
    def add(self, token_id: str, expires_at: Union[float, datetime]) -> None:
        """将令牌加入黑名单"""
        # 简化逻辑，直接存储时间戳
        expiry_timestamp = self._normalize_expiry(expires_at)
        self._store_token(token_id, expiry_timestamp)
    
    def contains(self, token_id: str) -> bool:
        """检查令牌是否在黑名单中且未过期"""
        # 获取存储的过期时间戳
        expiry_timestamp = self._get_token_expiry(token_id)
        
        # 如果不存在或已过期，返回False
        if expiry_timestamp is None or self._is_expired(expiry_timestamp):
            return False
            
        return True
    
    def cleanup(self) -> None:
        """清理过期的黑名单条目 - 由子类实现"""
        pass
    
    # 以下为子类必须实现的抽象方法
    def _store_token(self, token_id: str, expiry_timestamp: float) -> None:
        """存储令牌到黑名单 - 子类必须实现"""
        raise NotImplementedError("子类必须实现此方法")
    
    def _get_token_expiry(self, token_id: str) -> Optional[float]:
        """获取令牌的过期时间 - 子类必须实现"""
        raise NotImplementedError("子类必须实现此方法")

# 内存实现 - 用于开发和测试
class MemoryTokenBlacklist(TokenBlacklistProvider):
    def __init__(self):
        super().__init__()
        self._tokens = {}  # {token_id: 过期时间戳}
        self._last_cleanup = get_current_timestamp()
        self._cleanup_interval = timedelta(minutes=5)
    
    def _store_token(self, token_id: str, expiry_timestamp: float) -> None:
        """存储令牌到内存"""
        self._tokens[token_id] = expiry_timestamp
        
        # 检查是否需要清理
        now = get_current_timestamp()
        if now - self._last_cleanup > self._cleanup_interval.total_seconds():
            self.cleanup()
            self._last_cleanup = now
            
    def _get_token_expiry(self, token_id: str) -> Optional[float]:
        """获取令牌的过期时间戳"""
        return self._tokens.get(token_id)
    
    def cleanup(self) -> None:
        """清理过期的黑名单条目"""
        now = get_current_timestamp()
        expired_keys = [k for k, v in self._tokens.items() if now > v]
        for k in expired_keys:
            del self._tokens[k]
        if expired_keys:
            self._logger.info(f"已清理{len(expired_keys)}个过期黑名单条目")

# Redis实现 - 用于生产和分布式部署
class RedisTokenBlacklist(TokenBlacklistProvider):
    def __init__(self, redis_client, prefix="token_blacklist:"):
        super().__init__()
        self._redis = redis_client
        self._prefix = prefix
    
    def _store_token(self, token_id: str, expiry_timestamp: float) -> None:
        """存储令牌到Redis"""
        # 计算TTL秒数
        ttl_seconds = self._get_ttl_seconds(expiry_timestamp)
        
        # 设置Redis键的过期时间
        key = f"{self._prefix}{token_id}"
        self._redis.setex(key, ttl_seconds, "1")
        self._logger.info(f"令牌已加入Redis黑名单: {token_id}, 过期时间: {ttl_seconds}秒")
            
    def _get_token_expiry(self, token_id: str) -> Optional[float]:
        """Redis实现中只需判断键是否存在（Redis会自动清除过期键）"""
        key = f"{self._prefix}{token_id}"
        if self._redis.exists(key):
            # 获取剩余TTL
            ttl = self._redis.ttl(key)
            if ttl > 0:
                # 转换为过期时间戳
                return get_current_timestamp() + ttl
        return None
    
    # Redis会自动清理过期键，无需实现cleanup
