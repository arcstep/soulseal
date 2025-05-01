import logging
from datetime import datetime, timedelta

# 黑名单提供者抽象基类
class TokenBlacklistProvider:
    """令牌黑名单抽象接口
    
    不同的黑名单实现必须继承此类并实现所有方法
    """
    def add(self, token_id: str, expires_at: datetime) -> None:
        """将令牌加入黑名单"""
        raise NotImplementedError("子类必须实现此方法")
    
    def contains(self, token_id: str) -> bool:
        """检查令牌是否在黑名单中"""
        raise NotImplementedError("子类必须实现此方法")
    
    def cleanup(self) -> None:
        """清理过期的黑名单条目"""
        raise NotImplementedError("子类必须实现此方法")

# 内存实现 - 用于开发和测试
class MemoryTokenBlacklist(TokenBlacklistProvider):
    def __init__(self):
        self._blacklist = {}  # {token_id: 过期时间}
        self._logger = logging.getLogger(__name__)
        self._last_cleanup = datetime.utcnow()
        self._cleanup_interval = timedelta(minutes=5)
    
    def add(self, token_id: str, expires_at: datetime) -> None:
        self._blacklist[token_id] = expires_at
        self._logger.info(f"令牌已加入内存黑名单: {token_id}")
        
        # 检查是否需要清理
        now = datetime.utcnow()
        if now - self._last_cleanup > self._cleanup_interval:
            self.cleanup()
            self._last_cleanup = now
    
    def contains(self, token_id: str) -> bool:
        if token_id in self._blacklist:
            if datetime.utcnow() > self._blacklist[token_id]:
                del self._blacklist[token_id]
                return False
            return True
        return False
    
    def cleanup(self) -> None:
        now = datetime.utcnow()
        expired_keys = [k for k, v in self._blacklist.items() if now > v]
        if expired_keys:
            for k in expired_keys:
                del self._blacklist[k]
            self._logger.info(f"已清理{len(expired_keys)}个过期黑名单条目")

# Redis实现 - 用于生产和分布式部署
class RedisTokenBlacklist(TokenBlacklistProvider):
    def __init__(self, redis_client, prefix="token_blacklist:"):
        self._redis = redis_client
        self._prefix = prefix
        self._logger = logging.getLogger(__name__)
    
    def add(self, token_id: str, expires_at: datetime) -> None:
        # 计算过期秒数
        ttl = max(0, int((expires_at - datetime.utcnow()).total_seconds()))
        key = f"{self._prefix}{token_id}"
        self._redis.setex(key, ttl, "1")
        self._logger.info(f"令牌已加入Redis黑名单: {token_id}")
    
    def contains(self, token_id: str) -> bool:
        return bool(self._redis.exists(f"{self._prefix}{token_id}"))
    
    def cleanup(self) -> None:
        # Redis会自动过期，无需手动清理
        pass
