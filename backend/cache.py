"""
Advanced caching layer with Redis and in-memory fallback
Implements TTL, invalidation, and performance optimization
"""
from abc import ABC, abstractmethod
from typing import Any, Optional, Dict, List
from datetime import datetime, timedelta
import json
import hashlib
from functools import wraps
import logging

logger = logging.getLogger(__name__)

class CacheBackend(ABC):
    """Abstract base class for cache implementations"""
    
    @abstractmethod
    async def get(self, key: str) -> Optional[Any]:
        pass
    
    @abstractmethod
    async def set(self, key: str, value: Any, ttl: int = 3600) -> bool:
        pass
    
    @abstractmethod
    async def delete(self, key: str) -> bool:
        pass
    
    @abstractmethod
    async def clear_pattern(self, pattern: str) -> int:
        pass

class InMemoryCache(CacheBackend):
    """In-memory cache implementation with TTL support"""
    
    def __init__(self):
        self.store: Dict[str, tuple] = {}
    
    async def get(self, key: str) -> Optional[Any]:
        if key not in self.store:
            return None
        
        value, expiry = self.store[key]
        if datetime.utcnow() > expiry:
            del self.store[key]
            return None
        
        logger.debug(f"Cache hit: {key}")
        return value
    
    async def set(self, key: str, value: Any, ttl: int = 3600) -> bool:
        expiry = datetime.utcnow() + timedelta(seconds=ttl)
        self.store[key] = (value, expiry)
        logger.debug(f"Cache set: {key} (TTL: {ttl}s)")
        return True
    
    async def delete(self, key: str) -> bool:
        if key in self.store:
            del self.store[key]
            return True
        return False
    
    async def clear_pattern(self, pattern: str) -> int:
        """Clear all keys matching pattern"""
        keys_to_delete = [k for k in self.store if pattern in k]
        for key in keys_to_delete:
            await self.delete(key)
        return len(keys_to_delete)

class CacheManager:
    """Unified cache manager with multiple backends"""
    
    def __init__(self, backend: CacheBackend):
        self.backend = backend
    
    @staticmethod
    def generate_key(*args, **kwargs) -> str:
        """Generate cache key from arguments"""
        key_str = str(args) + str(sorted(kwargs.items()))
        return hashlib.md5(key_str.encode()).hexdigest()
    
    async def cache_result(self, key: str, ttl: int = 3600):
        """Decorator to cache function results"""
        def decorator(func):
            @wraps(func)
            async def wrapper(*args, **kwargs):
                # Try to get from cache
                cached = await self.backend.get(key)
                if cached is not None:
                    return cached
                
                # Execute function and cache result
                result = await func(*args, **kwargs)
                await self.backend.set(key, result, ttl)
                return result
            return wrapper
        return decorator
    
    async def invalidate_user_cache(self, user_id: int) -> int:
        """Invalidate all cache related to a user"""
        pattern = f"user_{user_id}"
        return await self.backend.clear_pattern(pattern)
    
    async def invalidate_transaction_cache(self, transaction_id: int) -> int:
        """Invalidate transaction cache"""
        pattern = f"transaction_{transaction_id}"
        return await self.backend.clear_pattern(pattern)

# Global cache instance
_cache_manager: Optional[CacheManager] = None

def get_cache_manager() -> CacheManager:
    """Get or create cache manager"""
    global _cache_manager
    if _cache_manager is None:
        backend = InMemoryCache()
        _cache_manager = CacheManager(backend)
    return _cache_manager
