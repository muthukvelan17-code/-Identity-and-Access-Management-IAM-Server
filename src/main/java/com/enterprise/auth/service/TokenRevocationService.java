package com.enterprise.auth.service;

import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;

@Service
public class TokenRevocationService {

    private final org.springframework.data.redis.core.RedisTemplate<String, Object> redisTemplate;
    private final java.util.Map<String, Boolean> fallbackMap = new java.util.concurrent.ConcurrentHashMap<>();
    
    private static final String BLACKLIST_PREFIX = "blacklisted:";

    public TokenRevocationService(java.util.Optional<org.springframework.data.redis.core.RedisTemplate<String, Object>> redisTemplate) {
        this.redisTemplate = redisTemplate.orElse(null);
    }

    public void blacklistToken(String token, long expirationMs) {
        if (redisTemplate != null) {
            redisTemplate.opsForValue().set(
                    BLACKLIST_PREFIX + token, 
                    true, 
                    Duration.ofMillis(expirationMs)
            );
        } else {
            fallbackMap.put(BLACKLIST_PREFIX + token, true);
        }
    }

    public boolean isTokenBlacklisted(String token) {
        if (redisTemplate != null) {
            try {
                return Boolean.TRUE.equals(redisTemplate.hasKey(BLACKLIST_PREFIX + token));
            } catch (Exception e) {
                return Boolean.TRUE.equals(fallbackMap.get(BLACKLIST_PREFIX + token));
            }
        }
        return Boolean.TRUE.equals(fallbackMap.get(BLACKLIST_PREFIX + token));
    }
}
