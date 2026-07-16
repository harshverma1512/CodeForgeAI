package com.codeforge.authentication_service.service

import com.codeforge.authentication_service.security.TokenService
import org.springframework.data.redis.core.RedisTemplate
import org.springframework.stereotype.Service
import java.time.Clock
import java.time.Duration
import java.time.Instant

@Service
class TokenBlacklistService(
    private val redisTemplate: RedisTemplate<String, String>,
    private val clock: Clock,
) {
    fun blacklist(jti: String, expiresAt: Instant) {
        val ttl = Duration.between(Instant.now(clock), expiresAt).coerceAtLeast(Duration.ZERO)
        redisTemplate.opsForValue().set(key(jti), "1", ttl)
    }

    fun isBlacklisted(jti: String): Boolean = redisTemplate.hasKey(key(jti)) == true

    private fun key(jti: String) = "blacklist:$jti"
}
