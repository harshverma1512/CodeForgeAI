package com.codeforge.authentication_service.service

import com.codeforge.authentication_service.exception.UnauthorizedException
import org.springframework.data.redis.core.RedisTemplate
import org.springframework.stereotype.Service
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.util.UUID

@Service
class PasswordResetService(
    private val redisTemplate: RedisTemplate<String, String>,
    private val clock: Clock,
) {
    fun issue(userId: UUID, ttl: Duration): String {
        val rawToken = "${UUID.randomUUID()}-${UUID.randomUUID()}"
        redisTemplate.opsForValue().set(key(hash(rawToken)), userId.toString(), ttl)
        return rawToken
    }

    fun consume(rawToken: String): UUID {
        val hashed = hash(rawToken)
        val value = redisTemplate.opsForValue().get(key(hashed)) ?: throw UnauthorizedException("Reset token expired or invalid")
        redisTemplate.delete(key(hashed))
        return UUID.fromString(value)
    }

    private fun key(hash: String) = "reset:$hash"

    private fun hash(value: String): String = java.security.MessageDigest.getInstance("SHA-256")
        .digest(value.toByteArray())
        .joinToString("") { "%02x".format(it) }
}
