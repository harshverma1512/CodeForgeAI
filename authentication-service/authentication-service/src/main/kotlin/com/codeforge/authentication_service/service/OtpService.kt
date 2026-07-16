package com.codeforge.authentication_service.service

import com.codeforge.authentication_service.config.AuthProperties
import com.codeforge.authentication_service.dto.OtpResponse
import com.codeforge.authentication_service.exception.UnauthorizedException
import com.fasterxml.jackson.databind.ObjectMapper
import org.slf4j.LoggerFactory
import org.springframework.dao.DataAccessResourceFailureException
import org.springframework.data.redis.core.RedisTemplate
import org.springframework.stereotype.Service
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ThreadLocalRandom

@Service
class OtpService(
    private val redisTemplate: RedisTemplate<String, String>,
    private val objectMapper: ObjectMapper,
    private val authProperties: AuthProperties,
    private val clock: Clock,
) {
    private val log = LoggerFactory.getLogger(javaClass)
    private val fallbackStore = ConcurrentHashMap<String, OtpChallengeRecord>()

    fun issueOtp(
        destination: String,
        purpose: String,
        userId: UUID?,
        challengeId: String? = null,
        ipAddress: String? = null,
        userAgent: String? = null,
        deviceFingerprint: String? = null,
    ): OtpResponse {
        val code = generateCode()
        val id = challengeId ?: UUID.randomUUID().toString()
        val record = OtpChallengeRecord(
            challengeId = id,
            destination = destination,
            purpose = purpose,
            userId = userId,
            codeHash = hash(code),
            ipAddress = ipAddress,
            userAgent = userAgent,
            deviceFingerprint = deviceFingerprint,
            expiresAtEpochMillis = Instant.now(clock).plus(authProperties.otp.ttl).toEpochMilli(),
            attempts = 0,
        )
        try {
            redisTemplate.opsForValue().set(key(id), objectMapper.writeValueAsString(record), authProperties.otp.ttl)
        } catch (ex: DataAccessResourceFailureException) {
            fallbackStore[key(id)] = record
            log.warn("Redis unavailable, using in-memory OTP store: {}", ex.message)
        }
        log.info("OTP issued purpose={} destination={} challengeId={} code={}", purpose, destination, id, code)
        return OtpResponse(id, destination, Instant.ofEpochMilli(record.expiresAtEpochMillis))
    }

    fun verify(challengeId: String, code: String, purpose: String): OtpChallengeRecord {
        val record = loadRecord(challengeId) ?: throw UnauthorizedException("OTP challenge expired")
        if (record.purpose != purpose) {
            throw UnauthorizedException("OTP purpose mismatch")
        }
        if (record.attempts >= authProperties.otp.maxAttempts) {
            deleteRecord(challengeId)
            throw UnauthorizedException("OTP attempt limit exceeded")
        }
        if (record.codeHash != hash(code)) {
            record.attempts += 1
            val expiresAt = Instant.ofEpochMilli(record.expiresAtEpochMillis)
            saveRecord(challengeId, record, Duration.between(Instant.now(clock), expiresAt).coerceAtLeast(Duration.ZERO))
            throw UnauthorizedException("Invalid OTP")
        }
        deleteRecord(challengeId)
        return record
    }

    fun peek(challengeId: String): OtpChallengeRecord? {
        return loadRecord(challengeId)
    }

    private fun key(challengeId: String) = "otp:$challengeId"

    private fun loadRecord(challengeId: String): OtpChallengeRecord? {
        val cacheKey = key(challengeId)
        return try {
            val cached = redisTemplate.opsForValue().get(cacheKey)
            if (cached != null) {
                val record = objectMapper.readValue(cached, OtpChallengeRecord::class.java)
                record.takeIf { Instant.ofEpochMilli(record.expiresAtEpochMillis).isAfter(Instant.now(clock)) }
            } else {
                fallbackStore[cacheKey]?.takeIf { Instant.ofEpochMilli(it.expiresAtEpochMillis).isAfter(Instant.now(clock)) }
            }
        } catch (ex: DataAccessResourceFailureException) {
            fallbackStore[cacheKey]?.takeIf { Instant.ofEpochMilli(it.expiresAtEpochMillis).isAfter(Instant.now(clock)) }
        }
    }

    private fun saveRecord(challengeId: String, record: OtpChallengeRecord, ttl: Duration) {
        val cacheKey = key(challengeId)
        try {
            redisTemplate.opsForValue().set(cacheKey, objectMapper.writeValueAsString(record), ttl)
        } catch (ex: DataAccessResourceFailureException) {
            fallbackStore[cacheKey] = record
            log.warn("Redis unavailable while saving OTP, using in-memory store: {}", ex.message)
        }
    }

    private fun deleteRecord(challengeId: String) {
        val cacheKey = key(challengeId)
        try {
            redisTemplate.delete(cacheKey)
        } catch (ex: DataAccessResourceFailureException) {
            fallbackStore.remove(cacheKey)
            log.warn("Redis unavailable while deleting OTP, removing from in-memory store: {}", ex.message)
        }
        fallbackStore.remove(cacheKey)
    }

    private fun generateCode(): String = ThreadLocalRandom.current().nextInt(100000, 1000000).toString()

    private fun hash(value: String): String = java.security.MessageDigest.getInstance("SHA-256")
        .digest(value.toByteArray())
        .joinToString("") { "%02x".format(it) }
}

data class OtpChallengeRecord(
    val challengeId: String = "",
    val destination: String = "",
    val purpose: String = "",
    val userId: UUID? = null,
    val codeHash: String = "",
    val ipAddress: String? = null,
    val userAgent: String? = null,
    val deviceFingerprint: String? = null,
    val expiresAtEpochMillis: Long = 0,
    var attempts: Int = 0,
)
