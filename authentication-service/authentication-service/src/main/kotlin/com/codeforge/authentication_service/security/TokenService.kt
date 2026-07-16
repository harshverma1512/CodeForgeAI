package com.codeforge.authentication_service.security

import com.codeforge.authentication_service.config.AuthProperties
import com.codeforge.authentication_service.domain.TokenKind
import com.codeforge.authentication_service.domain.UserAccount
import com.codeforge.authentication_service.exception.UnauthorizedException
import io.jsonwebtoken.Claims
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.io.Decoders
import io.jsonwebtoken.security.Keys
import org.springframework.stereotype.Service
import java.nio.charset.StandardCharsets
import java.time.Clock
import java.time.Instant
import java.util.Date
import java.util.UUID

@Service
class TokenService(
    private val authProperties: AuthProperties,
    private val clock: Clock,
) {
    private val key by lazy {
        val secret = authProperties.jwt.secret
        val keyBytes = if (secret.matches(Regex("^[A-Za-z0-9+/=]+$")) && secret.length >= 44) {
            Decoders.BASE64.decode(secret)
        } else {
            secret.toByteArray(StandardCharsets.UTF_8)
        }
        Keys.hmacShaKeyFor(keyBytes)
    }

    fun generateAccessToken(user: UserAccount, deviceFingerprint: String?, ipAddress: String?): TokenPairEnvelope {
        val now = Instant.now(clock)
        return buildToken(user, deviceFingerprint, ipAddress, TokenKind.ACCESS, now, authProperties.jwt.accessTokenTtl)
    }

    fun generateRefreshToken(user: UserAccount, deviceFingerprint: String?, ipAddress: String?): TokenPairEnvelope {
        val now = Instant.now(clock)
        return buildToken(user, deviceFingerprint, ipAddress, TokenKind.REFRESH, now, authProperties.jwt.refreshTokenTtl)
    }

    fun parseAndValidate(rawToken: String): TokenClaims {
        val claims = parseClaims(rawToken)
        val kind = claims["kind", String::class.java] ?: throw UnauthorizedException("Token kind missing")
        val subject = claims.subject?.let { UUID.fromString(it) } ?: throw UnauthorizedException("Token subject missing")
        return TokenClaims(
            subject = subject,
            username = claims["username", String::class.java] ?: "",
            roles = claims["roles", List::class.java]?.mapNotNull { it?.toString() }?.toSet().orEmpty(),
            tokenId = claims.id ?: throw UnauthorizedException("Token id missing"),
            kind = kind,
            deviceFingerprint = claims["device", String::class.java],
            ipAddress = claims["ip", String::class.java],
            issuer = claims.issuer ?: throw UnauthorizedException("Token issuer missing"),
            issuedAt = claims.issuedAt?.toInstant() ?: throw UnauthorizedException("Token issuedAt missing"),
            expiresAt = claims.expiration?.toInstant() ?: throw UnauthorizedException("Token expiration missing"),
        )
    }

    fun parseClaims(rawToken: String): Claims =
        Jwts.parser()
            .verifyWith(key)
            .requireIssuer(authProperties.issuer)
            .build()
            .parseSignedClaims(rawToken)
            .payload

    fun hashToken(token: String): String = token.toByteArray(StandardCharsets.UTF_8).let { bytes ->
        java.security.MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
    }

    private fun buildToken(
        user: UserAccount,
        deviceFingerprint: String?,
        ipAddress: String?,
        kind: TokenKind,
        now: Instant,
        ttl: java.time.Duration,
    ): TokenPairEnvelope {
        val jti = UUID.randomUUID().toString()
        val expiresAt = now.plus(ttl)
        val token = Jwts.builder()
            .issuer(authProperties.issuer)
            .subject(user.id!!.toString())
            .id(jti)
            .issuedAt(Date.from(now))
            .expiration(Date.from(expiresAt))
            .claim("username", user.username ?: user.email ?: user.phone ?: user.id.toString())
            .claim("roles", user.roles.toList())
            .claim("kind", kind.name)
            .claim("device", deviceFingerprint)
            .claim("ip", ipAddress)
            .claim("provider", user.provider.name)
            .signWith(key)
            .compact()
        return TokenPairEnvelope(token, jti, expiresAt)
    }
}

data class TokenPairEnvelope(
    val token: String,
    val jti: String,
    val expiresAt: Instant,
)
