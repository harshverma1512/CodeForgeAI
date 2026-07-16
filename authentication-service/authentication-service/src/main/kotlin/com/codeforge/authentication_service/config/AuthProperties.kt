package com.codeforge.authentication_service.config

import org.springframework.boot.context.properties.ConfigurationProperties
import java.time.Duration

@ConfigurationProperties(prefix = "auth")
data class AuthProperties(
    val issuer: String = "codeforge-authentication-service",
    val jwt: Jwt = Jwt(),
    val security: Security = Security(),
    val otp: Otp = Otp(),
    val oauth2: OAuth2 = OAuth2(),
) {
    data class Jwt(
        val secret: String = "change-me-change-me-change-me-change-me",
        val accessTokenTtl: Duration = Duration.ofMinutes(15),
        val refreshTokenTtl: Duration = Duration.ofDays(30),
    )

    data class Security(
        val loginAttemptLimit: Int = 5,
        val accountLockDuration: Duration = Duration.ofMinutes(15),
        val validateIp: Boolean = true,
        val validateDevice: Boolean = true,
        val refreshTokenRotation: Boolean = true,
    )

    data class Otp(
        val ttl: Duration = Duration.ofMinutes(10),
        val maxAttempts: Int = 5,
    )

    data class OAuth2(
        val redirectUri: String = "http://localhost:3000/auth/oauth2/callback",
    )
}
