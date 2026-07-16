package com.codeforge.authentication_service.security

import java.time.Instant
import java.util.UUID

data class TokenClaims(
    val subject: UUID,
    val username: String,
    val roles: Set<String>,
    val tokenId: String,
    val kind: String,
    val deviceFingerprint: String?,
    val ipAddress: String?,
    val issuer: String,
    val issuedAt: Instant,
    val expiresAt: Instant,
)
