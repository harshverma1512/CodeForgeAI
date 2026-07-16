package com.codeforge.authentication_service.repository

import com.codeforge.authentication_service.domain.RefreshTokenEntity
import com.codeforge.authentication_service.domain.TokenKind
import org.springframework.data.jpa.repository.JpaRepository
import java.time.Instant
import java.util.UUID

interface RefreshTokenRepository : JpaRepository<RefreshTokenEntity, UUID> {
    fun findByJti(jti: String): RefreshTokenEntity?
    fun findAllByUserIdAndRevokedAtIsNullAndExpiresAtAfterAndKind(userId: UUID, expiresAt: Instant, kind: TokenKind): List<RefreshTokenEntity>
    fun findAllByUserId(userId: UUID): List<RefreshTokenEntity>
    fun findAllByUserIdAndRevokedAtIsNull(userId: UUID): List<RefreshTokenEntity>
}
