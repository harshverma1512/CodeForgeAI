package com.codeforge.authentication_service.domain

import jakarta.persistence.Column
import jakarta.persistence.Entity
import jakarta.persistence.Enumerated
import jakarta.persistence.EnumType
import jakarta.persistence.Id
import jakarta.persistence.Index
import jakarta.persistence.Table
import java.time.Instant
import java.util.UUID

@Entity
@Table(
    name = "refresh_tokens",
    indexes = [
        Index(name = "ix_refresh_tokens_user_id", columnList = "userId"),
        Index(name = "ix_refresh_tokens_jti", columnList = "jti"),
    ]
)
open class RefreshTokenEntity(
    @Id
    @Column(nullable = false, updatable = false)
    open var id: UUID? = null,

    @Column(nullable = false)
    open var userId: UUID? = null,

    @Column(nullable = false, unique = true, length = 128)
    open var jti: String = "",

    @Column(nullable = false, length = 128)
    open var tokenHash: String = "",

    @Column(length = 128)
    open var deviceId: String? = null,

    @Column(length = 64)
    open var ipAddress: String? = null,

    @Column(length = 255)
    open var userAgent: String? = null,

    @Column(nullable = false)
    open var expiresAt: Instant = Instant.EPOCH,

    open var revokedAt: Instant? = null,

    @Column(length = 128)
    open var replacedByJti: String? = null,

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    open var kind: TokenKind = TokenKind.REFRESH,
) : AuditableEntity() {
    fun ensureId() {
        if (id == null) {
            id = UUID.randomUUID()
        }
    }
}
