package com.codeforge.authentication_service.domain

import jakarta.persistence.Column
import jakarta.persistence.Entity
import jakarta.persistence.Id
import jakarta.persistence.Index
import jakarta.persistence.Table
import java.time.Instant
import java.util.UUID

@Entity
@Table(
    name = "devices",
    indexes = [
        Index(name = "ix_devices_user_id", columnList = "userId"),
        Index(name = "ix_devices_fingerprint", columnList = "fingerprint"),
    ]
)
open class DeviceEntity(
    @Id
    @Column(nullable = false, updatable = false)
    open var id: UUID? = null,

    @Column(nullable = false)
    open var userId: UUID? = null,

    @Column(nullable = false, length = 128)
    open var fingerprint: String = "",

    @Column(length = 128)
    open var name: String? = null,

    @Column(length = 64)
    open var ipAddress: String? = null,

    @Column(length = 255)
    open var userAgent: String? = null,

    @Column(nullable = false)
    open var trusted: Boolean = false,

    open var lastSeenAt: Instant? = null,

    open var revokedAt: Instant? = null,
) : AuditableEntity() {
    fun ensureId() {
        if (id == null) {
            id = UUID.randomUUID()
        }
    }
}
