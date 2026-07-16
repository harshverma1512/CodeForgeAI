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
    name = "audit_events",
    indexes = [
        Index(name = "ix_audit_events_user_id", columnList = "userId"),
        Index(name = "ix_audit_events_type", columnList = "type"),
    ]
)
open class AuditEventEntity(
    @Id
    @Column(nullable = false, updatable = false)
    open var id: UUID? = null,

    open var userId: UUID? = null,

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    open var type: AuditEventType = AuditEventType.LOGIN_SUCCESS,

    @Column(nullable = false, length = 32)
    open var outcome: String = "SUCCESS",

    @Column(length = 128)
    open var ipAddress: String? = null,

    @Column(length = 255)
    open var userAgent: String? = null,

    @Column(length = 1024)
    open var details: String? = null,

    @Column(nullable = false)
    open var occurredAt: Instant = Instant.now(),
) : AuditableEntity() {
    fun ensureId() {
        if (id == null) {
            id = UUID.randomUUID()
        }
    }
}
