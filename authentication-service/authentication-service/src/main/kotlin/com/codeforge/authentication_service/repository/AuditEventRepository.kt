package com.codeforge.authentication_service.repository

import com.codeforge.authentication_service.domain.AuditEventEntity
import com.codeforge.authentication_service.domain.AuditEventType
import org.springframework.data.jpa.repository.JpaRepository
import java.util.UUID

interface AuditEventRepository : JpaRepository<AuditEventEntity, UUID> {
    fun findAllByUserIdOrderByOccurredAtDesc(userId: UUID): List<AuditEventEntity>
    fun findAllByTypeOrderByOccurredAtDesc(type: AuditEventType): List<AuditEventEntity>
}
