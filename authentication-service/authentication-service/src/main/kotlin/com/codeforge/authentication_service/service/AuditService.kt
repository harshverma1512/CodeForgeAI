package com.codeforge.authentication_service.service

import com.codeforge.authentication_service.domain.AuditEventEntity
import com.codeforge.authentication_service.domain.AuditEventType
import com.codeforge.authentication_service.repository.AuditEventRepository
import com.fasterxml.jackson.databind.ObjectMapper
import org.slf4j.LoggerFactory
import org.springframework.kafka.core.KafkaTemplate
import org.springframework.kafka.core.KafkaOperations
import org.springframework.beans.factory.ObjectProvider
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import java.time.Instant
import java.util.UUID

@Service
class AuditService(
    private val auditEventRepository: AuditEventRepository,
    private val kafkaTemplate: ObjectProvider<KafkaTemplate<String, String>>,
    private val objectMapper: ObjectMapper,
) {
    private val log = LoggerFactory.getLogger(javaClass)

    @Transactional
    fun record(
        type: AuditEventType,
        userId: UUID?,
        outcome: String,
        ipAddress: String? = null,
        userAgent: String? = null,
        details: String? = null,
    ): AuditEventEntity {
        val event = AuditEventEntity(
            userId = userId,
            type = type,
            outcome = outcome,
            ipAddress = ipAddress,
            userAgent = userAgent,
            details = details,
            occurredAt = Instant.now(),
        ).apply { ensureId() }
        val saved = auditEventRepository.save(event)
        kafkaTemplate.ifAvailable?.let { producer ->
            runCatching {
                producer.send("auth.audit", objectMapper.writeValueAsString(saved))
            }.onFailure { log.debug("Kafka audit publish failed: {}", it.message) }
        }
        return saved
    }
}
