package com.codeforge.authentication_service.domain

import jakarta.persistence.Column
import jakarta.persistence.EntityListeners
import jakarta.persistence.MappedSuperclass
import org.springframework.data.annotation.CreatedDate
import org.springframework.data.annotation.LastModifiedDate
import org.springframework.data.jpa.domain.support.AuditingEntityListener
import java.time.Instant

@MappedSuperclass
@EntityListeners(AuditingEntityListener::class)
abstract class AuditableEntity {
    @CreatedDate
    @Column(nullable = false, updatable = false)
    open var createdAt: Instant = Instant.EPOCH

    @LastModifiedDate
    @Column(nullable = false)
    open var updatedAt: Instant = Instant.EPOCH
}
