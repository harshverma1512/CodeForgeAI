package com.codeforge.authentication_service.repository

import com.codeforge.authentication_service.domain.DeviceEntity
import org.springframework.data.jpa.repository.JpaRepository
import java.util.UUID

interface DeviceRepository : JpaRepository<DeviceEntity, UUID> {
    fun findByUserId(userId: UUID): List<DeviceEntity>
    fun findByUserIdAndFingerprint(userId: UUID, fingerprint: String): DeviceEntity?
}
