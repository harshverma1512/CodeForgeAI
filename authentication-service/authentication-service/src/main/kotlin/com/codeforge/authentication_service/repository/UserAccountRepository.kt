package com.codeforge.authentication_service.repository

import com.codeforge.authentication_service.domain.UserAccount
import org.springframework.data.jpa.repository.JpaRepository
import java.util.UUID

interface UserAccountRepository : JpaRepository<UserAccount, UUID> {
    fun findByEmailIgnoreCase(email: String): UserAccount?
    fun findByPhone(phone: String): UserAccount?
    fun findByUsernameIgnoreCase(username: String): UserAccount?
    fun existsByEmailIgnoreCase(email: String): Boolean
    fun existsByPhone(phone: String): Boolean
    fun existsByUsernameIgnoreCase(username: String): Boolean
}
