package com.codeforge.authentication_service.domain

import jakarta.persistence.Column
import jakarta.persistence.ElementCollection
import jakarta.persistence.Entity
import jakarta.persistence.Enumerated
import jakarta.persistence.EnumType
import jakarta.persistence.FetchType
import jakarta.persistence.Id
import jakarta.persistence.Table
import jakarta.persistence.UniqueConstraint
import java.time.Instant
import java.util.UUID

@Entity
@Table(
    name = "users",
    uniqueConstraints = [
        UniqueConstraint(name = "uk_users_email", columnNames = ["email"]),
        UniqueConstraint(name = "uk_users_phone", columnNames = ["phone"]),
        UniqueConstraint(name = "uk_users_username", columnNames = ["username"]),
    ]
)
open class UserAccount(
    @Id
    @Column(nullable = false, updatable = false)
    open var id: UUID? = null,

    @Column(length = 254)
    open var email: String? = null,

    @Column(length = 32)
    open var phone: String? = null,

    @Column(length = 64)
    open var username: String? = null,

    @Column(length = 255)
    open var passwordHash: String? = null,

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    open var provider: AuthProvider = AuthProvider.LOCAL,

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    open var status: AccountStatus = AccountStatus.ACTIVE,

    @ElementCollection(fetch = FetchType.EAGER)
    @Column(name = "role")
    open var roles: MutableSet<String> = mutableSetOf("USER"),

    @Column(nullable = false)
    open var emailVerified: Boolean = false,

    @Column(nullable = false)
    open var phoneVerified: Boolean = false,

    @Column(nullable = false)
    open var mfaEnabled: Boolean = false,

    @Column(nullable = false)
    open var failedLoginAttempts: Int = 0,

    open var lockedUntil: Instant? = null,

    open var lastLoginAt: Instant? = null,
) : AuditableEntity() {
    fun ensureId() {
        if (id == null) {
            id = UUID.randomUUID()
        }
    }
}
