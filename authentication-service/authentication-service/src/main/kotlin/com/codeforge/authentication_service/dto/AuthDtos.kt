package com.codeforge.authentication_service.dto

import jakarta.validation.constraints.Email
import jakarta.validation.constraints.NotBlank
import jakarta.validation.constraints.Pattern
import java.time.Instant
import java.util.UUID

data class IdentifierRequest(
    @field:Email(message = "Email must be valid")
    val email: String? = null,
    @field:Pattern(regexp = "^\\+?[0-9]{8,15}$", message = "Phone must be E.164-style digits")
    val phone: String? = null,
    val username: String? = null,
)

data class EmailRegistrationRequest(
    @field:Email
    val email: String,
    @field:NotBlank
    val password: String,
    val username: String? = null,
    val phone: String? = null,
    val fullName: String? = null,
)

data class PhoneRegistrationRequest(
    @field:Pattern(regexp = "^\\+?[0-9]{8,15}$")
    val phone: String,
    @field:NotBlank
    val password: String,
    val email: String? = null,
    val username: String? = null,
    val fullName: String? = null,
)

data class UsernameRegistrationRequest(
    @field:NotBlank
    val username: String,
    @field:NotBlank
    val password: String,
    val email: String? = null,
    val phone: String? = null,
    val fullName: String? = null,
)

data class EmailLoginRequest(
    @field:Email
    val email: String,
    @field:NotBlank
    val password: String,
    val deviceFingerprint: String? = null,
)

data class PhoneLoginRequest(
    @field:Pattern(regexp = "^\\+?[0-9]{8,15}$")
    val phone: String,
    @field:NotBlank
    val password: String,
    val deviceFingerprint: String? = null,
)

data class UsernameLoginRequest(
    @field:NotBlank
    val username: String,
    @field:NotBlank
    val password: String,
    val deviceFingerprint: String? = null,
)

data class ForgotPasswordRequest(
    @field:Email
    val email: String? = null,
    @field:Pattern(regexp = "^\\+?[0-9]{8,15}$")
    val phone: String? = null,
    val username: String? = null,
)

data class ResetPasswordRequest(
    @field:NotBlank
    val token: String,
    @field:NotBlank
    val newPassword: String,
)

data class ChangePasswordRequest(
    @field:NotBlank
    val currentPassword: String,
    @field:NotBlank
    val newPassword: String,
)

data class OtpRequest(
    @field:Email
    val email: String? = null,
    @field:Pattern(regexp = "^\\+?[0-9]{8,15}$")
    val phone: String? = null,
    @field:NotBlank
    val purpose: String,
)

data class VerifyOtpRequest(
    @field:Email
    val email: String? = null,
    @field:Pattern(regexp = "^\\+?[0-9]{8,15}$")
    val phone: String? = null,
    @field:NotBlank
    val purpose: String,
    @field:NotBlank
    val code: String,
    val challengeId: String? = null,
)

data class RefreshTokenRequest(
    @field:NotBlank
    val refreshToken: String,
    val deviceFingerprint: String? = null,
)

data class LogoutRequest(
    @field:NotBlank
    val refreshToken: String,
)

data class DeviceCommandRequest(
    @field:NotBlank
    val deviceId: String,
)

data class AuthResponse(
    val accessToken: String,
    val refreshToken: String,
    val tokenType: String = "Bearer",
    val expiresAt: Instant,
    val refreshExpiresAt: Instant,
    val user: UserSummary,
    val mfaRequired: Boolean = false,
    val mfaChallengeId: String? = null,
)

data class UserSummary(
    val id: UUID,
    val email: String?,
    val phone: String?,
    val username: String?,
    val roles: Set<String>,
    val status: String,
    val provider: String,
    val emailVerified: Boolean,
    val phoneVerified: Boolean,
    val mfaEnabled: Boolean,
)

data class TokenPair(
    val accessToken: String,
    val refreshToken: String,
    val expiresAt: Instant,
    val refreshExpiresAt: Instant,
)

data class OtpResponse(
    val challengeId: String,
    val destination: String,
    val expiresAt: Instant,
)

data class SessionSummary(
    val refreshTokenId: UUID,
    val deviceId: String?,
    val fingerprint: String?,
    val ipAddress: String?,
    val userAgent: String?,
    val issuedAt: Instant,
    val expiresAt: Instant,
    val revokedAt: Instant?,
)

data class DeviceSummary(
    val id: UUID,
    val fingerprint: String,
    val name: String?,
    val ipAddress: String?,
    val userAgent: String?,
    val trusted: Boolean,
    val lastSeenAt: Instant?,
    val revokedAt: Instant?,
)

data class AuditSummary(
    val id: UUID,
    val userId: UUID?,
    val type: String,
    val outcome: String,
    val ipAddress: String?,
    val userAgent: String?,
    val details: String?,
    val occurredAt: Instant,
)

data class AdminUpdateRequest(
    val reason: String? = null,
)
