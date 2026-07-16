package com.codeforge.authentication_service.service

import com.codeforge.authentication_service.config.AuthProperties
import com.codeforge.authentication_service.domain.*
import com.codeforge.authentication_service.dto.*
import com.codeforge.authentication_service.exception.BadRequestException
import com.codeforge.authentication_service.exception.ConflictException
import com.codeforge.authentication_service.exception.ForbiddenException
import com.codeforge.authentication_service.exception.NotFoundException
import com.codeforge.authentication_service.exception.UnauthorizedException
import com.codeforge.authentication_service.repository.AuditEventRepository
import com.codeforge.authentication_service.repository.DeviceRepository
import com.codeforge.authentication_service.repository.RefreshTokenRepository
import com.codeforge.authentication_service.repository.UserAccountRepository
import com.codeforge.authentication_service.security.AuthenticatedPrincipal
import com.codeforge.authentication_service.security.TokenPairEnvelope
import com.codeforge.authentication_service.security.TokenService
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import java.time.Clock
import java.time.Instant
import java.util.UUID

@Service
class AuthService(
    private val userAccountRepository: UserAccountRepository,
    private val refreshTokenRepository: RefreshTokenRepository,
    private val deviceRepository: DeviceRepository,
    private val auditEventRepository: AuditEventRepository,
    private val passwordEncoder: PasswordEncoder,
    private val tokenService: TokenService,
    private val tokenBlacklistService: TokenBlacklistService,
    private val otpService: OtpService,
    private val passwordResetService: PasswordResetService,
    private val auditService: AuditService,
    private val authProperties: AuthProperties,
    private val clock: Clock,
) {
    @Transactional
    fun registerEmail(request: EmailRegistrationRequest, ip: String?, userAgent: String?): AuthResponse =
        register(request.email, request.phone, request.username ?: request.email.substringBefore("@"), request.password, AuthProvider.LOCAL, ip, userAgent)

    @Transactional
    fun registerPhone(request: PhoneRegistrationRequest, ip: String?, userAgent: String?): AuthResponse =
        register(request.email, request.phone, request.username ?: request.phone.filter(Char::isDigit), request.password, AuthProvider.LOCAL, ip, userAgent)

    @Transactional
    fun registerUsername(request: UsernameRegistrationRequest, ip: String?, userAgent: String?): AuthResponse =
        register(request.email, request.phone, request.username, request.password, AuthProvider.LOCAL, ip, userAgent)

    @Transactional
    fun loginEmail(request: EmailLoginRequest, ip: String?, userAgent: String?): AuthResponse =
        login(request.email, request.password, request.deviceFingerprint, ip, userAgent)

    @Transactional
    fun loginPhone(request: PhoneLoginRequest, ip: String?, userAgent: String?): AuthResponse =
        login(request.phone, request.password, request.deviceFingerprint, ip, userAgent)

    @Transactional
    fun loginUsername(request: UsernameLoginRequest, ip: String?, userAgent: String?): AuthResponse =
        login(request.username, request.password, request.deviceFingerprint, ip, userAgent)

    @Transactional
    fun handleOAuth2Login(provider: AuthProvider, identifier: String, email: String?, username: String?, ip: String?, userAgent: String?): AuthResponse {
        val user = findOrCreateOAuthUser(provider, identifier, email, username)
        return issueSession(user, oauthFingerprint(identifier, userAgent), ip, userAgent).toAuthResponse(user)
    }

    @Transactional
    fun refresh(request: RefreshTokenRequest, ip: String?, userAgent: String?): AuthResponse {
        val claims = tokenService.parseAndValidate(request.refreshToken)
        if (claims.kind != TokenKind.REFRESH.name) throw UnauthorizedException("Not a refresh token")
        if (tokenBlacklistService.isBlacklisted(claims.tokenId)) throw UnauthorizedException("Refresh token revoked")

        val tokenRecord = refreshTokenRepository.findByJti(claims.tokenId) ?: throw UnauthorizedException("Refresh token not recognized")
        if (tokenRecord.revokedAt != null || tokenRecord.expiresAt.isBefore(Instant.now(clock))) throw UnauthorizedException("Refresh token expired")
        if (authProperties.security.validateIp && ip != null && tokenRecord.ipAddress != null && tokenRecord.ipAddress != ip) {
            throw UnauthorizedException("IP validation failed")
        }
        if (authProperties.security.validateDevice && request.deviceFingerprint != null && tokenRecord.deviceId != null && tokenRecord.deviceId != request.deviceFingerprint) {
            throw UnauthorizedException("Device validation failed")
        }

        val user = userAccountRepository.findById(tokenRecord.userId!!).orElseThrow { UnauthorizedException("User not found") }
        ensureActive(user)

        val session = issueSession(user, request.deviceFingerprint ?: tokenRecord.deviceId, ip, userAgent)
        tokenRecord.revokedAt = Instant.now(clock)
        tokenRecord.replacedByJti = tokenService.parseAndValidate(session.refresh.token).tokenId
        refreshTokenRepository.save(tokenRecord)
        tokenBlacklistService.blacklist(claims.tokenId, claims.expiresAt)
        auditService.record(AuditEventType.TOKEN_REFRESHED, user.id, "SUCCESS", ip, userAgent, "token rotated")
        return session.toAuthResponse(user)
    }

    @Transactional
    fun logout(refreshToken: String, ip: String?, userAgent: String?): Boolean {
        val claims = tokenService.parseAndValidate(refreshToken)
        if (claims.kind != TokenKind.REFRESH.name) throw UnauthorizedException("Not a refresh token")
        refreshTokenRepository.findByJti(claims.tokenId)?.let {
            it.revokedAt = Instant.now(clock)
            refreshTokenRepository.save(it)
        }
        tokenBlacklistService.blacklist(claims.tokenId, claims.expiresAt)
        auditService.record(AuditEventType.LOGOUT, claims.subject, "SUCCESS", ip, userAgent, "logout")
        return true
    }

    @Transactional
    fun logoutAll(userId: UUID, ip: String?, userAgent: String?): Boolean {
        refreshTokenRepository.findAllByUserIdAndRevokedAtIsNull(userId).forEach {
            it.revokedAt = Instant.now(clock)
            refreshTokenRepository.save(it)
            tokenBlacklistService.blacklist(it.jti, it.expiresAt)
        }
        auditService.record(AuditEventType.LOGOUT_ALL, userId, "SUCCESS", ip, userAgent, "logout all devices")
        return true
    }

    @Transactional
    fun forgotPassword(request: ForgotPasswordRequest, ip: String?, userAgent: String?): String {
        val user = findUser(request.email, request.phone, request.username) ?: return "If the account exists, a reset link has been issued."
        val token = passwordResetService.issue(user.id!!, authProperties.jwt.refreshTokenTtl)
        auditService.record(AuditEventType.PASSWORD_RESET_REQUESTED, user.id, "SUCCESS", ip, userAgent, "reset requested")
        return token
    }

    @Transactional
    fun resetPassword(request: ResetPasswordRequest, ip: String?, userAgent: String?): Boolean {
        val userId = passwordResetService.consume(request.token)
        val user = userAccountRepository.findById(userId).orElseThrow { NotFoundException("User not found") }
        user.passwordHash = passwordEncoder.encode(request.newPassword)
        user.failedLoginAttempts = 0
        user.lockedUntil = null
        user.status = AccountStatus.ACTIVE
        userAccountRepository.save(user)
        logoutAll(user.id!!, ip, userAgent)
        auditService.record(AuditEventType.PASSWORD_RESET_COMPLETED, user.id, "SUCCESS", ip, userAgent, "password reset")
        return true
    }

    @Transactional
    fun changePassword(userId: UUID, request: ChangePasswordRequest, ip: String?, userAgent: String?): Boolean {
        val user = userAccountRepository.findById(userId).orElseThrow { NotFoundException("User not found") }
        ensureActive(user)
        if (!passwordEncoder.matches(request.currentPassword, user.passwordHash)) throw UnauthorizedException("Current password is incorrect")
        user.passwordHash = passwordEncoder.encode(request.newPassword)
        userAccountRepository.save(user)
        logoutAll(user.id!!, ip, userAgent)
        auditService.record(AuditEventType.PASSWORD_CHANGED, user.id, "SUCCESS", ip, userAgent, "password changed")
        return true
    }

    @Transactional
    fun requestOtp(request: OtpRequest, ip: String?, userAgent: String?): OtpResponse {
        val destination = request.email ?: request.phone ?: throw BadRequestException("Email or phone is required")
        val user = findUser(request.email, request.phone, null)
        val response = otpService.issueOtp(destination, request.purpose, user?.id, ipAddress = ip, userAgent = userAgent)
        auditService.record(
            AuditEventType.OTP_SENT,
            user?.id,
            "SUCCESS",
            ip,
            userAgent,
            "purpose=${request.purpose}, destination=$destination"
        )
        return response
    }

    @Transactional
    fun verifyOtp(request: VerifyOtpRequest, ip: String?, userAgent: String?): AuthResponse {
        val challengeId = request.challengeId ?: throw BadRequestException("challengeId is required")
        val record = otpService.verify(challengeId, request.code, request.purpose)
        val user = record.userId?.let { userAccountRepository.findById(it).orElseThrow { NotFoundException("User not found") } }
            ?: findUser(request.email, request.phone, null)
            ?: throw NotFoundException("User not found")

        return when (request.purpose.uppercase()) {
            "LOGIN" -> {
                ensureActive(user)
                userAccountRepository.save(user)
                auditService.record(AuditEventType.MFA_VERIFIED, user.id, "SUCCESS", ip, userAgent, "login verified")
                issueSession(user, record.deviceFingerprint ?: record.destination, ip, userAgent).toAuthResponse(user)
            }
            "EMAIL_VERIFY" -> {
                user.emailVerified = true
                userAccountRepository.save(user)
                auditService.record(AuditEventType.OTP_VERIFIED, user.id, "SUCCESS", ip, userAgent, "email verified")
                issueSession(user, record.destination, ip, userAgent).toAuthResponse(user)
            }
            "MOBILE_VERIFY" -> {
                user.phoneVerified = true
                userAccountRepository.save(user)
                auditService.record(AuditEventType.OTP_VERIFIED, user.id, "SUCCESS", ip, userAgent, "mobile verified")
                issueSession(user, record.destination, ip, userAgent).toAuthResponse(user)
            }
            else -> throw BadRequestException("Unsupported OTP purpose")
        }
    }

    fun me(principal: AuthenticatedPrincipal): UserSummary =
        userAccountRepository.findById(principal.userId).orElseThrow { NotFoundException("User not found") }.toSummary()

    fun sessions(userId: UUID): List<SessionSummary> =
        refreshTokenRepository.findAllByUserId(userId).map {
            SessionSummary(
                refreshTokenId = it.id ?: UUID.randomUUID(),
                deviceId = it.deviceId,
                fingerprint = it.deviceId,
                ipAddress = it.ipAddress,
                userAgent = it.userAgent,
                issuedAt = it.createdAt,
                expiresAt = it.expiresAt,
                revokedAt = it.revokedAt,
            )
        }

    fun devices(userId: UUID): List<DeviceSummary> =
        deviceRepository.findByUserId(userId).map {
            DeviceSummary(
                id = it.id ?: UUID.randomUUID(),
                fingerprint = it.fingerprint,
                name = it.name,
                ipAddress = it.ipAddress,
                userAgent = it.userAgent,
                trusted = it.trusted,
                lastSeenAt = it.lastSeenAt,
                revokedAt = it.revokedAt,
            )
        }

    fun auditHistory(userId: UUID): List<AuditSummary> =
        auditEventRepository.findAllByUserIdOrderByOccurredAtDesc(userId).map {
            AuditSummary(
                id = it.id ?: UUID.randomUUID(),
                userId = it.userId,
                type = it.type.name,
                outcome = it.outcome,
                ipAddress = it.ipAddress,
                userAgent = it.userAgent,
                details = it.details,
                occurredAt = it.occurredAt,
            )
        }

    @Transactional
    fun disableUser(userId: UUID, reason: String?): UserSummary {
        val user = userAccountRepository.findById(userId).orElseThrow { NotFoundException("User not found") }
        user.status = AccountStatus.DISABLED
        userAccountRepository.save(user)
        logoutAll(user.id!!, null, null)
        auditService.record(AuditEventType.USER_DISABLED, user.id, "SUCCESS", details = reason)
        return user.toSummary()
    }

    @Transactional
    fun enableUser(userId: UUID, reason: String?): UserSummary {
        val user = userAccountRepository.findById(userId).orElseThrow { NotFoundException("User not found") }
        user.status = AccountStatus.ACTIVE
        user.lockedUntil = null
        user.failedLoginAttempts = 0
        userAccountRepository.save(user)
        auditService.record(AuditEventType.USER_ENABLED, user.id, "SUCCESS", details = reason)
        return user.toSummary()
    }

    @Transactional
    fun deleteUser(userId: UUID, reason: String?): Boolean {
        val user = userAccountRepository.findById(userId).orElseThrow { NotFoundException("User not found") }
        user.status = AccountStatus.DELETED
        userAccountRepository.save(user)
        logoutAll(user.id!!, null, null)
        auditService.record(AuditEventType.USER_DELETED, user.id, "SUCCESS", details = reason)
        return true
    }

    private fun register(
        email: String?,
        phone: String?,
        username: String,
        password: String,
        provider: AuthProvider,
        ip: String?,
        userAgent: String?,
    ): AuthResponse {
        if (email != null && userAccountRepository.existsByEmailIgnoreCase(email)) throw ConflictException("Email already registered")
        if (phone != null && userAccountRepository.existsByPhone(phone)) throw ConflictException("Phone already registered")
        if (userAccountRepository.existsByUsernameIgnoreCase(username)) throw ConflictException("Username already registered")

        val user = UserAccount(
            email = email,
            phone = phone,
            username = username,
            passwordHash = passwordEncoder.encode(password),
            provider = provider,
            status = AccountStatus.ACTIVE,
        ).apply { ensureId() }
        val saved = userAccountRepository.save(user)
        auditService.record(AuditEventType.REGISTRATION, saved.id, "SUCCESS", ip, userAgent, "provider=${provider.name}")
        return issueSession(saved, defaultFingerprint(userAgent, ip), ip, userAgent).toAuthResponse(saved)
    }

    private fun login(identifier: String, password: String, deviceFingerprint: String?, ip: String?, userAgent: String?): AuthResponse {
        val user = resolveUser(identifier) ?: throw UnauthorizedException("Invalid credentials")
        if (user.status == AccountStatus.DISABLED || user.status == AccountStatus.DELETED) throw ForbiddenException("Account is disabled")
        if (user.lockedUntil?.isAfter(Instant.now(clock)) == true) throw ForbiddenException("Account is locked")

        if (!passwordEncoder.matches(password, user.passwordHash)) {
            onLoginFailure(user, ip, userAgent)
            throw UnauthorizedException("Invalid credentials")
        }

        user.failedLoginAttempts = 0
        user.lockedUntil = null
        user.lastLoginAt = Instant.now(clock)
        user.status = AccountStatus.ACTIVE
        userAccountRepository.save(user)

        if (user.mfaEnabled) {
            val fingerprint = deviceFingerprint ?: defaultFingerprint(userAgent, ip)
            val challenge = otpService.issueOtp(
                destination = user.email ?: user.phone ?: user.username ?: user.id.toString(),
                purpose = "LOGIN",
                userId = user.id,
                challengeId = UUID.randomUUID().toString(),
                ipAddress = ip,
                userAgent = userAgent,
                deviceFingerprint = fingerprint,
            )
            return AuthResponse(
                accessToken = "",
                refreshToken = "",
                expiresAt = Instant.now(clock),
                refreshExpiresAt = Instant.now(clock),
                user = user.toSummary(),
                mfaRequired = true,
                mfaChallengeId = challenge.challengeId,
            )
        }

        return issueSession(user, deviceFingerprint ?: defaultFingerprint(userAgent, ip), ip, userAgent).toAuthResponse(user)
    }

    private fun issueSession(user: UserAccount, deviceFingerprint: String?, ip: String?, userAgent: String?): TokenPairResult {
        val access = tokenService.generateAccessToken(user, deviceFingerprint, ip)
        val refresh = tokenService.generateRefreshToken(user, deviceFingerprint, ip)
        refreshTokenRepository.save(
            RefreshTokenEntity(
                userId = user.id,
                jti = refresh.jti,
                tokenHash = tokenService.hashToken(refresh.token),
                deviceId = deviceFingerprint,
                ipAddress = ip,
                userAgent = userAgent,
                expiresAt = refresh.expiresAt,
                kind = TokenKind.REFRESH,
            ).apply { ensureId() },
        )
        upsertDevice(user.id!!, deviceFingerprint, ip, userAgent)
        return TokenPairResult(access, refresh)
    }

    private fun upsertDevice(userId: UUID, fingerprint: String?, ip: String?, userAgent: String?) {
        if (fingerprint.isNullOrBlank()) return
        val device = deviceRepository.findByUserIdAndFingerprint(userId, fingerprint) ?: DeviceEntity(
            userId = userId,
            fingerprint = fingerprint,
        ).apply { ensureId() }
        device.ipAddress = ip
        device.userAgent = userAgent
        device.lastSeenAt = Instant.now(clock)
        deviceRepository.save(device)
    }

    private fun resolveUser(identifier: String): UserAccount? =
        when {
            identifier.contains("@") -> userAccountRepository.findByEmailIgnoreCase(identifier)
            identifier.any(Char::isDigit) && !identifier.contains("@") -> userAccountRepository.findByPhone(identifier)
            else -> userAccountRepository.findByUsernameIgnoreCase(identifier)
        }

    private fun findUser(email: String?, phone: String?, username: String?): UserAccount? =
        when {
            !email.isNullOrBlank() -> userAccountRepository.findByEmailIgnoreCase(email)
            !phone.isNullOrBlank() -> userAccountRepository.findByPhone(phone)
            !username.isNullOrBlank() -> userAccountRepository.findByUsernameIgnoreCase(username)
            else -> null
        }

    private fun ensureActive(user: UserAccount) {
        if (user.status == AccountStatus.DISABLED || user.status == AccountStatus.DELETED) throw ForbiddenException("Account is disabled")
        if (user.lockedUntil?.isAfter(Instant.now(clock)) == true) throw ForbiddenException("Account is locked")
    }

    private fun onLoginFailure(user: UserAccount, ip: String?, userAgent: String?) {
        user.failedLoginAttempts += 1
        if (user.failedLoginAttempts >= authProperties.security.loginAttemptLimit) {
            user.status = AccountStatus.LOCKED
            user.lockedUntil = Instant.now(clock).plus(authProperties.security.accountLockDuration)
            auditService.record(AuditEventType.ACCOUNT_LOCKED, user.id, "FAILURE", ip, userAgent, "attempt limit reached")
        }
        userAccountRepository.save(user)
        auditService.record(AuditEventType.LOGIN_FAILURE, user.id, "FAILURE", ip, userAgent, "bad credentials")
    }

    private fun findOrCreateOAuthUser(provider: AuthProvider, identifier: String, email: String?, username: String?): UserAccount {
        val existing = when (provider) {
            AuthProvider.GOOGLE -> email?.let { userAccountRepository.findByEmailIgnoreCase(it) }
            AuthProvider.GITHUB -> username?.let { userAccountRepository.findByUsernameIgnoreCase(it) } ?: email?.let { userAccountRepository.findByEmailIgnoreCase(it) }
            else -> null
        }
        if (existing != null) return existing
        val resolvedUsername = username ?: email?.substringBefore("@") ?: identifier
        return userAccountRepository.save(
            UserAccount(
                email = email,
                username = resolvedUsername,
                provider = provider,
                status = AccountStatus.ACTIVE,
                emailVerified = email != null,
            ).apply { ensureId() }
        )
    }

    private fun oauthFingerprint(identifier: String, userAgent: String?): String? = "${identifier}:${userAgent ?: ""}".takeIf { it.isNotBlank() }
    private fun defaultFingerprint(userAgent: String?, ip: String?): String? = listOfNotNull(userAgent, ip).joinToString(":").takeIf { it.isNotBlank() }
}

data class TokenPairResult(
    val access: TokenPairEnvelope,
    val refresh: TokenPairEnvelope,
) {
    fun toAuthResponse(user: UserAccount): AuthResponse = AuthResponse(
        accessToken = access.token,
        refreshToken = refresh.token,
        expiresAt = access.expiresAt,
        refreshExpiresAt = refresh.expiresAt,
        user = user.toSummary(),
    )
}

private fun UserAccount.toSummary(): UserSummary = UserSummary(
    id = id ?: UUID.randomUUID(),
    email = email,
    phone = phone,
    username = username,
    roles = roles.toSet(),
    status = status.name,
    provider = provider.name,
    emailVerified = emailVerified,
    phoneVerified = phoneVerified,
    mfaEnabled = mfaEnabled,
)
