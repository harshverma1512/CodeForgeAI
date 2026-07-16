package com.codeforge.authentication_service.controller

import com.codeforge.authentication_service.dto.*
import com.codeforge.authentication_service.security.AuthenticatedPrincipal
import com.codeforge.authentication_service.service.AuthService
import jakarta.servlet.http.HttpServletRequest
import jakarta.validation.Valid
import org.springframework.security.core.annotation.AuthenticationPrincipal
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/auth")
class AuthController(
    private val authService: AuthService,
) {
    @PostMapping("/register/email")
    fun registerEmail(@Valid @RequestBody request: EmailRegistrationRequest, http: HttpServletRequest): AuthResponse =
        authService.registerEmail(request, http.remoteAddr, http.getHeader("User-Agent"))

    @PostMapping("/register/phone")
    fun registerPhone(@Valid @RequestBody request: PhoneRegistrationRequest, http: HttpServletRequest): AuthResponse =
        authService.registerPhone(request, http.remoteAddr, http.getHeader("User-Agent"))

    @PostMapping("/register/username")
    fun registerUsername(@Valid @RequestBody request: UsernameRegistrationRequest, http: HttpServletRequest): AuthResponse =
        authService.registerUsername(request, http.remoteAddr, http.getHeader("User-Agent"))

    @PostMapping("/login/email")
    fun loginEmail(@Valid @RequestBody request: EmailLoginRequest, http: HttpServletRequest): AuthResponse =
        authService.loginEmail(request, http.remoteAddr, http.getHeader("User-Agent"))

    @PostMapping("/login/phone")
    fun loginPhone(@Valid @RequestBody request: PhoneLoginRequest, http: HttpServletRequest): AuthResponse =
        authService.loginPhone(request, http.remoteAddr, http.getHeader("User-Agent"))

    @PostMapping("/login/username")
    fun loginUsername(@Valid @RequestBody request: UsernameLoginRequest, http: HttpServletRequest): AuthResponse =
        authService.loginUsername(request, http.remoteAddr, http.getHeader("User-Agent"))

    @PostMapping("/refresh")
    fun refresh(@Valid @RequestBody request: RefreshTokenRequest, http: HttpServletRequest): AuthResponse =
        authService.refresh(request, http.remoteAddr, http.getHeader("User-Agent"))

    @PostMapping("/logout")
    fun logout(@Valid @RequestBody request: LogoutRequest, http: HttpServletRequest): Map<String, Boolean> =
        mapOf("success" to authService.logout(request.refreshToken, http.remoteAddr, http.getHeader("User-Agent")))

    @PostMapping("/logout-all")
    fun logoutAll(@AuthenticationPrincipal principal: AuthenticatedPrincipal?, http: HttpServletRequest): Map<String, Boolean> =
        mapOf("success" to authService.logoutAll(principal?.userId ?: throw IllegalStateException("Missing principal"), http.remoteAddr, http.getHeader("User-Agent")))

    @PostMapping("/forgot-password")
    fun forgotPassword(@Valid @RequestBody request: ForgotPasswordRequest, http: HttpServletRequest): Map<String, String> =
        mapOf("token" to authService.forgotPassword(request, http.remoteAddr, http.getHeader("User-Agent")))

    @PostMapping("/reset-password")
    fun resetPassword(@Valid @RequestBody request: ResetPasswordRequest, http: HttpServletRequest): Map<String, Boolean> =
        mapOf("success" to authService.resetPassword(request, http.remoteAddr, http.getHeader("User-Agent")))

    @PostMapping("/change-password")
    fun changePassword(
        @AuthenticationPrincipal principal: AuthenticatedPrincipal,
        @Valid @RequestBody request: ChangePasswordRequest,
        http: HttpServletRequest,
    ): Map<String, Boolean> =
        mapOf("success" to authService.changePassword(principal.userId, request, http.remoteAddr, http.getHeader("User-Agent")))

    @PostMapping("/otp/request")
    fun requestOtp(@Valid @RequestBody request: OtpRequest, http: HttpServletRequest): OtpResponse =
        authService.requestOtp(request, http.remoteAddr, http.getHeader("User-Agent"))

    @PostMapping("/otp/verify")
    fun verifyOtp(@Valid @RequestBody request: VerifyOtpRequest, http: HttpServletRequest): AuthResponse =
        authService.verifyOtp(request, http.remoteAddr, http.getHeader("User-Agent"))

    @GetMapping("/me")
    fun me(@AuthenticationPrincipal principal: AuthenticatedPrincipal): UserSummary =
        authService.me(principal)

    @GetMapping("/sessions")
    fun sessions(@AuthenticationPrincipal principal: AuthenticatedPrincipal): List<SessionSummary> =
        authService.sessions(principal.userId)

    @GetMapping("/devices")
    fun devices(@AuthenticationPrincipal principal: AuthenticatedPrincipal): List<DeviceSummary> =
        authService.devices(principal.userId)

    @GetMapping("/audit")
    fun audit(@AuthenticationPrincipal principal: AuthenticatedPrincipal): List<AuditSummary> =
        authService.auditHistory(principal.userId)
}
