package com.codeforge.authentication_service.controller

import com.codeforge.authentication_service.dto.AdminUpdateRequest
import com.codeforge.authentication_service.dto.UserSummary
import com.codeforge.authentication_service.security.AuthenticatedPrincipal
import com.codeforge.authentication_service.service.AuthService
import jakarta.validation.Valid
import org.springframework.security.access.prepost.PreAuthorize
import org.springframework.security.core.annotation.AuthenticationPrincipal
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController
import java.util.UUID

@RestController
@RequestMapping("/admin/users")
@PreAuthorize("hasRole('ADMIN')")
class AdminController(
    private val authService: AuthService,
) {
    @PostMapping("/{userId}/disable")
    fun disable(@PathVariable userId: UUID, @Valid @RequestBody(required = false) request: AdminUpdateRequest?): UserSummary =
        authService.disableUser(userId, request?.reason)

    @PostMapping("/{userId}/enable")
    fun enable(@PathVariable userId: UUID, @Valid @RequestBody(required = false) request: AdminUpdateRequest?): UserSummary =
        authService.enableUser(userId, request?.reason)

    @PostMapping("/{userId}/delete")
    fun delete(@PathVariable userId: UUID, @Valid @RequestBody(required = false) request: AdminUpdateRequest?): Map<String, Boolean> =
        mapOf("success" to authService.deleteUser(userId, request?.reason))
}
