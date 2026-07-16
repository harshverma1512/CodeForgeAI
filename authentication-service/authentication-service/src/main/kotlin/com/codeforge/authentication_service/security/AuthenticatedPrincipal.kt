package com.codeforge.authentication_service.security

import java.util.UUID

data class AuthenticatedPrincipal(
    val userId: UUID,
    val username: String,
    val roles: Set<String>,
)
