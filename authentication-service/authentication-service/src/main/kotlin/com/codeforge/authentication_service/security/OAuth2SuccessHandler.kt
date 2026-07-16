package com.codeforge.authentication_service.security

import com.codeforge.authentication_service.domain.AuthProvider
import com.codeforge.authentication_service.service.AuthService
import com.fasterxml.jackson.databind.ObjectMapper
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken
import org.springframework.security.oauth2.core.user.OAuth2User
import org.springframework.security.web.authentication.AuthenticationSuccessHandler
import org.springframework.stereotype.Component

@Component
class OAuth2SuccessHandler(
    private val authService: AuthService,
    private val objectMapper: ObjectMapper,
) : AuthenticationSuccessHandler {
    override fun onAuthenticationSuccess(
        request: HttpServletRequest,
        response: HttpServletResponse,
        authentication: Authentication,
    ) {
        val oauthToken = authentication as OAuth2AuthenticationToken
        val principal = authentication.principal as OAuth2User
        val provider = when (oauthToken.authorizedClientRegistrationId.lowercase()) {
            "google" -> AuthProvider.GOOGLE
            "github" -> AuthProvider.GITHUB
            else -> AuthProvider.LOCAL
        }
        val email = principal.getAttribute<String>("email")
        val username = principal.getAttribute<String>("login") ?: principal.getAttribute<String>("name") ?: email?.substringBefore("@")
        val identifier = principal.getAttribute<String>("sub")
            ?: principal.getAttribute<String>("id")
            ?: email
            ?: username
            ?: principal.name
        val authResponse = authService.handleOAuth2Login(
            provider = provider,
            identifier = identifier,
            email = email,
            username = username,
            ip = request.remoteAddr,
            userAgent = request.getHeader("User-Agent"),
        )
        response.contentType = "application/json"
        objectMapper.writeValue(response.writer, authResponse)
    }
}
