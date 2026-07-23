package com.codeforge.authentication_service.security

import com.codeforge.authentication_service.service.TokenBlacklistService
import jakarta.servlet.FilterChain
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.stereotype.Component
import org.springframework.web.filter.OncePerRequestFilter

@Component
class JwtAuthenticationFilter(
    private val tokenService: TokenService,
    private val tokenBlacklistService: TokenBlacklistService,
) : OncePerRequestFilter() {
    override fun doFilterInternal(
        request: HttpServletRequest,
        response: HttpServletResponse,
        filterChain: FilterChain,
    ) {

        val authorization = request.getHeader("Authorization")
        println("Authorization Header: $authorization")
        if (authorization?.startsWith("Bearer", ignoreCase = true) == true) {
            val token = authorization.removePrefix("Bearer ").trim()
            try {
                val claims = tokenService.parseAndValidate(token)
                if (claims.kind == "ACCESS" && !tokenBlacklistService.isBlacklisted(claims.tokenId)) {
                    val authorities = claims.roles.map { SimpleGrantedAuthority("ROLE_${it.uppercase()}") }
                    val principal = AuthenticatedPrincipal(
                        userId = claims.subject,
                        username = claims.username,
                        roles = claims.roles,
                    )
                    val authentication = UsernamePasswordAuthenticationToken(principal, null, authorities)
                    SecurityContextHolder.getContext().authentication = authentication
                }
            } catch (ex: Exception) {
                print("Invalid token: ${ex.message}")
                SecurityContextHolder.clearContext()
            }
        }
        filterChain.doFilter(request, response)
    }
}
