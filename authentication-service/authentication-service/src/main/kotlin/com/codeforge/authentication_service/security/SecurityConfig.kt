package com.codeforge.authentication_service.security

import com.codeforge.authentication_service.service.AuthService
import com.fasterxml.jackson.databind.ObjectMapper
import org.springframework.beans.factory.ObjectProvider
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.http.MediaType
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.web.AuthenticationEntryPoint
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter

@Configuration
@EnableMethodSecurity
class SecurityConfig(
    private val jwtAuthenticationFilter: JwtAuthenticationFilter,
    private val oauth2SuccessHandler: OAuth2SuccessHandler,
    private val objectMapper: ObjectMapper,
    private val clientRegistrationRepository: ObjectProvider<ClientRegistrationRepository>,
) {
    @Bean
    fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
        http
            .csrf { it.disable() }
            .sessionManagement { it.sessionCreationPolicy(SessionCreationPolicy.STATELESS) }
            .authorizeHttpRequests {
                it.requestMatchers(
                    "/actuator/health",
                    "/auth/register/**",
                    "/auth/login/**",
                    "/auth/otp/**",
                    "/auth/forgot-password",
                    "/auth/reset-password",
                    "/oauth2/**",
                    "/login/oauth2/**",
                    "/error",
                ).permitAll()
                it.anyRequest().authenticated()
            }
            .exceptionHandling { it.authenticationEntryPoint(authenticationEntryPoint()) }
            .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter::class.java)
        clientRegistrationRepository.ifAvailable?.let {
            http.oauth2Login { oauth2 ->
                oauth2.successHandler(oauth2SuccessHandler)
            }
        }
        return http.build()
    }

    @Bean
    fun authenticationEntryPoint(): AuthenticationEntryPoint = AuthenticationEntryPoint { request, response, authException ->
        response.status = 401
        response.contentType = MediaType.APPLICATION_JSON_VALUE
        objectMapper.writeValue(
            response.writer,
            mapOf(
                "error" to "Unauthorized",
                "message" to (authException.message ?: "Authentication required"),
                "path" to request.requestURI,
            ),
        )
    }
}
