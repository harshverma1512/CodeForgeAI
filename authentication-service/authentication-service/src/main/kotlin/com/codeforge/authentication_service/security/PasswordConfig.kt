package com.codeforge.authentication_service.security

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.crypto.password.DelegatingPasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder

@Configuration
class PasswordConfig {
    @Bean
    fun passwordEncoder(): PasswordEncoder {
        val encoders = mutableMapOf<String, PasswordEncoder>(
            "bcrypt" to BCryptPasswordEncoder(),
            "argon2" to Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8(),
        )
        return DelegatingPasswordEncoder("bcrypt", encoders)
    }
}
