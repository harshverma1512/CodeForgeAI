package com.codeforge.authentication_service.domain

enum class TokenKind {
    ACCESS,
    REFRESH,
    RESET_PASSWORD,
    EMAIL_OTP,
    MOBILE_OTP
}
