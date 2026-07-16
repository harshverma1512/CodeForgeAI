package com.codeforge.authentication_service.exception

open class ApiException(
    override val message: String,
    val status: Int,
) : RuntimeException(message)

class ConflictException(message: String) : ApiException(message, 409)
class NotFoundException(message: String) : ApiException(message, 404)
class UnauthorizedException(message: String) : ApiException(message, 401)
class ForbiddenException(message: String) : ApiException(message, 403)
class BadRequestException(message: String) : ApiException(message, 400)
