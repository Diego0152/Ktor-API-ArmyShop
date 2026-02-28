package com.example

import com.auth0.jwt.JWT
import com.auth0.jwt.JWTVerifier
import com.auth0.jwt.algorithms.Algorithm
import com.auth0.jwt.interfaces.DecodedJWT
import io.ktor.http.auth.HttpAuthHeader
import io.ktor.server.application.Application
import io.ktor.server.application.install
import io.ktor.server.auth.Authentication
import io.ktor.server.auth.jwt.JWTAuthenticationProvider
import io.ktor.server.auth.jwt.JWTPrincipal
import io.ktor.server.auth.jwt.jwt
import io.ktor.server.request.header

object JwtConfig {
    private const val defaultSecret = "super_secret_key"
    private const val defaultIssuer = "domain.com"
    private const val defaultAudience = "ktor_audience"
    private const val defaultRealm = "ktor_realm"

    private fun secret(application: Application): String {
        return application.environment.config.propertyOrNull("jwt.secret")?.getString()?.takeIf { it.isNotBlank() }
            ?: defaultSecret
    }

    private fun issuer(application: Application): String {
        return application.environment.config.propertyOrNull("jwt.issuer")?.getString()?.takeIf { it.isNotBlank() }
            ?: defaultIssuer
    }

    private fun audience(application: Application): String {
        return application.environment.config.propertyOrNull("jwt.audience")?.getString()?.takeIf { it.isNotBlank() }
            ?: defaultAudience
    }

    private fun realm(application: Application): String {
        return application.environment.config.propertyOrNull("jwt.realm")?.getString()?.takeIf { it.isNotBlank() }
            ?: defaultRealm
    }

    private fun algorithm(application: Application): Algorithm = Algorithm.HMAC256(secret(application))

    fun verifier(application: Application): JWTVerifier {
        return JWT.require(algorithm(application))
            .withIssuer(issuer(application))
            .withAudience(audience(application))
            .build()
    }

    fun generateToken(application: Application, idUsuario: Int, nombreUsuario: String, tokenId: String): String {
        return JWT.create()
            .withIssuer(issuer(application))
            .withAudience(audience(application))
            .withSubject("Authentication")
            .withClaim("idUsuario", idUsuario)
            .withClaim("nombreUsuario", nombreUsuario)
            .withClaim("tokenId", tokenId)
            .sign(algorithm(application))
    }

    fun verifyToken(application: Application, token: String): DecodedJWT? {
        return runCatching {
            verifier(application).verify(token)
        }.getOrNull()
    }

    fun extractTokenFromHeaders(headerValue: HttpAuthHeader?): String? {
        val bearerToken = (headerValue as? HttpAuthHeader.Single)
            ?.takeIf { it.authScheme.equals("Bearer", ignoreCase = true) }
            ?.blob
            ?.trim()

        return bearerToken?.takeIf { it.isNotEmpty() }
    }

    fun configureAuthentication(
        application: Application,
        config: JWTAuthenticationProvider.Config,
        tokenValidator: (Int, String) -> Boolean,
    ) {
        config.realm = realm(application)
        config.authHeader { call ->
            val authorization = call.request.header("Authorization")
            val bearerToken = authorization
                ?.takeIf { it.startsWith("Bearer ", ignoreCase = true) }
                ?.substringAfter("Bearer ")
                ?.trim()
                ?.takeIf { it.isNotEmpty() }

            bearerToken
                ?.let { HttpAuthHeader.Single("Bearer", it) }
                ?: call.request.header("X-Auth-Token")
                    ?.trim()
                    ?.takeIf { it.isNotEmpty() }
                    ?.let { HttpAuthHeader.Single("Bearer", it) }
        }
        config.verifier(verifier(application))
        config.validate { credential ->
            val userId = credential.payload.getClaim("idUsuario").asInt()
            val tokenId = credential.payload.getClaim("tokenId").asString()

            if (userId == null || tokenId.isNullOrBlank()) return@validate null
            if (!tokenValidator(userId, tokenId)) return@validate null

            JWTPrincipal(credential.payload)
        }
    }
}

fun Application.configureSecurity(tokenValidator: (Int, String) -> Boolean) {
    install(Authentication) {
        jwt("auth-jwt") {
            JwtConfig.configureAuthentication(this@configureSecurity, this, tokenValidator)
        }
    }
}
