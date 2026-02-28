package com.example

import io.ktor.client.request.*
import io.ktor.client.statement.bodyAsText
import io.ktor.http.*
import io.ktor.server.testing.*
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class ApplicationTest {

    private val json = Json { ignoreUnknownKeys = true }

    private fun parseToken(body: String): String {
        return json.parseToJsonElement(body)
            .jsonObject["token"]
            ?.jsonPrimitive
            ?.content
            ?: error("Token no encontrado en la respuesta")
    }

    private fun parseValido(body: String): Boolean {
        return json.parseToJsonElement(body)
            .jsonObject["valido"]
            ?.jsonPrimitive
            ?.boolean
            ?: false
    }

    @Test
    fun testRoot() = testApplication {
        application {
            module()
        }
        client.get("/").apply {
            assertEquals(HttpStatusCode.OK, status)
        }
    }

    @Test
    fun testV1RoutesNotExposedInV2Service() = testApplication {
        application {
            module()
        }

        client.get("/api/v1/usuarios").apply {
            assertEquals(HttpStatusCode.NotFound, status)
        }
    }

    @Test
    fun testProtectedEndpointWithoutTokenReturnsUnauthorized() = testApplication {
        application {
            module()
        }

        client.get("/api/v2/usuarios").apply {
            assertEquals(HttpStatusCode.Unauthorized, status)
        }
    }

    @Test
    fun testAuthValidateWithoutTokenReturnsUnauthorized() = testApplication {
        application {
            module()
        }

        client.get("/api/v2/auth/validate").apply {
            assertEquals(HttpStatusCode.Unauthorized, status)
            assertFalse(parseValido(bodyAsText()))
        }
    }

    @Test
    fun testRegisterLoginAndAccessProtectedEndpointWithBearerToken() = testApplication {
        application {
            module()
        }

        val uniqueValue = System.nanoTime()
        val username = "tester_$uniqueValue"
        val email = "$username@example.com"

        val registerResponse = client.post("/api/v2/auth/register") {
            contentType(ContentType.Application.Json)
            setBody(
                """
                {
                  "nombreUsuario": "$username",
                  "contrasena": "1234",
                  "email": "$email"
                }
                """.trimIndent(),
            )
        }

        assertEquals(HttpStatusCode.Created, registerResponse.status)

        val token = parseToken(registerResponse.bodyAsText())
        assertNotNull(token)

        client.get("/api/v2/auth/validate") {
            header(HttpHeaders.Authorization, "Bearer $token")
        }.apply {
            assertEquals(HttpStatusCode.OK, status)
            assertTrue(parseValido(bodyAsText()))
        }

        val loginResponse = client.post("/api/v2/auth/login") {
            contentType(ContentType.Application.Json)
            setBody(
                """
                {
                  "nombreUsuario": "$username",
                  "contrasena": "1234"
                }
                """.trimIndent(),
            )
        }
        assertEquals(HttpStatusCode.OK, loginResponse.status)

        val loginToken = parseToken(loginResponse.bodyAsText())
        assertEquals(token, loginToken)

        client.get("/api/v2/usuarios") {
            header(HttpHeaders.Authorization, "Bearer $token")
        }.apply {
            assertEquals(HttpStatusCode.OK, status)
        }
    }

    @Test
    fun testProtectedEndpointWithInvalidTokenReturnsUnauthorized() = testApplication {
        application {
            module()
        }

        client.get("/api/v2/usuarios") {
            header(HttpHeaders.Authorization, "Bearer token-invalido")
        }.apply {
            assertEquals(HttpStatusCode.Unauthorized, status)
        }
    }

    @Test
    fun testProtectedEndpointWithXAuthTokenHeader() = testApplication {
        application {
            module()
        }

        val uniqueValue = System.nanoTime()
        val username = "tester_xauth_$uniqueValue"
        val email = "$username@example.com"

        val registerResponse = client.post("/api/v2/auth/register") {
            contentType(ContentType.Application.Json)
            setBody(
                """
                {
                  "nombreUsuario": "$username",
                  "contrasena": "1234",
                  "email": "$email"
                }
                """.trimIndent(),
            )
        }

        assertEquals(HttpStatusCode.Created, registerResponse.status)
        val token = parseToken(registerResponse.bodyAsText())

        client.get("/api/v2/usuarios") {
            header("X-Auth-Token", token)
        }.apply {
            assertEquals(HttpStatusCode.OK, status)
        }
    }

    @Test
    fun testLogoutInvalidatesToken() = testApplication {
        application {
            module()
        }

        val uniqueValue = System.nanoTime()
        val username = "tester_logout_$uniqueValue"
        val email = "$username@example.com"

        val registerResponse = client.post("/api/v2/auth/register") {
            contentType(ContentType.Application.Json)
            setBody(
                """
                {
                  "nombreUsuario": "$username",
                  "contrasena": "1234",
                  "email": "$email"
                }
                """.trimIndent(),
            )
        }

        assertEquals(HttpStatusCode.Created, registerResponse.status)
        val token = parseToken(registerResponse.bodyAsText())

        client.post("/api/v2/auth/logout") {
            header(HttpHeaders.Authorization, "Bearer $token")
        }.apply {
            assertEquals(HttpStatusCode.OK, status)
        }

        client.get("/api/v2/usuarios") {
            header(HttpHeaders.Authorization, "Bearer $token")
        }.apply {
            assertEquals(HttpStatusCode.Unauthorized, status)
        }
    }

    @Test
    fun testLoginWithInvalidCredentialsReturnsUnauthorized() = testApplication {
        application {
            module()
        }

        client.post("/api/v2/auth/login") {
            contentType(ContentType.Application.Json)
            setBody(
                """
                {
                  "nombreUsuario": "usuario-inexistente",
                  "contrasena": "no-valida"
                }
                """.trimIndent(),
            )
        }.apply {
            assertEquals(HttpStatusCode.Unauthorized, status)
        }
    }

}
