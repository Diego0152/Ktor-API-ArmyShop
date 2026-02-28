package com.example

import io.ktor.client.request.*
import io.ktor.client.statement.bodyAsText
import io.ktor.http.*
import io.ktor.server.testing.*
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull

class ApplicationTest {

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
    fun testProtectedEndpointWithoutToken() = testApplication {
        application {
            module()
        }

        client.get("/api/v2/usuarios").apply {
            assertEquals(HttpStatusCode.Unauthorized, status)
        }
    }

    @Test
    fun testRegisterAndAccessProtectedEndpoint() = testApplication {
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

        val token = "\\\"token\\\":\\\"([^\\\"]+)\\\"".toRegex()
            .find(registerResponse.bodyAsText())
            ?.groupValues
            ?.getOrNull(1)
        assertNotNull(token)

        client.get("/api/v2/usuarios") {
            header(HttpHeaders.Authorization, "Bearer $token")
        }.apply {
            assertEquals(HttpStatusCode.OK, status)
        }
    }

}
