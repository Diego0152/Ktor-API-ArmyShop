package com.example

import com.zaxxer.hikari.HikariConfig
import com.zaxxer.hikari.HikariDataSource
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.Application
import io.ktor.server.application.ApplicationCall
import io.ktor.server.application.call
import io.ktor.server.request.receive
import io.ktor.server.response.respond
import io.ktor.server.routing.Route
import io.ktor.server.routing.delete
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.routing.put
import io.ktor.server.routing.route
import kotlinx.serialization.Serializable
import org.jetbrains.exposed.sql.Database
import org.jetbrains.exposed.sql.ResultRow
import org.jetbrains.exposed.sql.SchemaUtils
import org.jetbrains.exposed.sql.and
import org.jetbrains.exposed.sql.SqlExpressionBuilder.eq
import org.jetbrains.exposed.sql.Table
import org.jetbrains.exposed.sql.deleteWhere
import org.jetbrains.exposed.sql.insert
import org.jetbrains.exposed.sql.or
import org.jetbrains.exposed.sql.selectAll
import org.jetbrains.exposed.sql.transactions.transaction
import org.jetbrains.exposed.sql.update
import io.ktor.server.request.header
import io.ktor.util.AttributeKey
import io.ktor.server.application.createRouteScopedPlugin
import java.util.UUID

fun Application.configureDatabases() {
    val config = environment.config

    val jdbcUrl = config.propertyOrNull("database.jdbcUrl")?.getString()
        ?: "jdbc:h2:mem:ktor;DB_CLOSE_DELAY=-1"
    val driverClassName = config.propertyOrNull("database.driverClassName")?.getString()
        ?: if (jdbcUrl.startsWith("jdbc:mariadb:")) "org.mariadb.jdbc.Driver" else "org.h2.Driver"
    val username = config.propertyOrNull("database.username")?.getString() ?: "sa"
    val password = config.propertyOrNull("database.password")?.getString() ?: ""

    val hikariConfig = HikariConfig().apply {
        this.jdbcUrl = jdbcUrl
        this.driverClassName = driverClassName
        this.username = username
        this.password = password
        maximumPoolSize = 5
    }

    Database.connect(HikariDataSource(hikariConfig))

    transaction {
        SchemaUtils.create(Usuarios, Armas, Anuncios)
    }
}

object Usuarios : Table("usuarios") {
    val idUsuario = integer("idUsuario").autoIncrement()
    val nombreUsuario = varchar("nombre_usuario", 120)
    val contrasena = varchar("contrasena", 255)
    val imagen = varchar("imagen", 500).nullable()
    val email = varchar("email", 200)
    val rol = varchar("rol", 50)
    val activo = bool("activo").default(true)
    val token = varchar("token", 500).nullable()

    override val primaryKey = PrimaryKey(idUsuario)
}

object Armas : Table("armas") {
    val idArma = integer("idarma").autoIncrement()
    val nombre = varchar("nombre", 120)
    val categoria = varchar("categoria", 100)
    val coste = double("coste")
    val imagen = varchar("imagen", 500).nullable()
    val informacionExtra = text("informacion_extra").nullable()
    val calibre = varchar("calibre", 100).nullable()
    val stock = integer("stock").default(0)
    val userId = integer("userid").references(Usuarios.idUsuario).nullable()

    override val primaryKey = PrimaryKey(idArma)
}

object Anuncios : Table("anuncios") {
    val idAnuncio = integer("idAnuncio").autoIncrement()
    val url = varchar("url", 500)
    val imagen = varchar("imagen", 500).nullable()

    override val primaryKey = PrimaryKey(idAnuncio)
}

@Serializable
data class UsuarioCreateRequest(
    val nombreUsuario: String,
    val contrasena: String,
    val imagen: String? = null,
    val email: String,
    val rol: String,
    val activo: Boolean = true,
    val token: String? = null,
)

@Serializable
data class UsuarioUpdateRequest(
    val nombreUsuario: String,
    val contrasena: String,
    val imagen: String? = null,
    val email: String,
    val rol: String,
    val activo: Boolean,
    val token: String? = null,
)

@Serializable
data class UsuarioResponse(
    val idUsuario: Int,
    val nombreUsuario: String,
    val contrasena: String,
    val imagen: String?,
    val email: String,
    val rol: String,
    val activo: Boolean,
    val token: String?,
)

@Serializable
data class UsuarioPublicResponse(
    val idUsuario: Int,
    val nombreUsuario: String,
    val imagen: String?,
    val email: String,
    val rol: String,
    val activo: Boolean,
)

@Serializable
data class LoginRequest(
    val nombreUsuario: String,
    val contrasena: String,
)

@Serializable
data class RegisterRequest(
    val nombreUsuario: String,
    val contrasena: String,
    val imagen: String? = null,
    val email: String,
    val rol: String = "cliente",
)

@Serializable
data class AuthResponse(
    val token: String,
    val usuario: UsuarioPublicResponse,
)

@Serializable
data class TokenValidationResponse(
    val valido: Boolean,
    val usuario: UsuarioPublicResponse? = null,
)

@Serializable
data class ArmaCreateRequest(
    val nombre: String,
    val categoria: String,
    val coste: Double,
    val imagen: String? = null,
    val informacionExtra: String? = null,
    val calibre: String? = null,
    val stock: Int = 0,
    val userId: Int? = null,
)

@Serializable
data class ArmaUpdateRequest(
    val nombre: String,
    val categoria: String,
    val coste: Double,
    val imagen: String? = null,
    val informacionExtra: String? = null,
    val calibre: String? = null,
    val stock: Int,
    val userId: Int? = null,
)

@Serializable
data class ArmaResponse(
    val idArma: Int,
    val nombre: String,
    val categoria: String,
    val coste: Double,
    val imagen: String?,
    val informacionExtra: String?,
    val calibre: String?,
    val stock: Int,
    val userId: Int?,
)

@Serializable
data class AnuncioCreateRequest(
    val url: String,
    val imagen: String? = null,
)

@Serializable
data class AnuncioUpdateRequest(
    val url: String,
    val imagen: String? = null,
)

@Serializable
data class AnuncioResponse(
    val idAnuncio: Int,
    val url: String,
    val imagen: String?,
)

private fun ResultRow.toUsuarioResponse(): UsuarioResponse = UsuarioResponse(
    idUsuario = this[Usuarios.idUsuario],
    nombreUsuario = this[Usuarios.nombreUsuario],
    contrasena = this[Usuarios.contrasena],
    imagen = this[Usuarios.imagen],
    email = this[Usuarios.email],
    rol = this[Usuarios.rol],
    activo = this[Usuarios.activo],
    token = this[Usuarios.token],
)

private fun ResultRow.toArmaResponse(): ArmaResponse = ArmaResponse(
    idArma = this[Armas.idArma],
    nombre = this[Armas.nombre],
    categoria = this[Armas.categoria],
    coste = this[Armas.coste],
    imagen = this[Armas.imagen],
    informacionExtra = this[Armas.informacionExtra],
    calibre = this[Armas.calibre],
    stock = this[Armas.stock],
    userId = this[Armas.userId],
)

private fun ResultRow.toAnuncioResponse(): AnuncioResponse = AnuncioResponse(
    idAnuncio = this[Anuncios.idAnuncio],
    url = this[Anuncios.url],
    imagen = this[Anuncios.imagen],
)

private fun UsuarioResponse.toPublicResponse(): UsuarioPublicResponse = UsuarioPublicResponse(
    idUsuario = idUsuario,
    nombreUsuario = nombreUsuario,
    imagen = imagen,
    email = email,
    rol = rol,
    activo = activo,
)

private object UsuarioRepository {
    fun getAll(): List<UsuarioResponse> = transaction {
        Usuarios.selectAll().map { it.toUsuarioResponse() }
    }

    fun getById(id: Int): UsuarioResponse? = transaction {
        Usuarios.selectAll().where { Usuarios.idUsuario eq id }.singleOrNull()?.toUsuarioResponse()
    }

    fun create(payload: UsuarioCreateRequest): UsuarioResponse = transaction {
        val id = Usuarios.insert {
            it[nombreUsuario] = payload.nombreUsuario
            it[contrasena] = payload.contrasena
            it[imagen] = payload.imagen
            it[email] = payload.email
            it[rol] = payload.rol
            it[activo] = payload.activo
            it[token] = payload.token
        }[Usuarios.idUsuario]

        Usuarios.selectAll().where { Usuarios.idUsuario eq id }.single().toUsuarioResponse()
    }

    fun register(payload: RegisterRequest): UsuarioResponse = transaction {
        val exists = Usuarios.selectAll().where {
            (Usuarios.nombreUsuario eq payload.nombreUsuario) or (Usuarios.email eq payload.email)
        }.singleOrNull() != null

        if (exists) {
            throw IllegalArgumentException("El nombre de usuario o email ya existe")
        }

        val generatedToken = UUID.randomUUID().toString()

        val id = Usuarios.insert {
            it[nombreUsuario] = payload.nombreUsuario
            it[contrasena] = payload.contrasena
            it[imagen] = payload.imagen
            it[email] = payload.email
            it[rol] = payload.rol
            it[activo] = true
            it[token] = generatedToken
        }[Usuarios.idUsuario]

        Usuarios.selectAll().where { Usuarios.idUsuario eq id }.single().toUsuarioResponse()
    }

    fun login(nombre: String, password: String): UsuarioResponse? = transaction {
        val usuario = Usuarios.selectAll().where {
            (Usuarios.nombreUsuario eq nombre) and
                (Usuarios.contrasena eq password) and
                (Usuarios.activo eq true)
        }.singleOrNull()?.toUsuarioResponse() ?: return@transaction null

        if (!usuario.token.isNullOrBlank()) return@transaction usuario

        val generatedToken = UUID.randomUUID().toString()
        Usuarios.update({ Usuarios.idUsuario eq usuario.idUsuario }) {
            it[token] = generatedToken
        }

        usuario.copy(token = generatedToken)
    }

    fun getByToken(token: String): UsuarioResponse? = transaction {
        Usuarios.selectAll().where { Usuarios.token eq token }.singleOrNull()?.toUsuarioResponse()
    }

    fun clearToken(id: Int): Boolean = transaction {
        Usuarios.update({ Usuarios.idUsuario eq id }) {
            it[token] = null
        } > 0
    }

    fun update(id: Int, payload: UsuarioUpdateRequest): Boolean = transaction {
        Usuarios.update({ Usuarios.idUsuario eq id }) {
            it[nombreUsuario] = payload.nombreUsuario
            it[contrasena] = payload.contrasena
            it[imagen] = payload.imagen
            it[email] = payload.email
            it[rol] = payload.rol
            it[activo] = payload.activo
            it[token] = payload.token
        } > 0
    }

    fun delete(id: Int): Boolean = transaction {
        Usuarios.deleteWhere { Usuarios.idUsuario eq id } > 0
    }
}

private val AuthenticatedUserIdKey = AttributeKey<Int>("authenticatedUserId")

private fun ApplicationCall.extractTokenFromHeaders(): String? {
    val authorization = request.header("Authorization")
    val bearerToken = authorization
        ?.takeIf { it.startsWith("Bearer ", ignoreCase = true) }
        ?.substringAfter("Bearer ")
        ?.trim()
    val rawToken = request.header("X-Auth-Token")?.trim()

    return bearerToken?.takeIf { it.isNotEmpty() } ?: rawToken?.takeIf { it.isNotEmpty() }
}

private suspend fun ApplicationCall.requireAuthenticatedUserOrRespond(): UsuarioResponse? {
    val token = extractTokenFromHeaders()
    if (token == null) {
        respond(HttpStatusCode.Unauthorized, "Token requerido")
        return null
    }

    val usuario = UsuarioRepository.getByToken(token)
    if (usuario == null || !usuario.activo) {
        respond(HttpStatusCode.Unauthorized, "Token inválido")
        return null
    }

    attributes.put(AuthenticatedUserIdKey, usuario.idUsuario)
    return usuario
}

private val TokenAuthPlugin = createRouteScopedPlugin(name = "TokenAuthPlugin") {
    onCall { call ->
        call.requireAuthenticatedUserOrRespond() ?: return@onCall
    }
}

private object ArmaRepository {
    private fun userExists(userId: Int): Boolean {
        return Usuarios.selectAll().where { Usuarios.idUsuario eq userId }.singleOrNull() != null
    }

    fun getAll(): List<ArmaResponse> = transaction {
        Armas.selectAll().map { it.toArmaResponse() }
    }

    fun getById(id: Int): ArmaResponse? = transaction {
        Armas.selectAll().where { Armas.idArma eq id }.singleOrNull()?.toArmaResponse()
    }

    fun create(payload: ArmaCreateRequest): ArmaResponse = transaction {
        if (payload.userId != null && !userExists(payload.userId)) {
            throw IllegalArgumentException("El usuario con id ${payload.userId} no existe")
        }

        val id = Armas.insert {
            it[nombre] = payload.nombre
            it[categoria] = payload.categoria
            it[coste] = payload.coste
            it[imagen] = payload.imagen
            it[informacionExtra] = payload.informacionExtra
            it[calibre] = payload.calibre
            it[stock] = payload.stock
            it[userId] = payload.userId
        }[Armas.idArma]

        Armas.selectAll().where { Armas.idArma eq id }.single().toArmaResponse()
    }

    fun update(id: Int, payload: ArmaUpdateRequest): Boolean = transaction {
        if (payload.userId != null && !userExists(payload.userId)) {
            throw IllegalArgumentException("El usuario con id ${payload.userId} no existe")
        }

        Armas.update({ Armas.idArma eq id }) {
            it[nombre] = payload.nombre
            it[categoria] = payload.categoria
            it[coste] = payload.coste
            it[imagen] = payload.imagen
            it[informacionExtra] = payload.informacionExtra
            it[calibre] = payload.calibre
            it[stock] = payload.stock
            it[userId] = payload.userId
        } > 0
    }

    fun delete(id: Int): Boolean = transaction {
        Armas.deleteWhere { Armas.idArma eq id } > 0
    }
}

private object AnuncioRepository {
    fun getAll(): List<AnuncioResponse> = transaction {
        Anuncios.selectAll().map { it.toAnuncioResponse() }
    }

    fun getById(id: Int): AnuncioResponse? = transaction {
        Anuncios.selectAll().where { Anuncios.idAnuncio eq id }.singleOrNull()?.toAnuncioResponse()
    }

    fun create(payload: AnuncioCreateRequest): AnuncioResponse = transaction {
        val id = Anuncios.insert {
            it[url] = payload.url
            it[imagen] = payload.imagen
        }[Anuncios.idAnuncio]

        Anuncios.selectAll().where { Anuncios.idAnuncio eq id }.single().toAnuncioResponse()
    }

    fun update(id: Int, payload: AnuncioUpdateRequest): Boolean = transaction {
        Anuncios.update({ Anuncios.idAnuncio eq id }) {
            it[url] = payload.url
            it[imagen] = payload.imagen
        } > 0
    }

    fun delete(id: Int): Boolean = transaction {
        Anuncios.deleteWhere { Anuncios.idAnuncio eq id } > 0
    }
}

fun Route.apiRoutes() {
    route("/api/v2") {
        route("/auth") {
            post("/register") {
                try {
                    val payload = call.receive<RegisterRequest>()
                    val usuario = UsuarioRepository.register(payload)
                    call.respond(
                        HttpStatusCode.Created,
                        AuthResponse(
                            token = usuario.token.orEmpty(),
                            usuario = usuario.toPublicResponse(),
                        ),
                    )
                } catch (exception: IllegalArgumentException) {
                    call.respond(HttpStatusCode.BadRequest, exception.message ?: "Datos inválidos")
                }
            }

            post("/login") {
                val payload = call.receive<LoginRequest>()
                val usuario = UsuarioRepository.login(payload.nombreUsuario, payload.contrasena)
                    ?: return@post call.respond(HttpStatusCode.Unauthorized, "Credenciales inválidas")

                call.respond(
                    HttpStatusCode.OK,
                    AuthResponse(
                        token = usuario.token.orEmpty(),
                        usuario = usuario.toPublicResponse(),
                    ),
                )
            }

            get("/validate") {
                val token = call.extractTokenFromHeaders()

                if (token == null) {
                    return@get call.respond(HttpStatusCode.Unauthorized, TokenValidationResponse(valido = false))
                }

                val usuario = UsuarioRepository.getByToken(token)
                if (usuario == null || !usuario.activo) {
                    return@get call.respond(HttpStatusCode.Unauthorized, TokenValidationResponse(valido = false))
                }

                call.respond(TokenValidationResponse(valido = true, usuario = usuario.toPublicResponse()))
            }

            get("/me") {
                val usuario = call.requireAuthenticatedUserOrRespond() ?: return@get

                call.respond(usuario.toPublicResponse())
            }

            post("/logout") {
                val usuario = call.requireAuthenticatedUserOrRespond() ?: return@post
                UsuarioRepository.clearToken(usuario.idUsuario)
                call.respond(HttpStatusCode.OK)
            }
        }

        route("/usuarios") {
            install(TokenAuthPlugin)

            get {
                call.respond(UsuarioRepository.getAll())
            }

            get("/{id}") {
                val id = call.parameters["id"]?.toIntOrNull()
                    ?: return@get call.respond(HttpStatusCode.BadRequest, "Id inválido")

                val item = UsuarioRepository.getById(id)
                    ?: return@get call.respond(HttpStatusCode.NotFound, "Usuario no encontrado")

                call.respond(item)
            }

            post {
                val payload = call.receive<UsuarioCreateRequest>()
                call.respond(HttpStatusCode.Created, UsuarioRepository.create(payload))
            }

            put("/{id}") {
                val id = call.parameters["id"]?.toIntOrNull()
                    ?: return@put call.respond(HttpStatusCode.BadRequest, "Id inválido")

                val payload = call.receive<UsuarioUpdateRequest>()
                val updated = UsuarioRepository.update(id, payload)

                if (!updated) call.respond(HttpStatusCode.NotFound, "Usuario no encontrado")
                else call.respond(HttpStatusCode.OK)
            }

            delete("/{id}") {
                val id = call.parameters["id"]?.toIntOrNull()
                    ?: return@delete call.respond(HttpStatusCode.BadRequest, "Id inválido")

                val deleted = UsuarioRepository.delete(id)

                if (!deleted) call.respond(HttpStatusCode.NotFound, "Usuario no encontrado")
                else call.respond(HttpStatusCode.NoContent)
            }
        }

        route("/armas") {
            install(TokenAuthPlugin)

            get {
                call.respond(ArmaRepository.getAll())
            }

            get("/{id}") {
                val id = call.parameters["id"]?.toIntOrNull()
                    ?: return@get call.respond(HttpStatusCode.BadRequest, "Id inválido")

                val item = ArmaRepository.getById(id)
                    ?: return@get call.respond(HttpStatusCode.NotFound, "Arma no encontrada")

                call.respond(item)
            }

            post {
                val payload = call.receive<ArmaCreateRequest>()
                try {
                    call.respond(HttpStatusCode.Created, ArmaRepository.create(payload))
                } catch (exception: IllegalArgumentException) {
                    call.respond(HttpStatusCode.BadRequest, exception.message ?: "Datos inválidos")
                }
            }

            put("/{id}") {
                val id = call.parameters["id"]?.toIntOrNull()
                    ?: return@put call.respond(HttpStatusCode.BadRequest, "Id inválido")

                val payload = call.receive<ArmaUpdateRequest>()
                val updated = try {
                    ArmaRepository.update(id, payload)
                } catch (exception: IllegalArgumentException) {
                    return@put call.respond(HttpStatusCode.BadRequest, exception.message ?: "Datos inválidos")
                }

                if (!updated) call.respond(HttpStatusCode.NotFound, "Arma no encontrada")
                else call.respond(HttpStatusCode.OK)
            }

            delete("/{id}") {
                val id = call.parameters["id"]?.toIntOrNull()
                    ?: return@delete call.respond(HttpStatusCode.BadRequest, "Id inválido")

                val deleted = ArmaRepository.delete(id)

                if (!deleted) call.respond(HttpStatusCode.NotFound, "Arma no encontrada")
                else call.respond(HttpStatusCode.NoContent)
            }
        }

        route("/anuncios") {
            install(TokenAuthPlugin)

            get {
                call.respond(AnuncioRepository.getAll())
            }

            get("/{id}") {
                val id = call.parameters["id"]?.toIntOrNull()
                    ?: return@get call.respond(HttpStatusCode.BadRequest, "Id inválido")

                val item = AnuncioRepository.getById(id)
                    ?: return@get call.respond(HttpStatusCode.NotFound, "Anuncio no encontrado")

                call.respond(item)
            }

            post {
                val payload = call.receive<AnuncioCreateRequest>()
                call.respond(HttpStatusCode.Created, AnuncioRepository.create(payload))
            }

            put("/{id}") {
                val id = call.parameters["id"]?.toIntOrNull()
                    ?: return@put call.respond(HttpStatusCode.BadRequest, "Id inválido")

                val payload = call.receive<AnuncioUpdateRequest>()
                val updated = AnuncioRepository.update(id, payload)

                if (!updated) call.respond(HttpStatusCode.NotFound, "Anuncio no encontrado")
                else call.respond(HttpStatusCode.OK)
            }

            delete("/{id}") {
                val id = call.parameters["id"]?.toIntOrNull()
                    ?: return@delete call.respond(HttpStatusCode.BadRequest, "Id inválido")

                val deleted = AnuncioRepository.delete(id)

                if (!deleted) call.respond(HttpStatusCode.NotFound, "Anuncio no encontrado")
                else call.respond(HttpStatusCode.NoContent)
            }
        }
    }
}
