package com.example

import com.zaxxer.hikari.HikariConfig
import com.zaxxer.hikari.HikariDataSource
import io.ktor.http.HttpStatusCode
import io.ktor.http.auth.HttpAuthHeader
import io.ktor.server.application.Application
import io.ktor.server.application.ApplicationCall
import io.ktor.server.application.call
import io.ktor.server.auth.authenticate
import io.ktor.server.auth.principal
import io.ktor.server.auth.jwt.JWTPrincipal
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
import org.mindrot.jbcrypt.BCrypt
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

        if (jdbcUrl.startsWith("jdbc:mariadb:", ignoreCase = true)) {
            runCatching {
                exec("ALTER TABLE usuarios MODIFY COLUMN imagen LONGTEXT NULL")
            }
        }
    }
}

object Usuarios : Table("usuarios") {
    val idUsuario = integer("idUsuario").autoIncrement()
    val nombreUsuario = varchar("nombre_usuario", 120)
    val contrasena = varchar("contrasena", 255)
    val imagen = text("imagen").nullable()
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

private object PasswordSecurity {
    fun hashPassword(rawPassword: String): String = BCrypt.hashpw(rawPassword, BCrypt.gensalt())

    fun isBcryptHash(value: String): Boolean {
        return value.startsWith("$2a$") || value.startsWith("$2b$") || value.startsWith("$2y$")
    }

    fun verifyPassword(rawPassword: String, storedPassword: String): Boolean {
        return if (isBcryptHash(storedPassword)) {
            BCrypt.checkpw(rawPassword, storedPassword)
        } else {
            rawPassword == storedPassword
        }
    }
}

private object UsuarioRepository {
    fun getAll(): List<UsuarioResponse> = transaction {
        Usuarios.selectAll().map { it.toUsuarioResponse() }
    }

    fun getById(id: Int): UsuarioResponse? = transaction {
        Usuarios.selectAll().where { Usuarios.idUsuario eq id }.singleOrNull()?.toUsuarioResponse()
    }

    fun create(payload: UsuarioCreateRequest): UsuarioResponse = transaction {
        val hashedPassword = PasswordSecurity.hashPassword(payload.contrasena)
        val id = Usuarios.insert {
            it[nombreUsuario] = payload.nombreUsuario
            it[contrasena] = hashedPassword
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

        val hashedPassword = PasswordSecurity.hashPassword(payload.contrasena)
        val generatedToken = UUID.randomUUID().toString()

        val id = Usuarios.insert {
            it[nombreUsuario] = payload.nombreUsuario
            it[contrasena] = hashedPassword
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
                (Usuarios.activo eq true)
        }.singleOrNull()?.toUsuarioResponse() ?: return@transaction null

        if (!PasswordSecurity.verifyPassword(password, usuario.contrasena)) {
            return@transaction null
        }

        var resultUsuario = usuario

        if (!PasswordSecurity.isBcryptHash(usuario.contrasena)) {
            val hashedPassword = PasswordSecurity.hashPassword(password)
            Usuarios.update({ Usuarios.idUsuario eq usuario.idUsuario }) {
                it[contrasena] = hashedPassword
            }
            resultUsuario = resultUsuario.copy(contrasena = hashedPassword)
        }

        if (!resultUsuario.token.isNullOrBlank()) return@transaction resultUsuario

        val generatedToken = UUID.randomUUID().toString()
        Usuarios.update({ Usuarios.idUsuario eq resultUsuario.idUsuario }) {
            it[token] = generatedToken
        }

        resultUsuario.copy(token = generatedToken)
    }

    fun getByToken(token: String): UsuarioResponse? = transaction {
        Usuarios.selectAll().where { Usuarios.token eq token }.singleOrNull()?.toUsuarioResponse()
    }

    fun clearToken(id: Int): Boolean = transaction {
        Usuarios.update({ Usuarios.idUsuario eq id }) {
            it[token] = null
        } > 0
    }

    fun isTokenActive(id: Int, tokenId: String): Boolean = transaction {
        Usuarios.selectAll().where {
            (Usuarios.idUsuario eq id) and
                (Usuarios.token eq tokenId) and
                (Usuarios.activo eq true)
        }.singleOrNull() != null
    }

    fun update(id: Int, payload: UsuarioUpdateRequest): Boolean = transaction {
        val hashedPassword = PasswordSecurity.hashPassword(payload.contrasena)
        Usuarios.update({ Usuarios.idUsuario eq id }) {
            it[nombreUsuario] = payload.nombreUsuario
            it[contrasena] = hashedPassword
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

fun isActiveJwtToken(userId: Int, tokenId: String): Boolean {
    return UsuarioRepository.isTokenActive(userId, tokenId)
}

private fun buildAuthResponse(application: Application, usuario: UsuarioResponse): AuthResponse {
    val tokenId = usuario.token ?: error("El usuario no tiene token activo")
    val jwtToken = JwtConfig.generateToken(application, usuario.idUsuario, usuario.nombreUsuario, tokenId)
    return AuthResponse(token = jwtToken, usuario = usuario.toPublicResponse())
}

private fun ApplicationCall.extractJwtTokenFromHeaders(): String? {
    val authorization = request.header("Authorization")
    val authHeader = authorization
        ?.takeIf { it.startsWith("Bearer ", ignoreCase = true) }
        ?.substringAfter("Bearer ")
        ?.trim()
        ?.takeIf { it.isNotEmpty() }
        ?.let { HttpAuthHeader.Single("Bearer", it) }
        ?: request.header("X-Auth-Token")
            ?.trim()
            ?.takeIf { it.isNotEmpty() }
            ?.let { HttpAuthHeader.Single("Bearer", it) }
    return JwtConfig.extractTokenFromHeaders(authHeader)
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
                        buildAuthResponse(call.application, usuario),
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
                    buildAuthResponse(call.application, usuario),
                )
            }

            get("/validate") {
                val token = call.extractJwtTokenFromHeaders()

                if (token == null) {
                    return@get call.respond(HttpStatusCode.Unauthorized, TokenValidationResponse(valido = false))
                }

                val decoded = JwtConfig.verifyToken(call.application, token)
                    ?: return@get call.respond(HttpStatusCode.Unauthorized, TokenValidationResponse(valido = false))

                val userId = decoded.getClaim("idUsuario").asInt()
                val tokenId = decoded.getClaim("tokenId").asString()

                if (userId == null || tokenId.isNullOrBlank() || !isActiveJwtToken(userId, tokenId)) {
                    return@get call.respond(HttpStatusCode.Unauthorized, TokenValidationResponse(valido = false))
                }

                val usuario = UsuarioRepository.getById(userId)
                if (usuario == null || !usuario.activo) {
                    return@get call.respond(HttpStatusCode.Unauthorized, TokenValidationResponse(valido = false))
                }

                call.respond(TokenValidationResponse(valido = true, usuario = usuario.toPublicResponse()))
            }

            authenticate("auth-jwt") {
                get("/me") {
                    val principal = call.principal<JWTPrincipal>()
                        ?: return@get call.respond(HttpStatusCode.Unauthorized)
                    val userId = principal.payload.getClaim("idUsuario").asInt()
                        ?: return@get call.respond(HttpStatusCode.Unauthorized)
                    val usuario = UsuarioRepository.getById(userId)
                        ?: return@get call.respond(HttpStatusCode.Unauthorized)

                    call.respond(usuario.toPublicResponse())
                }

                post("/logout") {
                    val principal = call.principal<JWTPrincipal>()
                        ?: return@post call.respond(HttpStatusCode.Unauthorized)
                    val userId = principal.payload.getClaim("idUsuario").asInt()
                        ?: return@post call.respond(HttpStatusCode.Unauthorized)

                    UsuarioRepository.clearToken(userId)
                    call.respond(HttpStatusCode.OK)
                }
            }
        }

        authenticate("auth-jwt") {
            route("/usuarios") {

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
}
