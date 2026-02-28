# Ktor API + MariaDB

API en Ktor con CRUD de `usuarios`, `armas` y `anuncios`, persistencia en MariaDB y administrador web de base de datos con Adminer.

La API usa autenticación por token: para acceder a los endpoints de negocio debes estar logueado y enviar un token válido.

## Levantar base de datos y administrador

1. Levanta los contenedores:

```bash
docker compose up -d
```

2. Adminer quedará disponible en:

```text
http://localhost:8081
```

3. Datos de conexión de Adminer:

- System: `MariaDB`
- Server: `mariadb`
- Username: `ktor_user`
- Password: `ktor_pass`
- Database: `ktor_db`

## Configurar la API

Puedes copiar `.env.example` a `.env` y ajustar valores. Variables usadas por la app:

- `DB_URL` (ej. `jdbc:mariadb://localhost:3306/ktor_db`)
- `DB_DRIVER` (`org.mariadb.jdbc.Driver`)
- `DB_USER`
- `DB_PASSWORD`

Si no defines variables, la app usa H2 en memoria como fallback (útil para tests/desarrollo rápido).

## Ejecutar

```bash
./gradlew run
```

API base en `http://localhost:8080`.

## Endpoints de autenticación

Públicos (no requieren token):

- `POST /api/v2/auth/register`
- `POST /api/v2/auth/login`
- `GET /api/v2/auth/validate`

Protegidos (requieren token):

- `GET /api/v2/auth/me`
- `POST /api/v2/auth/logout`

## Endpoints protegidos (CRUD)

Todos requieren token válido:

- `GET /api/v2/usuarios`
- `GET /api/v2/usuarios/{id}`
- `POST /api/v2/usuarios`
- `PUT /api/v2/usuarios/{id}`
- `DELETE /api/v2/usuarios/{id}`

- `GET /api/v2/armas`
- `GET /api/v2/armas/{id}`
- `POST /api/v2/armas`
- `PUT /api/v2/armas/{id}`
- `DELETE /api/v2/armas/{id}`

- `GET /api/v2/anuncios`
- `GET /api/v2/anuncios/{id}`
- `POST /api/v2/anuncios`
- `PUT /api/v2/anuncios/{id}`
- `DELETE /api/v2/anuncios/{id}`

## Uso con Postman (paso a paso)

### 1) Crea un Environment en Postman

Variables recomendadas:

- `baseUrl` = `http://localhost:8080`
- `token` = *(vacía al inicio)*

### 2) Registrar usuario

Request:

- Método: `POST`
- URL: `{{baseUrl}}/api/v2/auth/register`
- Header: `Content-Type: application/json`
- Body:

```json
{
	"nombreUsuario": "dani",
	"contrasena": "123456",
	"imagen": "https://img.example/avatar.png",
	"email": "dani@mail.com",
	"rol": "admin"
}
```

La respuesta devuelve `token` y `usuario`.

### 3) Login

Request:

- Método: `POST`
- URL: `{{baseUrl}}/api/v2/auth/login`
- Header: `Content-Type: application/json`
- Body:

```json
{
	"nombreUsuario": "dani",
	"contrasena": "123456"
}
```

### 4) Guardar token automáticamente en Postman

En la request de `register` y/o `login`, en la pestaña **Tests**, añade:

```javascript
const json = pm.response.json();
if (json.token) {
	pm.environment.set("token", json.token);
}
```

### 5) Consumir endpoints protegidos

Puedes enviar el token de dos formas:

- Header `Authorization: Bearer {{token}}`
- o header `X-Auth-Token: {{token}}`

Ejemplo (listar usuarios):

- Método: `GET`
- URL: `{{baseUrl}}/api/v2/usuarios`
- Header: `Authorization: Bearer {{token}}`

Si no envías token o es inválido, la API responde `401 Unauthorized`.

### 6) Validar token

- Método: `GET`
- URL: `{{baseUrl}}/api/v2/auth/validate`
- Header: `Authorization: Bearer {{token}}`

### 7) Logout

- Método: `POST`
- URL: `{{baseUrl}}/api/v2/auth/logout`
- Header: `Authorization: Bearer {{token}}`

Esto invalida el token actual del usuario.

### Ejemplo `POST /api/v2/usuarios` (protegido)

```json
{
	"nombreUsuario": "dani",
	"contrasena": "123456",
	"imagen": "https://img.example/avatar.png",
	"email": "dani@mail.com",
	"rol": "admin",
	"activo": true,
	"token": "mi-token-opcional"
}
```

### Ejemplo `POST /api/v2/armas`

```json
{
	"nombre": "AK-47",
	"categoria": "Rifle",
	"coste": 1200.5,
	"imagen": "https://img.example/ak47.png",
	"informacionExtra": "Versión estándar",
	"calibre": "7.62",
	"stock": 10,
	"userId": 1
}
```

### Ejemplo `POST /api/v2/anuncios`

```json
{
	"url": "https://miweb.com/oferta",
	"imagen": "https://img.example/banner.png"
}
```

## Tests

```bash
./gradlew test
```

