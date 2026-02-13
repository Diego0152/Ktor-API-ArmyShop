# Ktor API + MariaDB

API en Ktor con CRUD de `usuarios`, `armas` y `anuncios`, persistencia en MariaDB y administrador web de base de datos con Adminer.

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

## Endpoints

Cada recurso tiene CRUD completo:

- `GET /api/v1/usuarios`
- `GET /api/v1/usuarios/{id}`
- `POST /api/v1/usuarios`
- `PUT /api/v1/usuarios/{id}`
- `DELETE /api/v1/usuarios/{id}`

- `GET /api/v1/armas`
- `GET /api/v1/armas/{id}`
- `POST /api/v1/armas`
- `PUT /api/v1/armas/{id}`
- `DELETE /api/v1/armas/{id}`

- `GET /api/v1/anuncios`
- `GET /api/v1/anuncios/{id}`
- `POST /api/v1/anuncios`
- `PUT /api/v1/anuncios/{id}`
- `DELETE /api/v1/anuncios/{id}`

### Ejemplo `POST /api/v1/usuarios`

```json
{
	"nombreUsuario": "dani",
	"contrasena": "123456",
	"imagen": "https://img.example/avatar.png",
	"email": "dani@mail.com",
	"rol": "admin",
	"activo": true,
	"token": "mi-token"
}
```

### Ejemplo `POST /api/v1/armas`

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

### Ejemplo `POST /api/v1/anuncios`

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

