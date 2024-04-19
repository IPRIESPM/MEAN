# Backend en Nest

```bash
docker-compose up -d
```

Copiar el archivo ```.env.template``` a ```.env``` y añadir los datos de conexión a la base de datos.

## Rutas

### Auth

- POST /auth/

```json
{
    "name": "name",
    "email": "email",
    "password": "password"
}
```

- POST /auth/login

```json
{
    "email": "email",
    "password": "password"
}
```
