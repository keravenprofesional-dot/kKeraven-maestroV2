# STACK.md — Stack técnico real de KERPLUS

## Backend
- Lenguaje/runtime: Node.js 20 (imagen `node:20-alpine`)
- Framework: Express 4
- Gestor de paquetes: npm

## Frontend
- Un solo archivo `public/index.html` (HTML5, CSS3, JavaScript, sin framework) — sin Bootstrap ni build step
- Librerías externas por CDN: Tabler Icons (webfont), SheetJS `xlsx` (importar/exportar Excel), Leaflet (Ruta con Mapa), jsPDF + jsPDF-AutoTable + html2canvas (reportes PDF)
- AJAX contra la API REST (`/api/...`) vía el helper `apiFetch`
- IndexedDB (`keraven2`) solo para los módulos que aún no migraron a base de datos real (ver comentario en `guardar()`/`cargar()` en `public/index.html`)

## Base de datos
- Motor: PostgreSQL 16 — actualmente **Supabase** (managed, remoto) vía `DATABASE_URL` + `DB_SSL=true`; el servicio `db` local de `docker-compose.yml` (Postgres 16-alpine en `./pgdata`) sigue definido pero no es al que la app se conecta mientras `DATABASE_URL` apunte a Supabase
- ORM: ninguno — `pg` (Pool) con SQL parametrizado directo
- Cache: ninguno

## Infraestructura
- Contenedores: Docker Compose (`db` + `kerplus-app`, puerto host `8086:3000`)
- Hosting: por definir (migración a Supabase en curso; sin Synology en este proyecto)
- Reverse proxy: ninguno confirmado todavía (`trust proxy` ya configurado en `server.js`)
- CI/CD: ninguno todavía

## Autenticación
- Sesiones con `express-session` + `connect-pg-simple` (persistidas en la misma base Postgres que usa la app)
- Hash de PIN: `bcryptjs` (login por selector de usuario + PIN de 6 dígitos, no usuario/clave tradicional)
- RBAC de 6 roles (`gerente`, `subgerente`, `coordinador`, `supervisor`, `almacen`, `promotor`) con permisos por módulo (`PERMS_POR_ROL` en `db.js`), sobreescribibles por usuario vía `permisos_custom`

## IA
- Asistente propio ("Sarah"): claves de API cifradas en la tabla `config_ia` (nunca en texto plano — ver `IA_CIFRADO_SECRET`), consumidas solo desde el backend (el navegador nunca ve la clave)
- Usada también para lectura/verificación de cédula por proxy seguro

## Colas / trabajos en segundo plano
- Ninguno — todo es síncrono request/response

## Respaldo y restauración
- `backup.js` (`pg_dump`/`pg_restore`, requiere `postgresql-client` en la imagen) — respaldos manuales desde el módulo de Configuración, guardados en `backups/`

## Testing
- Ninguna suite automatizada todavía (`node:test` es la opción preferida si se agrega, según `agents/keraven.md` §5.12)

## Dependencias que el proyecto evita a propósito
Sin ORM pesado, sin framework de frontend, sin build step — mantenerlo así salvo autorización explícita.

## Versión mínima soportada de cada pieza
Node.js 20, PostgreSQL 16, Docker Compose (formato v3.8).
