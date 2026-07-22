# PROJECT.md — KERPLUS (Keraven Profesional)

## Nombre del proyecto
KERPLUS — backend + base de datos real de "Keraven Maestro v2", el sistema de
gestión interno de Keraven Profesional, SRL.

## Descripción en una frase
ERP/CRM interno para una empresa de venta de productos (contratos a
crédito/contado, cobranza, almacén/laboratorio de producción, comisiones,
nómina, contabilidad y RRHH), con jerarquía de roles y permisos por módulo.

## Dominio de negocio
Distribución y venta directa (promotores en ruta), con producción propia
(Laboratorio: materias primas → recetas → producción → stock) y cobranza en
campo (Ruta con Mapa, Cobrador Automático por WhatsApp).

## Roles de usuario y permisos
| Rol | Publica/administra | Alcance típico |
|---|---|---|
| Gerente | Todo — usuarios, permisos, configuración, anular factura, ver toda la facturación | Total |
| Sub-Gerente | Igual que Gerente salvo anular factura | Total |
| Coordinador | Buzón, cobros, comisiones, CRM, ruta | Amplio, sin Usuarios/Auditoría/RRHH |
| Supervisor | Buzón, cobros, comisiones (cuadre), ruta | Su equipo/zona |
| Almacén | Arqueo, Almacén Principal/Móvil | Inventario |
| Promotor | Registrar contrato (Facturación) | Lo que él mismo vende |

El permiso real de cada usuario lo decide `PERMS_POR_ROL` en `db.js` (o
`permisos_custom` si el usuario tiene overrides guardados) — es la fuente de
verdad, no la tabla de arriba, que es solo orientativa.

## Entidades principales del dominio
- **Contrato** (`contratos`): venta a un cliente, contado o crédito, con
  buzón de aprobación simultáneo a Supervisor/Coordinador/Gerente/Sub-Gerente
  (el primero que decide cierra en todos los buzones).
- **Cliente** (`clientes`): datos de contacto/dirección; alimenta CxC y CRM.
- **Producto** (`productos`): catálogo con precio de referencia.
- **Laboratorio**: `rrhh`-independiente — materias primas, recetas, entradas,
  producciones; termina sumando a `almacen_stock`.
- **Almacén** (`almacen_stock`, `almacen_entradas`, `almacen_movimientos`):
  bodega principal y ruta (móvil).
- **Comisiones** (`comisiones_semana_promotores` y relacionadas): semanal, por
  promotor, contado 16% / crédito 8% (regla ya codificada en el servidor).
- **RRHH** (`rrhh_incidencias`, `rrhh_vacaciones`, `rrhh_candidatos`,
  `rrhh_evaluaciones`): incidencias con referencia orientativa al Código de
  Trabajo dominicano (Ley 16-92) — **nunca** decide una sanción por sí solo.
- **Comunicados** (`comunicados`, `comunicados_confirmaciones`): anuncios
  internos — Gerencia/Sub-Gerencia/Coordinador publican (1 a 90 días de
  vigencia), Supervisor/Almacén/Promotor deben confirmar lectura.
- **Auditoría** (`auditoria`): historial de acciones administrativas.

## Reglas de negocio no obvias
- El Buzón de aprobación llega a varios roles a la vez; el primero que decide
  (aprobar/rechazar) cierra el contrato en todos los buzones — no es "primero
  en ver", es "primero en decidir".
- Comisión automática al aprobar un contrato: contado 16%, crédito 8% (la
  genera el servidor dentro de la misma transacción que aprueba).
- RRHH: el "artículo de referencia" del Código de Trabajo es solo
  informativo — el encargado de RRHH es quien decide, nunca el sistema.
- Comunicados: la vigencia (1-90 días) la fija quien publica; vencido, deja
  de listarse como vigente automáticamente (por fecha, sin tarea programada).
- Permisos: `permisos_custom` (si existe) **reemplaza por completo** la lista
  de permisos del rol — no la extiende ni la combina.

## Convenciones de idioma en el código
Español consistente en variables, funciones, columnas y mensajes. No mezclar
inglés y español en identificadores nuevos.

## Qué NO se puede romper
- El volumen `pgdata` si en algún momento se vuelve a usar el Postgres local
  (contiene datos reales de la operación).
- La conexión a Supabase (`DATABASE_URL`/`DB_SSL`) mientras dure la migración
  — no revertir a local sin confirmarlo explícitamente con quien pida el cambio.
- El cifrado de las claves de IA en `config_ia` (`IA_CIFRADO_SECRET`) — nunca
  guardarlas ni loguearlas en texto plano.
- El patrón de Buzón (decisión simultánea a varios roles, primero-en-decidir
  cierra para todos).

## Definición de "cambio crítico" para este proyecto
Igual que en `CLAUDE.md`: esquema de datos (`schema.sql`), autenticación/
sesiones/permisos, el modelo de roles/alcance, `docker-compose.yml`/
`Dockerfile`/puertos/volúmenes/variables de entorno, cualquier cosa que
borre/altere contratos, comisiones, nómina o RRHH ya registrados, y el
destino de `DATABASE_URL` (local vs. Supabase).

## Contactos / dueños del proyecto
Empresa: Keraven Profesional, SRL. Cambios críticos requieren aprobación
explícita de quien pide el trabajo.
