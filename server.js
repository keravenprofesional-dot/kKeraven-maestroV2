'use strict';

require('dotenv').config();
const path = require('path');
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const session = require('express-session');
const pgSession = require('connect-pg-simple')(session);

const db = require('./db');
const backup = require('./backup');

const app = express();
app.set('trust proxy', 1);

// CSP desactivada por ahora: el frontend actual (public/index.html) es un
// archivo unico con <style>/<script> inline masivos y sin infraestructura
// de nonces, y carga librerias desde jsdelivr/cdnjs/unpkg. Hardenizar CSP
// es trabajo pendiente para cuando el frontend este migrado (Etapa 3) y
// se pueda armar una politica que no rompa nada.
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '200kb' }));
app.use(express.static(path.join(__dirname, 'public')));

app.use(
  session({
    store: new pgSession({ pool: db.pool, createTableIfMissing: true }),
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: 'lax',
      secure: process.env.COOKIE_SECURE === 'true',
      maxAge: 1000 * 60 * 60 * 12, // 12 horas
    },
  })
);

// Limites por IP (defensa contra flood/DoS), no contra fuerza bruta de un
// PIN puntual -- eso ya lo cubre el bloqueo POR CUENTA en verificarLogin()
// (MAX_INTENTOS fallidos seguidos bloquea esa cuenta, sin importar la IP).
// Varios promotores/supervisores entrando casi al mismo tiempo desde la
// misma red de oficina o el mismo NAT comparten IP -- con límites bajos
// (15 logins / 600 llamadas de API cada 15 min) los primeros entran y el
// resto queda bloqueado sin haber hecho nada malo. Subido a un techo que
// sigue frenando un ataque real pero no golpea el uso legítimo concurrente.
const limiteLogin = rateLimit({ windowMs: 15 * 60 * 1000, max: 60, standardHeaders: true, legacyHeaders: false });
const limiteApi = rateLimit({ windowMs: 15 * 60 * 1000, max: 3000, standardHeaders: true, legacyHeaders: false });
app.use('/api', limiteApi);

function h(fn) {
  return (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
}

function requireAuth(req, res, next) {
  if (!req.session.usuarioId) return res.status(401).json({ error: 'No autenticado' });
  next();
}

function requirePermiso(modulo) {
  return async (req, res, next) => {
    const usuario = req.usuario || await db.buscarUsuarioPorId(req.session.usuarioId);
    if (!usuario || !usuario.activo) return res.status(401).json({ error: 'No autenticado' });
    const permisos = db.permisosEfectivos(usuario);
    if (!permisos.includes(modulo)) return res.status(403).json({ error: 'Sin permiso para este módulo' });
    req.usuario = usuario;
    next();
  };
}

function requireAnyPermiso(...modulos) {
  return async (req, res, next) => {
    const usuario = req.usuario || await db.buscarUsuarioPorId(req.session.usuarioId);
    if (!usuario || !usuario.activo) return res.status(401).json({ error: 'No autenticado' });
    const permisos = db.permisosEfectivos(usuario);
    if (!modulos.some((m) => permisos.includes(m))) return res.status(403).json({ error: 'Sin permiso para este módulo' });
    req.usuario = usuario;
    next();
  };
}

// Exige un permiso adicional SOLO si la peticion viene marcada como
// importacion masiva (ver `condicion`) -- asi la ruta de un solo
// registro (formulario normal) no se ve afectada, pero una carga por
// Excel/lote si necesita ademas el permiso opcional 'excel' que
// Gerencia otorga aparte en Usuarios. Se encadena DESPUES de
// requirePermiso/requireAnyPermiso para reusar el req.usuario ya cargado.
function requirePermisoSi(condicion, modulo) {
  return async (req, res, next) => {
    if (!condicion(req)) return next();
    const usuario = req.usuario || await db.buscarUsuarioPorId(req.session.usuarioId);
    if (!usuario || !usuario.activo) return res.status(401).json({ error: 'No autenticado' });
    const permisos = db.permisosEfectivos(usuario);
    if (!permisos.includes(modulo)) return res.status(403).json({ error: 'Sin permiso para importar/exportar Excel' });
    req.usuario = usuario;
    next();
  };
}
const esImportacionExcel = (req) => !!(req.body && (req.body.origen === 'excel' || req.body.viaImportacion === true));

function requireRol(...roles) {
  return async (req, res, next) => {
    const usuario = await db.buscarUsuarioPorId(req.session.usuarioId);
    if (!usuario || !usuario.activo) return res.status(401).json({ error: 'No autenticado' });
    if (!roles.includes(usuario.rol)) return res.status(403).json({ error: 'Rol sin autorización' });
    req.usuario = usuario;
    next();
  };
}

// ── LOGIN ─────────────────────────────────────────────────────────
// Lista de usuarios activos para el selector del login (no incluye pin_hash).
app.get('/api/usuarios-login', h(async (req, res) => {
  res.json(await db.listarUsuariosActivos());
}));

app.post('/api/login', limiteLogin, h(async (req, res) => {
  const { usuarioId, pin } = req.body || {};
  if (!usuarioId || !pin) return res.status(400).json({ error: 'Falta usuario o PIN' });

  const resultado = await db.verificarLogin(usuarioId, pin);
  if (!resultado.ok) {
    if (resultado.motivo === 'bloqueado') {
      return res.status(429).json({ error: 'Usuario bloqueado temporalmente por intentos fallidos', bloqueado_hasta: resultado.bloqueado_hasta });
    }
    return res.status(401).json({ error: 'Usuario o PIN incorrecto' });
  }

  // Regenerar sesion en el login (previene fijacion de sesion)
  req.session.regenerate((err) => {
    if (err) return res.status(500).json({ error: 'Error de sesión' });
    req.session.usuarioId = resultado.usuario.id;
    const { pin_hash, ...usuarioSinHash } = resultado.usuario;
    res.json({ usuario: usuarioSinHash, permisos: db.permisosEfectivos(resultado.usuario) });
  });
}));

app.post('/api/logout', (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

// Reverifica el PIN del usuario YA logueado, para confirmaciones sensibles
// (ej. eliminar una factura) sin alterar la sesión activa. Usa el mismo
// limite de intentos que el login normal — nunca acepta un PIN maestro.
app.post('/api/verificar-pin', requireAuth, limiteLogin, h(async (req, res) => {
  const { pin } = req.body || {};
  if (!pin) return res.status(400).json({ error: 'Falta el PIN' });
  const resultado = await db.verificarLogin(req.session.usuarioId, pin);
  if (!resultado.ok) {
    if (resultado.motivo === 'bloqueado') {
      return res.status(429).json({ error: 'Demasiados intentos. Cuenta bloqueada temporalmente.' });
    }
    return res.status(401).json({ error: 'PIN incorrecto' });
  }
  res.json({ ok: true });
}));

app.get('/api/session', requireAuth, h(async (req, res) => {
  const usuario = await db.buscarUsuarioPorId(req.session.usuarioId);
  if (!usuario || !usuario.activo) return res.status(401).json({ error: 'No autenticado' });
  const { pin_hash, ...usuarioSinHash } = usuario;
  res.json({ usuario: usuarioSinHash, permisos: db.permisosEfectivos(usuario) });
}));

// ── USUARIOS (administración — solo gerente/subgerente) ─────────────
app.get('/api/usuarios', requireAuth, requireRol('gerente', 'subgerente'), h(async (req, res) => {
  res.json(await db.listarUsuariosCompleto());
}));

app.patch('/api/usuarios/:id', requireAuth, requireRol('gerente', 'subgerente'), h(async (req, res) => {
  const { nombre, rol, rolLabel } = req.body || {};
  const actualizado = await db.actualizarUsuario(req.params.id, { nombre, rol, rolLabel });
  if (!actualizado) return res.status(404).json({ error: 'Usuario no encontrado' });
  res.json(actualizado);
}));

app.post('/api/usuarios', requireAuth, requireRol('gerente', 'subgerente'), h(async (req, res) => {
  const { nombre, rol, rolLabel, pin, color } = req.body || {};
  if (!nombre || !rol || !pin) return res.status(400).json({ error: 'Faltan datos obligatorios' });
  const nuevo = await db.crearUsuario({ nombre, rol, rolLabel, pin, color });
  res.status(201).json(nuevo);
}));

app.patch('/api/usuarios/:id/permisos', requireAuth, requireRol('gerente', 'subgerente'), h(async (req, res) => {
  const { permisos } = req.body || {}; // array de modulos, o null para volver al default del rol
  await db.actualizarPermisosUsuario(req.params.id, permisos);
  res.json({ ok: true });
}));

// Alcance de Facturación: por defecto cada usuario (salvo Gerente/
// Sub-Gerente) solo ve lo que él mismo registró. Esto habilita ver la
// facturación de todo el equipo -- exclusivo de quien Gerencia decida.
app.patch('/api/usuarios/:id/ver-todas-facturas', requireAuth, requireRol('gerente', 'subgerente'), h(async (req, res) => {
  const { valor } = req.body || {};
  await db.actualizarVerTodasFacturas(req.params.id, !!valor);
  res.json({ ok: true });
}));

app.patch('/api/usuarios/:id/pin', requireAuth, requireRol('gerente', 'subgerente'), h(async (req, res) => {
  const { pin } = req.body || {};
  if (!pin) return res.status(400).json({ error: 'Falta el nuevo PIN' });
  await db.cambiarPinUsuario(req.params.id, pin);
  res.json({ ok: true });
}));

app.post('/api/usuarios/:id/desactivar', requireAuth, requireRol('gerente', 'subgerente'), h(async (req, res) => {
  await db.desactivarUsuario(req.params.id);
  res.json({ ok: true });
}));
app.post('/api/usuarios/:id/reactivar', requireAuth, requireRol('gerente', 'subgerente'), h(async (req, res) => {
  await db.reactivarUsuario(req.params.id);
  res.json({ ok: true });
}));

// ── PRODUCTOS (catálogo editable) ────────────────────────────────────
app.get('/api/productos', requireAuth, h(async (req, res) => {
  res.json(await db.listarProductos({ soloActivos: req.query.todos !== '1' }));
}));

app.post('/api/productos', requireAuth, requirePermiso('productos'), requirePermisoSi(esImportacionExcel, 'excel'), h(async (req, res) => {
  const { nombre, precioReferencia, categoria, codigo } = req.body || {};
  if (!nombre) return res.status(400).json({ error: 'Falta el nombre del producto' });
  res.status(201).json(await db.crearProducto({ nombre, precioReferencia, categoria, codigo }));
}));

app.patch('/api/productos/:id', requireAuth, requirePermiso('productos'), requirePermisoSi(esImportacionExcel, 'excel'), h(async (req, res) => {
  const { nombre, precioReferencia, categoria, codigo } = req.body || {};
  const actualizado = await db.actualizarProducto(req.params.id, { nombre, precioReferencia, categoria, codigo });
  if (!actualizado) return res.status(404).json({ error: 'Producto no encontrado' });
  res.json(actualizado);
}));

app.post('/api/productos/:id/desactivar', requireAuth, requirePermiso('productos'), h(async (req, res) => {
  await db.desactivarProducto(req.params.id);
  res.json({ ok: true });
}));
app.post('/api/productos/:id/reactivar', requireAuth, requirePermiso('productos'), h(async (req, res) => {
  await db.reactivarProducto(req.params.id);
  res.json({ ok: true });
}));

// ── LABORATORIO (fabricación: materias primas, recetas, producción) ──
app.get('/api/lab/materias-primas', requireAuth, requirePermiso('laboratorio'), h(async (req, res) => {
  res.json(await db.listarMateriasPrimas({ soloActivas: req.query.todos !== '1' }));
}));
app.post('/api/lab/materias-primas', requireAuth, requirePermiso('laboratorio'), requirePermisoSi(esImportacionExcel, 'excel'), h(async (req, res) => {
  const { nombre, tipo, unidad, costoUnitario, stockMinimo } = req.body || {};
  if (!nombre) return res.status(400).json({ error: 'Falta el nombre de la materia prima' });
  res.status(201).json(await db.crearMateriaPrima({ nombre, tipo, unidad, costoUnitario, stockMinimo }));
}));
app.patch('/api/lab/materias-primas/:id', requireAuth, requirePermiso('laboratorio'), requirePermisoSi(esImportacionExcel, 'excel'), h(async (req, res) => {
  const { nombre, tipo, unidad, costoUnitario, stockMinimo } = req.body || {};
  const actualizado = await db.actualizarMateriaPrima(req.params.id, { nombre, tipo, unidad, costoUnitario, stockMinimo });
  if (!actualizado) return res.status(404).json({ error: 'Materia prima no encontrada' });
  res.json(actualizado);
}));
app.post('/api/lab/materias-primas/:id/desactivar', requireAuth, requirePermiso('laboratorio'), h(async (req, res) => {
  await db.desactivarMateriaPrima(req.params.id);
  res.json({ ok: true });
}));
app.post('/api/lab/materias-primas/:id/reactivar', requireAuth, requirePermiso('laboratorio'), h(async (req, res) => {
  await db.reactivarMateriaPrima(req.params.id);
  res.json({ ok: true });
}));

app.post('/api/lab/materias-primas/:id/entrada', requireAuth, requirePermiso('laboratorio'), h(async (req, res) => {
  const { cantidad, costoTotal, proveedor, loteProveedor, fechaVencimiento } = req.body || {};
  if (cantidad == null || Number(cantidad) <= 0) return res.status(400).json({ error: 'Cantidad inválida' });
  const actualizado = await db.registrarEntradaLab(req.params.id, cantidad, { costoTotal, proveedor, loteProveedor, fechaVencimiento }, req.usuario.id);
  if (!actualizado) return res.status(404).json({ error: 'Materia prima no encontrada' });
  res.json(actualizado);
}));
app.get('/api/lab/entradas', requireAuth, requirePermiso('laboratorio'), h(async (req, res) => {
  res.json(await db.listarEntradasLab(req.query.materiaPrimaId));
}));

app.get('/api/lab/recetas', requireAuth, requirePermiso('laboratorio'), h(async (req, res) => {
  res.json(await db.listarRecetas());
}));
app.post('/api/lab/recetas/:productoId', requireAuth, requirePermiso('laboratorio'), h(async (req, res) => {
  const { contenidoPorUnidad, contenidoUnidad, mermaPct, notas, items } = req.body || {};
  res.json(await db.guardarReceta(req.params.productoId, { contenidoPorUnidad, contenidoUnidad, mermaPct, notas, items }));
}));

app.get('/api/lab/producciones', requireAuth, requirePermiso('laboratorio'), h(async (req, res) => {
  res.json(await db.listarProducciones());
}));
// Confirmar una producción consume inventario real y afecta el costo de
// fabricación -- permiso aparte de 'laboratorio' (armar recetas, ver
// catálogo) para que no cualquiera con acceso al módulo pueda disparar
// esta acción irreversible.
app.post('/api/lab/producciones', requireAuth, requirePermiso('laboratorio'), requirePermiso('laboratorio_produccion'), h(async (req, res) => {
  const { recetaId, lotes, sumarAlmacen } = req.body || {};
  if (!recetaId || !lotes) return res.status(400).json({ error: 'Faltan datos' });
  const resultado = await db.registrarProduccion(recetaId, lotes, sumarAlmacen !== false, req.usuario.id);
  if (!resultado) return res.status(404).json({ error: 'Receta no encontrada' });
  if (resultado.error) return res.status(409).json(resultado);
  res.status(201).json(resultado);
}));

// ── CONTRATOS / FACTURACIÓN ───────────────────────────────────────────
app.get('/api/contratos', requireAuth, requireAnyPermiso('contrato', 'buzon', 'cobros'), h(async (req, res) => {
  res.json(await db.listarContratos({ estado: req.query.estado, usuario: req.usuario }));
}));

// Cuadre de ventas del propio usuario -- lo único que un promotor/vendedor
// puede ver de su facturación: totales, nunca el detalle de un cliente.
app.get('/api/contratos/mi-cuadre', requireAuth, requirePermiso('contrato'), h(async (req, res) => {
  res.json(await db.resumenVentasUsuario(req.usuario.id));
}));

app.post('/api/contratos', requireAuth, requirePermiso('contrato'), requirePermisoSi(esImportacionExcel, 'excel'), h(async (req, res) => {
  const datos = req.body || {};
  if (!datos.nombre || !datos.cedula || !datos.telefono1 || !datos.monto || !datos.tipoVenta) {
    return res.status(400).json({ error: 'Faltan datos obligatorios del contrato' });
  }
  const contrato = await db.crearContrato(datos, req.usuario ? req.usuario.id : req.session.usuarioId);
  res.status(201).json(contrato);
}));

app.post('/api/contratos/:id/decidir', requireAuth, requirePermiso('buzon'), h(async (req, res) => {
  const { decision, comentario } = req.body || {};
  if (!['aprobado', 'rechazado'].includes(decision)) return res.status(400).json({ error: 'Decisión inválida' });
  const usuario = await db.buscarUsuarioPorId(req.session.usuarioId);
  const contrato = await db.decidirContrato(req.params.id, decision, comentario || '', usuario.id, usuario.nombre);
  if (!contrato) return res.status(404).json({ error: 'Contrato no encontrado' });
  if (contrato.conflicto) {
    const quien = contrato.decididoPor ? await db.buscarUsuarioPorId(contrato.decididoPor) : null;
    return res.status(409).json({
      error: `Este contrato ya fue ${contrato.estadoActual}${quien ? ' por ' + quien.nombre : ''}. Tu decisión no se aplicó.`,
    });
  }
  res.json(contrato);
}));

// Editar los datos del cliente de un contrato ya aprobado -- exclusivo
// Gerente/Sub-Gerente (regla confirmada por el usuario: solo esos dos
// roles editan lo que otros ya crearon, no solo lo aprueban).
app.patch('/api/contratos/:id/cliente', requireAuth, requireRol('gerente', 'subgerente'), h(async (req, res) => {
  const { nombre, cedula, telefono1, telefono2, email, institucion, barrio, referencia, direccion, motivo } = req.body || {};
  if (!nombre || !cedula) return res.status(400).json({ error: 'Nombre y cédula son obligatorios' });
  const contrato = await db.editarClienteDeContrato(
    req.params.id,
    { nombre, cedula, telefono1, telefono2, email, institucion, barrio, referencia, direccion },
    motivo
  );
  if (!contrato) return res.status(404).json({ error: 'Contrato no encontrado' });
  res.json(contrato);
}));

// Eliminar factura -- accion irreversible, exclusiva Gerente/Sub-Gerente.
// El frontend ya revalida el PIN por separado (/api/verificar-pin)
// antes de llamar a esto; el requireRol de aca es la segunda capa.
// Ya no se borra la factura -- queda el registro completo, marcado
// como anulado, con quien, cuando y por que (ver anularContrato en db.js).
app.post('/api/contratos/:id/anular', requireAuth, requireRol('gerente', 'subgerente'), h(async (req, res) => {
  const { motivo } = req.body || {};
  if (!motivo || !motivo.trim()) return res.status(400).json({ error: 'El motivo de la anulación es obligatorio' });
  const resultado = await db.anularContrato(req.params.id, req.usuario.id, motivo.trim());
  if (!resultado) return res.status(404).json({ error: 'Contrato no encontrado' });
  res.json(resultado);
}));

// Auditoría: linea de tiempo de anulaciones/decisiones/abonos, y
// alertas calculadas contra los datos reales. Solo Gerencia.
app.get('/api/auditoria', requireAuth, requireRol('gerente', 'subgerente'), h(async (req, res) => {
  const [eventos, alertas] = await Promise.all([db.listarAuditoria(), db.alertasSistema()]);
  res.json({ eventos, alertas });
}));

// Tareas: pueden nacer de una alerta de Auditoría o crearse a mano.
// Cualquier usuario autenticado ve/actualiza sus propias tareas; solo
// Gerencia/Sub-Gerencia pueden crear y asignarle una tarea a otro.
app.get('/api/tareas', requireAuth, h(async (req, res) => {
  res.json(await db.listarTareas({ soloAbiertas: req.query.abiertas === '1' }));
}));
app.post('/api/tareas', requireAuth, requireRol('gerente', 'subgerente'), h(async (req, res) => {
  const { titulo, descripcion, origenTipo, asignadoA, fechaLimite } = req.body || {};
  if (!titulo || !titulo.trim()) return res.status(400).json({ error: 'Falta el título de la tarea' });
  res.status(201).json(await db.crearTarea({ titulo, descripcion, origenTipo, asignadoA, fechaLimite }, req.usuario.id));
}));
app.patch('/api/tareas/:id', requireAuth, h(async (req, res) => {
  const { estado } = req.body || {};
  if (!['pendiente', 'en_proceso', 'completada', 'descartada'].includes(estado)) {
    return res.status(400).json({ error: 'Estado inválido' });
  }
  const tarea = await db.actualizarEstadoTarea(req.params.id, estado);
  if (!tarea) return res.status(404).json({ error: 'Tarea no encontrada' });
  res.json(tarea);
}));

// ── COMUNICADOS ──────────────────────────────────────────────────
// Publican Gerencia/Sub-Gerencia/Coordinador; deben confirmar lectura
// Supervisor/Almacén/Promotor. Vigencia elegida por quien publica (1-90 días).
app.get('/api/comunicados', requireAuth, requirePermiso('comunicados'), h(async (req, res) => {
  res.json(await db.listarComunicadosVigentes(req.usuario.id));
}));
app.post('/api/comunicados', requireAuth, requireRol('gerente', 'subgerente', 'coordinador'), h(async (req, res) => {
  const { titulo, mensaje, diasVigencia } = req.body || {};
  if (!titulo || !titulo.trim()) return res.status(400).json({ error: 'Falta el título' });
  if (!mensaje || !mensaje.trim()) return res.status(400).json({ error: 'Falta el mensaje' });
  const dias = Number(diasVigencia);
  if (!Number.isInteger(dias) || dias < 1 || dias > 90) {
    return res.status(400).json({ error: 'Los días de vigencia deben ser un entero entre 1 y 90' });
  }
  res.status(201).json(await db.crearComunicado({ titulo: titulo.trim(), mensaje: mensaje.trim(), diasVigencia: dias }, req.usuario.id));
}));
app.post('/api/comunicados/:id/confirmar', requireAuth, requireRol(...db.ROLES_CONFIRMAN_COMUNICADO), h(async (req, res) => {
  const com = await db.confirmarComunicado(req.params.id, req.usuario.id);
  if (!com) return res.status(404).json({ error: 'Comunicado no encontrado o ya venció' });
  res.json({ ok: true });
}));
app.get('/api/comunicados/:id/confirmaciones', requireAuth, requireRol('gerente', 'subgerente', 'coordinador'), h(async (req, res) => {
  res.json(await db.listarConfirmacionesComunicado(req.params.id));
}));
app.post('/api/comunicados/:id/desactivar', requireAuth, requireRol('gerente', 'subgerente', 'coordinador'), h(async (req, res) => {
  const com = await db.desactivarComunicado(req.params.id);
  if (!com) return res.status(404).json({ error: 'Comunicado no encontrado' });
  res.json(com);
}));

app.post('/api/contratos/:id/abonar', requireAuth, requireAnyPermiso('cobros', 'cobrador', 'ruta'), h(async (req, res) => {
  const { monto, via, nota } = req.body || {};
  if (monto == null || Number(monto) < 0) return res.status(400).json({ error: 'Monto inválido' });
  const contrato = await db.registrarAbonoContrato(req.params.id, monto, { via, nota }, req.usuario.id);
  if (!contrato) return res.status(404).json({ error: 'Contrato no encontrado' });
  res.json(contrato);
}));

// Ruta con Mapa: selección manual de la ruta del día (gerente/supervisor
// buscan y agregan a mano, ya no se arma sola con todo contrato con GPS).
app.get('/api/ruta/buscar', requireAuth, requirePermiso('ruta'), h(async (req, res) => {
  const q = String(req.query.q || '').trim();
  if (q.length < 2) return res.json([]);
  res.json(await db.buscarContratosParaRuta(q));
}));
app.get('/api/ruta/seleccion', requireAuth, requirePermiso('ruta'), h(async (req, res) => {
  res.json(await db.listarRutaSeleccionHoy());
}));
app.post('/api/ruta/seleccion', requireAuth, requirePermiso('ruta'), h(async (req, res) => {
  const { contratoId, gpsLat, gpsLng } = req.body || {};
  if (!contratoId) return res.status(400).json({ error: 'Falta contratoId' });
  if ((gpsLat == null) !== (gpsLng == null)) return res.status(400).json({ error: 'GPS incompleto' });
  await db.agregarARutaSeleccion(contratoId, req.usuario.id, gpsLat, gpsLng);
  res.json(await db.listarRutaSeleccionHoy());
}));
app.delete('/api/ruta/seleccion/:id', requireAuth, requirePermiso('ruta'), h(async (req, res) => {
  await db.quitarDeRutaSeleccion(req.params.id);
  res.json({ ok: true });
}));
app.patch('/api/ruta/seleccion/:id', requireAuth, requirePermiso('ruta'), h(async (req, res) => {
  const { estado, montoResultado, nota } = req.body || {};
  if (!['pagado', 'abonado', 'no_pago', 'saltado', 'pendiente'].includes(estado)) {
    return res.status(400).json({ error: 'Estado inválido' });
  }
  const fila = await db.actualizarEstadoRuta(req.params.id, estado, montoResultado, nota);
  if (!fila) return res.status(404).json({ error: 'No encontrado' });
  res.json(fila);
}));

// Datos operativos de cobranza (telefono2, fecha limite, promesa de pago,
// notas de gestion) -- NO toca monto ni saldo, eso solo cambia abonando.
// Trabajo diario de Cobrador/Cobros/Ruta, no restringido a Gerente/Sub-Gerente.
app.patch('/api/contratos/:id/cobranza', requireAuth, requireAnyPermiso('cobrador', 'cobros', 'ruta'), requirePermisoSi(esImportacionExcel, 'excel'), h(async (req, res) => {
  const { telefono2, fechaLimite, promesaPago, notas } = req.body || {};
  const contrato = await db.editarDatosCobranza(req.params.id, { telefono2, fechaLimite, promesaPago, notas });
  if (!contrato) return res.status(404).json({ error: 'Contrato no encontrado' });
  res.json(contrato);
}));

// Migracion (una sola vez, desde el navegador) de los clientes que el
// Cobrador tenia en localStorage antes de conectarse a la base de datos
// real. No exige cedula/promotor/productos porque esa deuda ya existia.
// Esta ruta SOLO la usan los importadores masivos (nunca una edicion de
// un solo registro), asi que exige 'excel' siempre, sin condicion.
app.post('/api/contratos/migrar-cobrador', requireAuth, requireAnyPermiso('cobrador', 'cobros', 'ruta'), requirePermiso('excel'), h(async (req, res) => {
  const { numeroFactura, nombre, telefono1, telefono2, monto, saldo, fechaLimite, promesaPago, notas } = req.body || {};
  if (!numeroFactura || !nombre || monto == null) return res.status(400).json({ error: 'Faltan datos obligatorios' });
  const contrato = await db.crearContratoLegacyCobrador(
    { numeroFactura, nombre, telefono1, telefono2, monto, saldo, fechaLimite, promesaPago, notas },
    req.usuario.id
  );
  if (!contrato) return res.status(409).json({ error: 'Ya existe una factura con ese número' });
  res.status(201).json(contrato);
}));

// ── ALMACÉN (bodega y ruta) ───────────────────────────────────────────
app.get('/api/almacen/stock', requireAuth, requireAnyPermiso('almp', 'almm', 'arqueo'), h(async (req, res) => {
  res.json(await db.listarStock());
}));

app.get('/api/almacen/entradas', requireAuth, requirePermiso('almp'), h(async (req, res) => {
  res.json(await db.listarEntradasAlmacen());
}));

app.post('/api/almacen/entradas', requireAuth, requirePermiso('almp'), h(async (req, res) => {
  const { proveedor, items } = req.body || {};
  if (!Array.isArray(items) || !items.length) return res.status(400).json({ error: 'Ingresa al menos una cantidad' });
  res.status(201).json(await db.registrarEntradaAlmacen({ proveedor, items }, req.usuario.id));
}));

app.post('/api/almacen/movimientos', requireAuth, requirePermiso('almm'), h(async (req, res) => {
  const { tipo, clienteTexto, items } = req.body || {};
  if (!['venta', 'carga'].includes(tipo)) return res.status(400).json({ error: 'Tipo de movimiento inválido' });
  if (!Array.isArray(items) || !items.length) return res.status(400).json({ error: 'Selecciona al menos un producto' });
  const resultado = await db.registrarMovimientoAlmacen({ tipo, clienteTexto, items }, req.usuario.id);
  if (resultado.error) return res.status(400).json({ error: resultado.error });
  res.status(201).json(resultado);
}));

// ── COMISIONES ─────────────────────────────────────────────────────
app.get('/api/comisiones/semanas', requireAuth, requireAnyPermiso('com', 'miscom'), h(async (req, res) => {
  res.json(await db.listarComisionesSemanas());
}));

app.post('/api/comisiones/semanas', requireAuth, requirePermiso('com'), h(async (req, res) => {
  const { fechaDesde, fechaHasta, mesPago, promotores } = req.body || {};
  if (!fechaDesde) return res.status(400).json({ error: 'Falta la fecha de inicio' });
  if (!Array.isArray(promotores) || !promotores.length) return res.status(400).json({ error: 'Ingresa al menos una venta' });
  res.status(201).json(await db.crearSemanaComisionManual({ fechaDesde, fechaHasta, mesPago, promotores }, req.usuario.id));
}));

app.post('/api/comisiones/regenerar', requireAuth, requirePermiso('com'), h(async (req, res) => {
  res.json({ agregadas: await db.regenerarComisionesFaltantes(req.usuario.id) });
}));

app.post('/api/comisiones/pagar', requireAuth, requirePermiso('com'), h(async (req, res) => {
  const pago = await db.marcarComisionesSemanasPagadas(req.usuario.id);
  if (!pago) return res.status(400).json({ error: 'No hay semanas pendientes de pago' });
  res.json(pago);
}));

app.get('/api/comisiones/pagos', requireAuth, requirePermiso('com'), h(async (req, res) => {
  res.json(await db.listarComisionesPagos());
}));

// ── CUENTAS POR PAGAR ─────────────────────────────────────────────────
app.get('/api/cuentas-por-pagar', requireAuth, requirePermiso('cxp'), h(async (req, res) => {
  res.json(await db.listarCuentasPorPagar());
}));

app.post('/api/cuentas-por-pagar', requireAuth, requirePermiso('cxp'), h(async (req, res) => {
  const { proveedor, concepto, monto, vencimiento, notas } = req.body || {};
  if (!proveedor || !monto) return res.status(400).json({ error: 'Proveedor y monto son obligatorios' });
  res.status(201).json(await db.crearCuentaPorPagar({ proveedor, concepto, monto, vencimiento, notas }));
}));

app.post('/api/cuentas-por-pagar/:id/abonar', requireAuth, requirePermiso('cxp'), h(async (req, res) => {
  const { monto, nota } = req.body || {};
  if (!monto || Number(monto) <= 0) return res.status(400).json({ error: 'Monto inválido' });
  const cuenta = await db.abonarCuentaPorPagar(req.params.id, monto, nota);
  if (!cuenta) return res.status(404).json({ error: 'Cuenta no encontrada' });
  res.json(cuenta);
}));

// ── CRM — CLIENTES ─────────────────────────────────────────────────────
app.get('/api/crm/clientes', requireAuth, requirePermiso('ccrm'), h(async (req, res) => {
  res.json(await db.listarClientesCrm());
}));

app.post('/api/crm/clientes', requireAuth, requirePermiso('ccrm'), h(async (req, res) => {
  const { nombre, telefono1, cedula, tipo, notas, estadoCrm, proximoSeguimiento, vendedorId } = req.body || {};
  if (!nombre) return res.status(400).json({ error: 'Falta el nombre' });
  res.status(201).json(await db.crearClienteCrm({ nombre, telefono1, cedula, tipo, notas, estadoCrm, proximoSeguimiento, vendedorId }));
}));

app.patch('/api/crm/clientes/:id', requireAuth, requirePermiso('ccrm'), h(async (req, res) => {
  const { estadoCrm, proximoSeguimiento, vendedorId } = req.body || {};
  const actualizado = await db.actualizarClienteCrm(req.params.id, { estadoCrm, proximoSeguimiento, vendedorId });
  if (!actualizado) return res.status(404).json({ error: 'Cliente no encontrado' });
  res.json(actualizado);
}));

app.post('/api/crm/clientes/:id/notas', requireAuth, requirePermiso('ccrm'), h(async (req, res) => {
  const { texto } = req.body || {};
  if (!texto || !texto.trim()) return res.status(400).json({ error: 'La nota no puede estar vacía' });
  res.status(201).json(await db.agregarNotaCliente(req.params.id, texto.trim(), req.usuario.id));
}));

// ── CONTABILIDAD ───────────────────────────────────────────────────────
app.get('/api/asientos', requireAuth, requirePermiso('contab'), h(async (req, res) => {
  res.json(await db.listarAsientos());
}));

app.post('/api/asientos', requireAuth, requirePermiso('contab'), h(async (req, res) => {
  const { fecha, descripcion, cuenta, tipo, debe, haber } = req.body || {};
  if (!descripcion) return res.status(400).json({ error: 'Falta la descripción' });
  res.status(201).json(await db.crearAsiento({ fecha, descripcion, cuenta, tipo, debe, haber }, req.usuario.id));
}));

// ── NÓMINA ─────────────────────────────────────────────────────────────
app.get('/api/empleados', requireAuth, requirePermiso('nomina'), h(async (req, res) => {
  res.json(await db.listarEmpleados({ soloActivos: req.query.todos !== '1' }));
}));

app.post('/api/empleados', requireAuth, requirePermiso('nomina'), h(async (req, res) => {
  const { nombre, cedula, codigo, banco, cuenta, cargo, departamento, salario, fechaIngreso } = req.body || {};
  if (!nombre || !salario) return res.status(400).json({ error: 'Nombre y salario son obligatorios' });
  res.status(201).json(await db.crearEmpleado({ nombre, cedula, codigo, banco, cuenta, cargo, departamento, salario, fechaIngreso }));
}));

app.post('/api/empleados/:id/desactivar', requireAuth, requirePermiso('nomina'), h(async (req, res) => {
  await db.desactivarEmpleado(req.params.id);
  res.json({ ok: true });
}));

app.get('/api/nominas', requireAuth, requirePermiso('nomina'), h(async (req, res) => {
  res.json(await db.listarNominas());
}));

app.post('/api/nominas/procesar', requireAuth, requirePermiso('nomina'), h(async (req, res) => {
  const { mes, quincena } = req.body || {};
  if (!mes || !['primera', 'segunda'].includes(quincena)) return res.status(400).json({ error: 'Mes o quincena inválidos' });
  const resultado = await db.procesarNomina({ mes, quincena }, req.usuario.id);
  if (resultado.error) return res.status(400).json({ error: resultado.error });
  res.status(201).json(resultado);
}));

// ── RECURSOS HUMANOS ───────────────────────────────────────────────────
// Tardanzas, faltas, amonestaciones, vacaciones y reclutamiento/período de
// prueba. Exclusivo Gerente/Sub-Gerente por la sensibilidad de los datos
// disciplinarios. Las referencias a artículos del Código de Trabajo son
// solo informativas (ver CODIGO_TRABAJO_REFERENCIA en db.js) -- el
// encargado de RRHH es quien decide e indaga, el sistema no resuelve nada.
app.get('/api/rrhh/empleados', requireAuth, requireRol('gerente', 'subgerente'), h(async (req, res) => {
  res.json(await db.listarEmpleadosRRHH());
}));

app.get('/api/rrhh/codigo-trabajo', requireAuth, requireRol('gerente', 'subgerente'), h(async (req, res) => {
  res.json(db.CODIGO_TRABAJO_REFERENCIA);
}));

app.get('/api/rrhh/deberes-derechos', requireAuth, requireRol('gerente', 'subgerente'), h(async (req, res) => {
  res.json(db.CODIGO_TRABAJO_DEBERES_DERECHOS);
}));

// Plantilla del cuestionario de competencias por puesto -- sin
// respuestas, solo la estructura de preguntas/opciones.
app.get('/api/rrhh/cuestionario/:puesto', requireAuth, requireRol('gerente', 'subgerente'), h(async (req, res) => {
  res.json(db.obtenerCuestionario(req.params.puesto));
}));

app.get('/api/rrhh/incidencias', requireAuth, requireRol('gerente', 'subgerente'), h(async (req, res) => {
  res.json(await db.listarIncidencias(req.query.empleadoId || null));
}));
app.post('/api/rrhh/incidencias', requireAuth, requireRol('gerente', 'subgerente'), h(async (req, res) => {
  const { empleadoId, tipo, fecha, descripcion, articuloReferencia } = req.body || {};
  const TIPOS = ['tardanza', 'falta_justificada', 'falta_injustificada', 'amonestacion', 'bajo_rendimiento', 'mal_manejo', 'observacion', 'evaluacion_desempeno', 'otro'];
  if (!empleadoId || !TIPOS.includes(tipo)) return res.status(400).json({ error: 'Empleado o tipo de incidencia inválidos' });
  res.status(201).json(await db.registrarIncidencia({ empleadoId, tipo, fecha, descripcion, articuloReferencia }, req.usuario.id));
}));

app.get('/api/rrhh/vacaciones/:empleadoId', requireAuth, requireRol('gerente', 'subgerente'), h(async (req, res) => {
  const [resumen, historial] = await Promise.all([
    db.calcularVacaciones(req.params.empleadoId),
    db.listarVacaciones(req.params.empleadoId),
  ]);
  if (!resumen) return res.status(404).json({ error: 'Empleado no encontrado' });
  res.json({ resumen, historial });
}));
app.post('/api/rrhh/vacaciones', requireAuth, requireRol('gerente', 'subgerente'), h(async (req, res) => {
  const { empleadoId, fechaInicio, fechaFin, dias, notas } = req.body || {};
  if (!empleadoId || !fechaInicio || !fechaFin || !dias || Number(dias) <= 0) {
    return res.status(400).json({ error: 'Faltan datos de las vacaciones' });
  }
  res.status(201).json(await db.registrarVacaciones({ empleadoId, fechaInicio, fechaFin, dias, notas }, req.usuario.id));
}));

app.get('/api/rrhh/candidatos', requireAuth, requireRol('gerente', 'subgerente'), h(async (req, res) => {
  res.json(await db.listarCandidatos());
}));
app.post('/api/rrhh/candidatos', requireAuth, requireRol('gerente', 'subgerente'), h(async (req, res) => {
  const datos = req.body || {};
  if (!datos.nombre || !datos.nombre.trim()) return res.status(400).json({ error: 'Falta el nombre del candidato' });
  res.status(201).json(await db.crearCandidato(datos, req.usuario.id));
}));
// Completar/editar la ficha (solicitud de empleo) de un candidato, sin
// tocar su etapa -- eso lo maneja el PATCH de abajo.
app.patch('/api/rrhh/candidatos/:id/perfil', requireAuth, requireRol('gerente', 'subgerente'), h(async (req, res) => {
  const candidato = await db.actualizarPerfilCandidato(req.params.id, req.body || {});
  if (!candidato) return res.status(404).json({ error: 'Candidato no encontrado' });
  res.json(candidato);
}));
app.patch('/api/rrhh/candidatos/:id', requireAuth, requireRol('gerente', 'subgerente'), h(async (req, res) => {
  const { etapa, cargo, salarioBruto, fechaIngreso } = req.body || {};
  const ETAPAS = ['aplicado', 'entrevista', 'prueba', 'fijo', 'rechazado', 'retirado'];
  if (!ETAPAS.includes(etapa)) return res.status(400).json({ error: 'Etapa inválida' });
  const candidato = await db.actualizarEtapaCandidato(req.params.id, etapa, { cargo, salarioBruto, fechaIngreso });
  if (!candidato) return res.status(404).json({ error: 'Candidato no encontrado' });
  res.json(candidato);
}));

// Ficha extendida de un empleado ya contratado (ej. dado de alta directo
// en Nómina, sin pasar por el pipeline de candidatos).
app.patch('/api/rrhh/empleados/:id/perfil', requireAuth, requireRol('gerente', 'subgerente'), h(async (req, res) => {
  const empleado = await db.actualizarPerfilEmpleado(req.params.id, req.body || {});
  if (!empleado) return res.status(404).json({ error: 'Empleado no encontrado' });
  res.json(empleado);
}));

// Cuestionario de competencias respondido -- herramienta de apoyo para
// RRHH, no una decisión automática de contratación (ver disclaimer en
// db.js / CUESTIONARIOS_POR_PUESTO).
app.get('/api/rrhh/evaluaciones', requireAuth, requireRol('gerente', 'subgerente'), h(async (req, res) => {
  if (!req.query.candidatoId) return res.status(400).json({ error: 'Falta candidatoId' });
  res.json(await db.listarEvaluaciones(req.query.candidatoId));
}));
app.post('/api/rrhh/evaluaciones', requireAuth, requireRol('gerente', 'subgerente'), h(async (req, res) => {
  const { candidatoId, puesto, respuestas, notasEvaluador } = req.body || {};
  if (!candidatoId || !puesto || !respuestas || typeof respuestas !== 'object') {
    return res.status(400).json({ error: 'Faltan datos de la evaluación' });
  }
  res.status(201).json(await db.guardarEvaluacion(candidatoId, puesto, respuestas, notasEvaluador, req.usuario.id));
}));

// ── RESPALDO Y RESTAURACIÓN DE LA BASE DE DATOS ───────────────────────
// Exclusivo Gerente/Sub-Gerente -- restaurar sobrescribe TODOS los datos
// actuales con los del respaldo elegido (acción irreversible salvo por
// el respaldo de seguridad automático que se crea justo antes).
app.get('/api/backups', requireAuth, requireRol('gerente', 'subgerente'), h(async (req, res) => {
  res.json(await backup.listarBackups());
}));
app.post('/api/backups', requireAuth, requireRol('gerente', 'subgerente'), h(async (req, res) => {
  const { etiqueta } = req.body || {};
  res.status(201).json(await backup.crearBackup(etiqueta));
}));
app.post('/api/backups/:archivo/restaurar', requireAuth, requireRol('gerente', 'subgerente'), h(async (req, res) => {
  const resultado = await backup.restaurarBackup(req.params.archivo);
  res.json(resultado);
}));

// ── IA (Sarah) — la clave del negocio vive cifrada en el servidor,
// nunca en el navegador (Etapa 6). Cualquier usuario autenticado puede
// chatear con Sarah; solo Gerente/Sub-Gerente administra las claves.
app.get('/api/ia/config', requireAuth, requireRol('gerente', 'subgerente'), h(async (req, res) => {
  res.json(await db.listarConfigIA());
}));
app.post('/api/ia/config', requireAuth, requireRol('gerente', 'subgerente'), h(async (req, res) => {
  const { proveedor, apiKey } = req.body || {};
  if (!['openai', 'gemini', 'claude'].includes(proveedor) || !apiKey) {
    return res.status(400).json({ error: 'Proveedor o clave inválidos' });
  }
  res.json(await db.guardarClaveIA(proveedor, apiKey));
}));
app.post('/api/ia/config/:proveedor/desactivar', requireAuth, requireRol('gerente', 'subgerente'), h(async (req, res) => {
  await db.desactivarClaveIA(req.params.proveedor);
  res.json({ ok: true });
}));

app.post('/api/ia/chat', requireAuth, h(async (req, res) => {
  const { messages, sys } = req.body || {};
  if (!Array.isArray(messages) || !messages.length) return res.status(400).json({ error: 'Faltan mensajes' });
  const resultado = await db.llamarIA(messages, sys || '');
  if (resultado.error) return res.status(502).json({ error: resultado.error });
  res.json({ texto: resultado.texto });
}));

// Límite propio y más grande solo para esta ruta -- una foto de cédula en
// base64 no entra en el límite general de 200kb del resto de la API.
app.post('/api/ia/leer-cedula', requireAuth, express.json({ limit: '8mb' }), h(async (req, res) => {
  const { imagenBase64 } = req.body || {};
  if (!imagenBase64) return res.status(400).json({ error: 'Falta la imagen' });
  const resultado = await db.leerCedulaConIA(imagenBase64);
  if (resultado.error) return res.status(502).json({ error: resultado.error });
  res.json(resultado);
}));

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: 'Error interno del servidor' });
});

const PUERTO = process.env.PORT || 3000;
db.init()
  .then(() => {
    app.listen(PUERTO, () => console.log(`KERPLUS escuchando en el puerto ${PUERTO}`));
  })
  .catch((err) => {
    console.error('No se pudo inicializar la base de datos:', err);
    process.exit(1);
  });
