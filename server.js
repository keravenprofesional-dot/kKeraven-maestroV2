'use strict';

require('dotenv').config();
const path = require('path');
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const session = require('express-session');
const pgSession = require('connect-pg-simple')(session);

const db = require('./db');

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

const limiteLogin = rateLimit({ windowMs: 15 * 60 * 1000, max: 15, standardHeaders: true, legacyHeaders: false });
const limiteApi = rateLimit({ windowMs: 15 * 60 * 1000, max: 600, standardHeaders: true, legacyHeaders: false });
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
    const usuario = await db.buscarUsuarioPorId(req.session.usuarioId);
    if (!usuario || !usuario.activo) return res.status(401).json({ error: 'No autenticado' });
    const permisos = db.permisosEfectivos(usuario);
    if (!permisos.includes(modulo)) return res.status(403).json({ error: 'Sin permiso para este módulo' });
    req.usuario = usuario;
    next();
  };
}

function requireAnyPermiso(...modulos) {
  return async (req, res, next) => {
    const usuario = await db.buscarUsuarioPorId(req.session.usuarioId);
    if (!usuario || !usuario.activo) return res.status(401).json({ error: 'No autenticado' });
    const permisos = db.permisosEfectivos(usuario);
    if (!modulos.some((m) => permisos.includes(m))) return res.status(403).json({ error: 'Sin permiso para este módulo' });
    req.usuario = usuario;
    next();
  };
}

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

app.post('/api/productos', requireAuth, requirePermiso('productos'), h(async (req, res) => {
  const { nombre, precioReferencia, categoria } = req.body || {};
  if (!nombre) return res.status(400).json({ error: 'Falta el nombre del producto' });
  res.status(201).json(await db.crearProducto({ nombre, precioReferencia, categoria }));
}));

app.patch('/api/productos/:id', requireAuth, requirePermiso('productos'), h(async (req, res) => {
  const { nombre, precioReferencia, categoria } = req.body || {};
  const actualizado = await db.actualizarProducto(req.params.id, { nombre, precioReferencia, categoria });
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

// ── CONTRATOS / FACTURACIÓN ───────────────────────────────────────────
app.get('/api/contratos', requireAuth, requireAnyPermiso('contrato', 'buzon', 'cobros'), h(async (req, res) => {
  res.json(await db.listarContratos({ estado: req.query.estado }));
}));

app.post('/api/contratos', requireAuth, requirePermiso('contrato'), h(async (req, res) => {
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
  res.json(contrato);
}));

app.post('/api/contratos/:id/abonar', requireAuth, requireAnyPermiso('cobros', 'cobrador', 'ruta'), h(async (req, res) => {
  const { monto, via, nota } = req.body || {};
  if (monto == null || Number(monto) < 0) return res.status(400).json({ error: 'Monto inválido' });
  const contrato = await db.registrarAbonoContrato(req.params.id, monto, { via, nota }, req.usuario.id);
  if (!contrato) return res.status(404).json({ error: 'Contrato no encontrado' });
  res.json(contrato);
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
