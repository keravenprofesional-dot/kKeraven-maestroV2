'use strict';

const fs = require('fs');
const path = require('path');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

// Permisos por defecto segun rol (misma tabla que PERMS en el HTML original,
// linea 609 de keraven_maestro_v2_37.html). Un usuario puede tener
// permisos_custom en la base de datos que sobreescribe esta lista por completo
// para ese usuario puntual.
const PERMS_POR_ROL = {
  gerente:     ['dash','contrato','buzon','cobros','arqueo','almp','almm','com','users','cfg','pedidos','nomina','contab','cxp','ccrm','clientes','cxc','miscom','delfac','pagar','rendimiento','asistente','cobrador','ruta','productos'],
  subgerente:  ['dash','contrato','buzon','cobros','arqueo','almp','almm','com','users','cfg','pedidos','nomina','contab','cxp','ccrm','clientes','cxc','miscom','pagar','rendimiento','asistente','cobrador','ruta','productos'],
  coordinador: ['dash','contrato','buzon','cobros','arqueo','almp','com','cfg','pedidos','nomina','contab','cxp','ccrm','clientes','cxc','miscom','pagar','rendimiento','asistente','cobrador','ruta'],
  supervisor:  ['dash','contrato','buzon','cobros','almm','cfg','clientes','cxc','miscom','rendimiento','asistente','cobrador','ruta'],
  almacen:     ['dash','arqueo','almp','almm','cfg','asistente'],
  promotor:    ['dash','contrato','cfg','asistente'],
};

async function init() {
  const schema = fs.readFileSync(path.join(__dirname, 'schema.sql'), 'utf8');
  await pool.query(schema);
  const seedProductos = fs.readFileSync(path.join(__dirname, 'seed_productos.sql'), 'utf8');
  await pool.query(seedProductos);
}

function permisosEfectivos(usuario) {
  if (usuario.permisos_custom && Array.isArray(usuario.permisos_custom)) {
    return usuario.permisos_custom;
  }
  return PERMS_POR_ROL[usuario.rol] || [];
}

// ── USUARIOS / LOGIN ────────────────────────────────────────────────
const MAX_INTENTOS = 5;
const BLOQUEO_MINUTOS = 15;

async function listarUsuariosActivos() {
  const { rows } = await pool.query(
    `SELECT id, nombre, rol, rol_label, color FROM usuarios WHERE activo = TRUE ORDER BY id`
  );
  return rows;
}

async function buscarUsuarioPorId(id) {
  const { rows } = await pool.query(`SELECT * FROM usuarios WHERE id = $1`, [id]);
  return rows[0] || null;
}

// Verifica PIN contra el hash guardado. Aplica limite de intentos: tras
// MAX_INTENTOS fallidos seguidos, bloquea el usuario por BLOQUEO_MINUTOS.
// Esto es lo que reemplaza la comparacion en el navegador (linea 701-707
// del HTML original, "if(pin!==u.pin)") por una verificacion real en el
// servidor.
async function verificarLogin(usuarioId, pin) {
  const usuario = await buscarUsuarioPorId(usuarioId);
  if (!usuario || !usuario.activo) return { ok: false, motivo: 'usuario_no_encontrado' };

  if (usuario.bloqueado_hasta && new Date(usuario.bloqueado_hasta) > new Date()) {
    return { ok: false, motivo: 'bloqueado', bloqueado_hasta: usuario.bloqueado_hasta };
  }

  const coincide = await bcrypt.compare(String(pin), usuario.pin_hash);
  if (!coincide) {
    const intentos = usuario.intentos_fallidos + 1;
    if (intentos >= MAX_INTENTOS) {
      const bloqueadoHasta = new Date(Date.now() + BLOQUEO_MINUTOS * 60 * 1000);
      await pool.query(
        `UPDATE usuarios SET intentos_fallidos = 0, bloqueado_hasta = $2 WHERE id = $1`,
        [usuarioId, bloqueadoHasta]
      );
      return { ok: false, motivo: 'bloqueado', bloqueado_hasta: bloqueadoHasta };
    }
    await pool.query(`UPDATE usuarios SET intentos_fallidos = $2 WHERE id = $1`, [usuarioId, intentos]);
    return { ok: false, motivo: 'pin_incorrecto' };
  }

  await pool.query(
    `UPDATE usuarios SET intentos_fallidos = 0, bloqueado_hasta = NULL WHERE id = $1`,
    [usuarioId]
  );
  return { ok: true, usuario };
}

async function crearUsuario({ nombre, rol, rolLabel, pin, color }) {
  const pinHash = await bcrypt.hash(String(pin), 10);
  const { rows } = await pool.query(
    `INSERT INTO usuarios (nombre, rol, rol_label, pin_hash, color)
     VALUES ($1,$2,$3,$4,$5) RETURNING id, nombre, rol, rol_label, color, activo`,
    [nombre, rol, rolLabel, pinHash, color || '#B8860B']
  );
  return rows[0];
}

async function cambiarPinUsuario(id, nuevoPin) {
  const pinHash = await bcrypt.hash(String(nuevoPin), 10);
  await pool.query(`UPDATE usuarios SET pin_hash = $2 WHERE id = $1`, [id, pinHash]);
}

async function actualizarPermisosUsuario(id, permisos) {
  await pool.query(`UPDATE usuarios SET permisos_custom = $2 WHERE id = $1`, [
    id,
    permisos ? JSON.stringify(permisos) : null,
  ]);
}

async function desactivarUsuario(id) {
  await pool.query(`UPDATE usuarios SET activo = FALSE WHERE id = $1`, [id]);
}
async function reactivarUsuario(id) {
  await pool.query(`UPDATE usuarios SET activo = TRUE WHERE id = $1`, [id]);
}

// ── PRODUCTOS (catalogo editable) ────────────────────────────────────
async function listarProductos({ soloActivos = true } = {}) {
  const { rows } = await pool.query(
    `SELECT * FROM productos ${soloActivos ? 'WHERE activo = TRUE' : ''} ORDER BY categoria, nombre`
  );
  return rows;
}

async function crearProducto({ nombre, precioReferencia, categoria }) {
  const { rows } = await pool.query(
    `INSERT INTO productos (nombre, precio_referencia, categoria) VALUES ($1,$2,$3)
     RETURNING *`,
    [nombre, precioReferencia || 0, categoria || 'Otros']
  );
  // nuevo producto arranca con stock 0 en bodega y ruta
  await pool.query(
    `INSERT INTO almacen_stock (producto_id, ubicacion, cantidad) VALUES ($1,'bodega',0),($1,'ruta',0)
     ON CONFLICT (producto_id, ubicacion) DO NOTHING`,
    [rows[0].id]
  );
  return rows[0];
}

async function actualizarProducto(id, { nombre, precioReferencia, categoria }) {
  const { rows } = await pool.query(
    `UPDATE productos SET
       nombre = COALESCE($2, nombre),
       precio_referencia = COALESCE($3, precio_referencia),
       categoria = COALESCE($4, categoria)
     WHERE id = $1 RETURNING *`,
    [id, nombre, precioReferencia, categoria]
  );
  return rows[0] || null;
}

async function desactivarProducto(id) {
  await pool.query(`UPDATE productos SET activo = FALSE WHERE id = $1`, [id]);
}
async function reactivarProducto(id) {
  await pool.query(`UPDATE productos SET activo = TRUE WHERE id = $1`, [id]);
}

module.exports = {
  pool,
  init,
  PERMS_POR_ROL,
  permisosEfectivos,
  listarUsuariosActivos,
  buscarUsuarioPorId,
  verificarLogin,
  crearUsuario,
  cambiarPinUsuario,
  actualizarPermisosUsuario,
  desactivarUsuario,
  reactivarUsuario,
  listarProductos,
  crearProducto,
  actualizarProducto,
  desactivarProducto,
  reactivarProducto,
};
