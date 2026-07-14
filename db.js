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

// Lista completa para el panel de administracion (incluye inactivos, sin pin_hash)
async function listarUsuariosCompleto() {
  const { rows } = await pool.query(
    `SELECT id, nombre, rol, rol_label, color, activo, editable, permisos_custom
     FROM usuarios ORDER BY id`
  );
  return rows;
}

async function actualizarUsuario(id, { nombre, rol, rolLabel }) {
  const { rows } = await pool.query(
    `UPDATE usuarios SET
       nombre = COALESCE($2, nombre),
       rol = COALESCE($3, rol),
       rol_label = COALESCE($4, rol_label)
     WHERE id = $1
     RETURNING id, nombre, rol, rol_label, color, activo, editable, permisos_custom`,
    [id, nombre, rol, rolLabel]
  );
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

// ── CLIENTES ──────────────────────────────────────────────────────
// Busca por cedula (si viene) y reusa; si no existe, crea uno nuevo.
// Es lo que permite que Facturacion y Cobrador compartan el mismo
// cliente en vez de tener copias sueltas como en el HTML original.
async function resolverCliente(datos) {
  const cedula = (datos.cedula || '').trim();
  if (cedula) {
    const existente = await pool.query(`SELECT id FROM clientes WHERE cedula = $1`, [cedula]);
    if (existente.rows[0]) return existente.rows[0].id;
  }
  const { rows } = await pool.query(
    `INSERT INTO clientes (cedula, nombre, telefono1, telefono2, email, institucion, barrio, referencia, direccion, zona)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING id`,
    [cedula || null, datos.nombre, datos.telefono1 || null, datos.telefono2 || null, datos.email || null,
     datos.institucion || null, datos.barrio || null, datos.referencia || null, datos.direccion || null, datos.zona || null]
  );
  return rows[0].id;
}

// ── CONTRATOS / FACTURACION ──────────────────────────────────────
// Numeracion atomica -- UPDATE...RETURNING, nunca MAX()+1 (mismo
// patron que la tabla `contadores` de Seguimiento de Almas).
async function siguienteNumeroFactura() {
  const { rows } = await pool.query(
    `UPDATE contadores SET valor = valor + 1 WHERE clave = 'factura' RETURNING valor`
  );
  return 'KRV-' + String(rows[0].valor).padStart(4, '0');
}

async function crearContrato(datos, usuarioId) {
  const cliente = await pool.connect();
  try {
    await cliente.query('BEGIN');
    const clienteId = await resolverCliente(datos);
    const numeroFactura = (datos.fac && datos.fac.trim()) || (await siguienteNumeroFactura());
    const neto = (Number(datos.monto) || 0) - (Number(datos.descuento) || 0);
    const { rows } = await cliente.query(
      `INSERT INTO contratos (numero_factura, fecha, cliente_id, promotor_id, promotor_nombre, zona, canal,
         tipo_venta, plazo_dias, fecha_limite, monto, descuento, neto, saldo, observaciones,
         foto_frente_url, foto_reverso_url, foto_factura_url, gps_lat, gps_lng, gps_plus_code, gps_precision_m,
         estado, origen, creado_por)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,'pendiente',$23,$24)
       RETURNING *`,
      [numeroFactura, datos.fecha || new Date().toISOString().slice(0, 10), clienteId,
       datos.promotorId || null, datos.promotorNombre || null, datos.zona || null, datos.canal || 'ruta',
       datos.tipoVenta, datos.plazoDias || null, datos.fechaLimite || null,
       Number(datos.monto) || 0, Number(datos.descuento) || 0, neto, Number(datos.monto) || 0,
       datos.observaciones || null, datos.fotoFrenteUrl || null, datos.fotoReversoUrl || null,
       datos.fotoFacturaUrl || null, datos.gpsLat || null, datos.gpsLng || null,
       datos.gpsPlusCode || null, datos.gpsPrecisionM || null, datos.origen || 'manual', usuarioId]
    );
    const contrato = rows[0];
    for (const nombreProducto of datos.productos || []) {
      const p = await cliente.query(`SELECT id FROM productos WHERE nombre = $1`, [nombreProducto]);
      if (p.rows[0]) {
        await cliente.query(
          `INSERT INTO contrato_productos (contrato_id, producto_id, cantidad) VALUES ($1,$2,1)`,
          [contrato.id, p.rows[0].id]
        );
      }
    }
    await cliente.query('COMMIT');
    return contrato;
  } catch (err) {
    await cliente.query('ROLLBACK');
    throw err;
  } finally {
    cliente.release();
  }
}

async function listarContratos({ estado } = {}) {
  const { rows } = await pool.query(
    `SELECT c.*, cl.nombre AS cliente_nombre, cl.cedula AS cliente_cedula,
            cl.telefono1 AS cliente_tel1, cl.telefono2 AS cliente_tel2,
            cl.institucion AS cliente_institucion, cl.barrio AS cliente_barrio,
            cl.referencia AS cliente_referencia, cl.direccion AS cliente_direccion,
            COALESCE(
              (SELECT json_agg(p.nombre) FROM contrato_productos cp
               JOIN productos p ON p.id = cp.producto_id WHERE cp.contrato_id = c.id), '[]'
            ) AS productos,
            COALESCE(
              (SELECT json_agg(json_build_object(
                 'id',a.id,'fecha',a.fecha,'monto',a.monto,'via',a.via,'nota',a.nota,
                 'registrado_por_nombre',u.nombre
               ) ORDER BY a.fecha)
               FROM contrato_abonos a LEFT JOIN usuarios u ON u.id = a.registrado_por
               WHERE a.contrato_id = c.id), '[]'
            ) AS abonos
     FROM contratos c
     JOIN clientes cl ON cl.id = c.cliente_id
     ${estado ? 'WHERE c.estado = $1' : ''}
     ORDER BY c.creado_en DESC`,
    estado ? [estado] : []
  );
  return rows;
}

const MESES = ['Enero','Febrero','Marzo','Abril','Mayo','Junio','Julio','Agosto','Septiembre','Octubre','Noviembre','Diciembre'];

// Aprobar/rechazar. Al aprobar, genera automaticamente la semana de
// comision (mismo comportamiento que decidir() en el HTML original,
// linea 1585-1625, pero hecho en el servidor y en una transaccion).
async function decidirContrato(id, decision, comentario, usuarioId, usuarioNombre) {
  const cliente = await pool.connect();
  try {
    await cliente.query('BEGIN');
    const { rows } = await cliente.query(
      `UPDATE contratos SET estado = $2, decidido_por = $3, decidido_en = now()
       WHERE id = $1 RETURNING *`,
      [id, decision, usuarioId]
    );
    const contrato = rows[0];
    if (!contrato) { await cliente.query('ROLLBACK'); return null; }

    if (decision === 'aprobado' && contrato.promotor_id) {
      const ya = await cliente.query(
        `SELECT id FROM comisiones_semanas WHERE contrato_id = $1`, [id]
      );
      if (!ya.rows[0]) {
        const fecha = contrato.fecha;
        const mesNom = MESES[new Date(fecha).getMonth()] + ' ' + new Date(fecha).getFullYear();
        const monto = Number(contrato.monto) || 0;
        const esCredito = contrato.tipo_venta === 'credito';
        const c8 = esCredito ? Math.round(monto * 0.08) : 0;
        const c16 = esCredito ? 0 : Math.round(monto * 0.16);
        const total = c8 + c16;
        const semana = await cliente.query(
          `INSERT INTO comisiones_semanas (fecha_desde, fecha_hasta, mes_pago, automatica, contrato_id,
             factura_texto, tipo_venta, monto_venta, total, pagado, registrado_por)
           VALUES ($1,$1,$2,TRUE,$3,$4,$5,$6,$7,FALSE,$8) RETURNING id`,
          [fecha, mesNom, id, contrato.numero_factura, contrato.tipo_venta, monto, total, usuarioId]
        );
        await cliente.query(
          `INSERT INTO comisiones_semana_promotores (semana_id, promotor_nombre, venta_credito, venta_contado, comision_8, comision_16, total)
           VALUES ($1,$2,$3,$4,$5,$6,$7)`,
          [semana.rows[0].id, contrato.promotor_nombre || '', esCredito ? monto : 0, esCredito ? 0 : monto, c8, c16, total]
        );
      }
    }
    await cliente.query('COMMIT');
    return contrato;
  } catch (err) {
    await cliente.query('ROLLBACK');
    throw err;
  } finally {
    cliente.release();
  }
}

// Registra un abono contra un contrato (usado por Cobros, Ruta y
// Cobrador -- mismo endpoint para los 3). FOR UPDATE evita que dos
// cobros simultaneos sobre el mismo contrato se pisen el saldo.
// monto=0 es valido (ej. "No pagó" -- deja una visita en el
// historial sin afectar el saldo); solo se rechaza si es negativo.
async function registrarAbonoContrato(contratoId, monto, { via, nota }, usuarioId) {
  const cliente = await pool.connect();
  try {
    await cliente.query('BEGIN');
    const { rows } = await cliente.query(
      `SELECT saldo FROM contratos WHERE id = $1 FOR UPDATE`, [contratoId]
    );
    if (!rows[0]) { await cliente.query('ROLLBACK'); return null; }
    const deuda = Math.max(0, Number(rows[0].saldo) || 0);
    const m = Math.max(0, Math.min(Number(monto) || 0, deuda));

    await cliente.query(
      `INSERT INTO contrato_abonos (contrato_id, monto, via, nota, registrado_por) VALUES ($1,$2,$3,$4,$5)`,
      [contratoId, m, via || 'manual', nota || '', usuarioId]
    );
    const { rows: actualizado } = m > 0
      ? await cliente.query(`UPDATE contratos SET saldo = saldo - $2 WHERE id = $1 RETURNING *`, [contratoId, m])
      : await cliente.query(`SELECT * FROM contratos WHERE id = $1`, [contratoId]);
    await cliente.query('COMMIT');
    return actualizado[0];
  } catch (err) {
    await cliente.query('ROLLBACK');
    throw err;
  } finally {
    cliente.release();
  }
}

module.exports = {
  pool,
  init,
  PERMS_POR_ROL,
  permisosEfectivos,
  listarUsuariosActivos,
  listarUsuariosCompleto,
  actualizarUsuario,
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
  resolverCliente,
  siguienteNumeroFactura,
  crearContrato,
  listarContratos,
  decidirContrato,
  registrarAbonoContrato,
};
