'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

// Permisos por defecto segun rol (misma tabla que PERMS en el HTML original,
// linea 609 de keraven_maestro_v2_37.html). Un usuario puede tener
// permisos_custom en la base de datos que sobreescribe esta lista por completo
// para ese usuario puntual.
const PERMS_POR_ROL = {
  gerente:     ['dash','contrato','buzon','cobros','arqueo','almp','almm','com','users','cfg','pedidos','nomina','contab','cxp','ccrm','clientes','cxc','miscom','delfac','pagar','rendimiento','asistente','cobrador','ruta','productos','laboratorio','laboratorio_produccion','excel'],
  subgerente:  ['dash','contrato','buzon','cobros','arqueo','almp','almm','com','users','cfg','pedidos','nomina','contab','cxp','ccrm','clientes','cxc','miscom','pagar','rendimiento','asistente','cobrador','ruta','productos','laboratorio','laboratorio_produccion','excel'],
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
  const seedLab = fs.readFileSync(path.join(__dirname, 'seed_lab_materias_primas.sql'), 'utf8');
  await pool.query(seedLab);
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

// ── RUTA CON MAPA: selección manual de la ruta del día ────────────────
// Busca contratos aprobados con saldo pendiente por factura, cédula,
// teléfono o nombre del cliente -- lo que gerente/supervisor usan para
// armar a mano la ruta de hoy (ya no se arma sola con todo lo que tenga GPS).
async function buscarContratosParaRuta(q) {
  const texto = `%${String(q || '').trim()}%`;
  const { rows } = await pool.query(
    `SELECT c.id, c.numero_factura, c.saldo, c.fecha_limite, c.gps_lat, c.gps_lng,
            cl.nombre AS cliente_nombre, cl.cedula AS cliente_cedula,
            cl.telefono1 AS cliente_tel1, cl.direccion AS cliente_direccion,
            cl.referencia AS cliente_referencia, cl.institucion AS cliente_institucion,
            (rs.id IS NOT NULL) AS ya_en_ruta_hoy
     FROM contratos c
     JOIN clientes cl ON cl.id = c.cliente_id
     LEFT JOIN ruta_seleccion rs ON rs.contrato_id = c.id AND rs.fecha = CURRENT_DATE
     WHERE c.estado = 'aprobado' AND c.saldo > 0
       AND (c.numero_factura ILIKE $1 OR cl.cedula ILIKE $1 OR cl.telefono1 ILIKE $1
            OR cl.telefono2 ILIKE $1 OR cl.nombre ILIKE $1)
     ORDER BY cl.nombre
     LIMIT 30`,
    [texto]
  );
  return rows;
}

async function listarRutaSeleccionHoy() {
  const { rows } = await pool.query(
    `SELECT rs.id AS seleccion_id, rs.estado, rs.monto_resultado, rs.nota, rs.visitado_en,
            c.id AS contrato_id, c.numero_factura, c.saldo, c.fecha_limite, c.gps_lat, c.gps_lng,
            cl.nombre AS cliente_nombre, cl.telefono1 AS cliente_tel1,
            cl.direccion AS cliente_direccion, cl.referencia AS cliente_referencia,
            cl.institucion AS cliente_institucion
     FROM ruta_seleccion rs
     JOIN contratos c ON c.id = rs.contrato_id
     JOIN clientes cl ON cl.id = c.cliente_id
     WHERE rs.fecha = CURRENT_DATE
     ORDER BY rs.creado_en`
  );
  return rows;
}

// Si el contrato no tenía GPS, se lo completa aquí (sin pisar uno que ya
// exista) para que la próxima vez ya no falte.
async function agregarARutaSeleccion(contratoId, usuarioId, gpsLat, gpsLng) {
  if (gpsLat != null && gpsLng != null) {
    await pool.query(
      `UPDATE contratos SET gps_lat = $2, gps_lng = $3
       WHERE id = $1 AND gps_lat IS NULL`,
      [contratoId, gpsLat, gpsLng]
    );
  }
  const { rows } = await pool.query(
    `INSERT INTO ruta_seleccion (contrato_id, agregado_por)
     VALUES ($1, $2)
     ON CONFLICT (contrato_id, fecha) DO NOTHING
     RETURNING id`,
    [contratoId, usuarioId]
  );
  return rows[0] || null;
}

async function quitarDeRutaSeleccion(seleccionId) {
  await pool.query(`DELETE FROM ruta_seleccion WHERE id = $1 AND fecha = CURRENT_DATE`, [seleccionId]);
}

async function actualizarEstadoRuta(seleccionId, estado, montoResultado, nota) {
  const { rows } = await pool.query(
    `UPDATE ruta_seleccion SET estado = $2, monto_resultado = $3, nota = $4, visitado_en = now()
     WHERE id = $1 RETURNING *`,
    [seleccionId, estado, montoResultado ?? null, nota || null]
  );
  return rows[0] || null;
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

    if (decision === 'aprobado' && contrato.promotor_nombre && Number(contrato.monto) > 0) {
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

// Edita los datos del cliente de un contrato ya aprobado. Como
// contratos.cliente_id apunta a la tabla `clientes` compartida con
// CRM/Cobrador, esto actualiza el cliente real -- el cambio se ve
// automaticamente en todos los modulos que lo referencian, no solo en
// este contrato. Exclusivo Gerente/Sub-Gerente (ver requireRol en la
// ruta). El motivo de la correccion queda en contratos.observaciones.
async function editarClienteDeContrato(contratoId, datosCliente, motivo) {
  const cliente = await pool.connect();
  try {
    await cliente.query('BEGIN');
    const { rows } = await cliente.query(`SELECT cliente_id FROM contratos WHERE id = $1 FOR UPDATE`, [contratoId]);
    if (!rows[0]) { await cliente.query('ROLLBACK'); return null; }
    await cliente.query(
      `UPDATE clientes SET
         nombre = $2, cedula = $3, telefono1 = $4, telefono2 = $5, email = $6,
         institucion = $7, barrio = $8, referencia = $9, direccion = $10
       WHERE id = $1`,
      [rows[0].cliente_id, datosCliente.nombre, datosCliente.cedula, datosCliente.telefono1 || null,
       datosCliente.telefono2 || null, datosCliente.email || null, datosCliente.institucion || null,
       datosCliente.barrio || null, datosCliente.referencia || null, datosCliente.direccion || null]
    );
    const { rows: actualizado } = await cliente.query(
      `UPDATE contratos SET observaciones = $2 WHERE id = $1 RETURNING *`,
      [contratoId, motivo || null]
    );
    await cliente.query('COMMIT');
    return actualizado[0];
  } catch (err) {
    await cliente.query('ROLLBACK');
    throw err;
  } finally {
    cliente.release();
  }
}

// Elimina una factura por completo (accion irreversible, solo
// Gerente/Sub-Gerente, con PIN reverificado en la ruta). Tambien
// elimina la comision automatica asociada, si la tiene -- mismo
// comportamiento que decidir() en el HTML original.
async function eliminarContrato(id) {
  const cliente = await pool.connect();
  try {
    await cliente.query('BEGIN');
    const { rows } = await cliente.query(`SELECT numero_factura FROM contratos WHERE id = $1 FOR UPDATE`, [id]);
    if (!rows[0]) { await cliente.query('ROLLBACK'); return null; }
    await cliente.query(`DELETE FROM comisiones_semanas WHERE contrato_id = $1`, [id]);
    await cliente.query(`DELETE FROM contratos WHERE id = $1`, [id]);
    await cliente.query('COMMIT');
    return { numeroFactura: rows[0].numero_factura };
  } catch (err) {
    await cliente.query('ROLLBACK');
    throw err;
  } finally {
    cliente.release();
  }
}

// Edita los datos OPERATIVOS de cobranza de un contrato (telefono2 del
// cliente, fecha limite, promesa de pago y notas de gestion). A
// diferencia de editarClienteDeContrato (identidad del cliente, solo
// Gerente/Sub-Gerente), esto lo puede hacer cualquiera con acceso a
// Cobrador/Cobros/Ruta -- es trabajo diario de cobranza, no una
// correccion de datos de facturacion. Nunca toca monto ni saldo: eso
// solo cambia via registrarAbonoContrato, para que el historial de
// abonos siempre cuadre con la deuda.
async function editarDatosCobranza(contratoId, { telefono2, fechaLimite, promesaPago, notas }) {
  const cliente = await pool.connect();
  try {
    await cliente.query('BEGIN');
    const { rows } = await cliente.query(`SELECT cliente_id FROM contratos WHERE id = $1 FOR UPDATE`, [contratoId]);
    if (!rows[0]) { await cliente.query('ROLLBACK'); return null; }
    await cliente.query(`UPDATE clientes SET telefono2 = $2 WHERE id = $1`, [rows[0].cliente_id, telefono2 || null]);
    const { rows: actualizado } = await cliente.query(
      `UPDATE contratos SET fecha_limite = $2, promesa_pago = $3, observaciones = $4 WHERE id = $1 RETURNING *`,
      [contratoId, fechaLimite || null, promesaPago || null, notas || null]
    );
    await cliente.query('COMMIT');
    return actualizado[0];
  } catch (err) {
    await cliente.query('ROLLBACK');
    throw err;
  } finally {
    cliente.release();
  }
}

// Crea un contrato "legado" a partir de un cliente que ya existia en el
// Cobrador antes de que este se conectara a la base de datos real (ver
// CB_DATOS_INICIALES en public/index.html). Se usa una sola vez por
// numero de factura -- si ya existe, no duplica. A diferencia de
// crearContrato() no exige cedula/promotor/productos porque esta deuda
// ya existia y no tiene esos datos; queda marcada origen='cobrador'.
async function crearContratoLegacyCobrador(datos, usuarioId) {
  const cliente = await pool.connect();
  try {
    await cliente.query('BEGIN');
    const { rows: existe } = await cliente.query(
      `SELECT id FROM contratos WHERE numero_factura = $1 FOR UPDATE`,
      [datos.numeroFactura]
    );
    if (existe[0]) { await cliente.query('ROLLBACK'); return null; }
    const { rows: clienteRows } = await cliente.query(
      `INSERT INTO clientes (nombre, telefono1, telefono2) VALUES ($1, $2, $3) RETURNING id`,
      [datos.nombre, datos.telefono1 || null, datos.telefono2 || null]
    );
    const monto = Number(datos.monto) || 0;
    const saldo = datos.saldo != null ? Number(datos.saldo) : monto;
    const { rows: contratoRows } = await cliente.query(
      `INSERT INTO contratos
         (numero_factura, cliente_id, promotor_nombre, tipo_venta, fecha_limite, promesa_pago,
          monto, neto, saldo, observaciones, estado, origen, creado_por, decidido_por, decidido_en)
       VALUES ($1, $2, 'Cobrador (migración)', 'credito', $3, $4, $5, $5, $6, $7, 'aprobado', 'cobrador', $8, $8, now())
       RETURNING *`,
      [datos.numeroFactura, clienteRows[0].id, datos.fechaLimite || null, datos.promesaPago || null,
       monto, saldo, datos.notas || null, usuarioId]
    );
    await cliente.query('COMMIT');
    return contratoRows[0];
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

// ── ALMACEN (bodega + ruta) ──────────────────────────────────────────
// Devuelve, por producto, su stock en bodega y en ruta -- forma facil
// de reconstruir los diccionarios almP/almM que ya usa el frontend.
async function listarStock() {
  const { rows } = await pool.query(
    `SELECT p.nombre,
            COALESCE(MAX(s.cantidad) FILTER (WHERE s.ubicacion = 'bodega'), 0) AS bodega,
            COALESCE(MAX(s.cantidad) FILTER (WHERE s.ubicacion = 'ruta'), 0) AS ruta
     FROM productos p
     LEFT JOIN almacen_stock s ON s.producto_id = p.id
     WHERE p.activo = TRUE
     GROUP BY p.nombre
     ORDER BY p.nombre`
  );
  return rows;
}

async function registrarEntradaAlmacen({ proveedor, items }, usuarioId) {
  const cliente = await pool.connect();
  try {
    await cliente.query('BEGIN');
    const { rows } = await cliente.query(
      `INSERT INTO almacen_entradas (proveedor, registrado_por) VALUES ($1,$2) RETURNING id`,
      [proveedor || 'Sin especificar', usuarioId]
    );
    const entradaId = rows[0].id;
    for (const { nombre, cantidad } of items) {
      const p = await cliente.query(`SELECT id FROM productos WHERE nombre = $1`, [nombre]);
      if (!p.rows[0] || cantidad <= 0) continue;
      await cliente.query(
        `INSERT INTO almacen_entrada_items (entrada_id, producto_id, cantidad) VALUES ($1,$2,$3)`,
        [entradaId, p.rows[0].id, cantidad]
      );
      await cliente.query(
        `UPDATE almacen_stock SET cantidad = cantidad + $2 WHERE producto_id = $1 AND ubicacion = 'bodega'`,
        [p.rows[0].id, cantidad]
      );
    }
    await cliente.query('COMMIT');
    return { id: entradaId };
  } catch (err) {
    await cliente.query('ROLLBACK');
    throw err;
  } finally {
    cliente.release();
  }
}

async function listarEntradasAlmacen() {
  const { rows } = await pool.query(
    `SELECT e.id, e.fecha, e.proveedor, u.nombre AS registrado_por_nombre,
            COALESCE(
              (SELECT json_agg(json_build_object('nombre',p.nombre,'cantidad',ei.cantidad))
               FROM almacen_entrada_items ei JOIN productos p ON p.id = ei.producto_id
               WHERE ei.entrada_id = e.id), '[]'
            ) AS items
     FROM almacen_entradas e
     LEFT JOIN usuarios u ON u.id = e.registrado_por
     ORDER BY e.creado_en DESC`
  );
  return rows;
}

// tipo: 'venta' (descuenta de ruta) | 'carga' (bodega -> ruta)
async function registrarMovimientoAlmacen({ tipo, clienteTexto, items }, usuarioId) {
  const cliente = await pool.connect();
  try {
    await cliente.query('BEGIN');
    // Validar stock suficiente ANTES de mover nada (con lock de fila)
    for (const { nombre, cantidad } of items) {
      const p = await cliente.query(`SELECT id FROM productos WHERE nombre = $1`, [nombre]);
      if (!p.rows[0]) continue;
      const origen = tipo === 'venta' ? 'ruta' : 'bodega';
      const stock = await cliente.query(
        `SELECT cantidad FROM almacen_stock WHERE producto_id = $1 AND ubicacion = $2 FOR UPDATE`,
        [p.rows[0].id, origen]
      );
      if (!stock.rows[0] || Number(stock.rows[0].cantidad) < cantidad) {
        await cliente.query('ROLLBACK');
        return { error: `Stock insuficiente: ${nombre}` };
      }
    }
    const { rows } = await cliente.query(
      `INSERT INTO almacen_movimientos (tipo, cliente_texto, registrado_por) VALUES ($1,$2,$3) RETURNING id`,
      [tipo, clienteTexto || null, usuarioId]
    );
    const movId = rows[0].id;
    for (const { nombre, cantidad } of items) {
      if (cantidad <= 0) continue;
      const p = await cliente.query(`SELECT id FROM productos WHERE nombre = $1`, [nombre]);
      if (!p.rows[0]) continue;
      await cliente.query(
        `INSERT INTO almacen_movimiento_items (movimiento_id, producto_id, cantidad) VALUES ($1,$2,$3)`,
        [movId, p.rows[0].id, cantidad]
      );
      if (tipo === 'venta') {
        await cliente.query(
          `UPDATE almacen_stock SET cantidad = cantidad - $2 WHERE producto_id = $1 AND ubicacion = 'ruta'`,
          [p.rows[0].id, cantidad]
        );
      } else {
        await cliente.query(
          `UPDATE almacen_stock SET cantidad = cantidad - $2 WHERE producto_id = $1 AND ubicacion = 'bodega'`,
          [p.rows[0].id, cantidad]
        );
        await cliente.query(
          `UPDATE almacen_stock SET cantidad = cantidad + $2 WHERE producto_id = $1 AND ubicacion = 'ruta'`,
          [p.rows[0].id, cantidad]
        );
      }
    }
    await cliente.query('COMMIT');
    return { id: movId };
  } catch (err) {
    await cliente.query('ROLLBACK');
    throw err;
  } finally {
    cliente.release();
  }
}

// ── COMISIONES ────────────────────────────────────────────────────
async function listarComisionesSemanas() {
  const { rows } = await pool.query(
    `SELECT s.*,
            COALESCE(
              (SELECT json_agg(json_build_object(
                 'nombre',sp.promotor_nombre,'vc',sp.venta_credito,'vo',sp.venta_contado,
                 'c8',sp.comision_8,'c16',sp.comision_16,'tot',sp.total
               ))
               FROM comisiones_semana_promotores sp WHERE sp.semana_id = s.id), '[]'
            ) AS promotores
     FROM comisiones_semanas s
     ORDER BY s.creado_en DESC`
  );
  return rows;
}

async function crearSemanaComisionManual({ fechaDesde, fechaHasta, mesPago, promotores }, usuarioId) {
  const cliente = await pool.connect();
  try {
    await cliente.query('BEGIN');
    const total = promotores.reduce((s, p) => s + (Number(p.c8) || 0) + (Number(p.c16) || 0), 0);
    const { rows } = await cliente.query(
      `INSERT INTO comisiones_semanas (fecha_desde, fecha_hasta, mes_pago, automatica, total, pagado, registrado_por)
       VALUES ($1,$2,$3,FALSE,$4,FALSE,$5) RETURNING id`,
      [fechaDesde, fechaHasta || fechaDesde, mesPago || null, total, usuarioId]
    );
    const semanaId = rows[0].id;
    for (const p of promotores) {
      const c8 = Math.round((Number(p.venta_credito) || 0) * 0.08);
      const c16 = Math.round((Number(p.venta_contado) || 0) * 0.16);
      if (c8 + c16 <= 0) continue;
      await cliente.query(
        `INSERT INTO comisiones_semana_promotores (semana_id, promotor_nombre, venta_credito, venta_contado, comision_8, comision_16, total)
         VALUES ($1,$2,$3,$4,$5,$6,$7)`,
        [semanaId, p.nombre, Number(p.venta_credito) || 0, Number(p.venta_contado) || 0, c8, c16, c8 + c16]
      );
    }
    await cliente.query('COMMIT');
    return { id: semanaId };
  } catch (err) {
    await cliente.query('ROLLBACK');
    throw err;
  } finally {
    cliente.release();
  }
}

async function marcarComisionesSemanasPagadas(usuarioId) {
  const cliente = await pool.connect();
  try {
    await cliente.query('BEGIN');
    const pendientes = await cliente.query(
      `SELECT id, total, mes_pago FROM comisiones_semanas WHERE pagado = FALSE FOR UPDATE`
    );
    if (!pendientes.rows.length) { await cliente.query('ROLLBACK'); return null; }
    const total = pendientes.rows.reduce((s, r) => s + Number(r.total), 0);
    const meses = [...new Set(pendientes.rows.map((r) => r.mes_pago).filter(Boolean))].join(', ');
    await cliente.query(`UPDATE comisiones_semanas SET pagado = TRUE WHERE pagado = FALSE`);
    const pago = await cliente.query(
      `INSERT INTO comisiones_pagos (mes, cantidad_semanas, total, registrado_por) VALUES ($1,$2,$3,$4) RETURNING *`,
      [meses, pendientes.rows.length, total, usuarioId]
    );
    await cliente.query('COMMIT');
    return pago.rows[0];
  } catch (err) {
    await cliente.query('ROLLBACK');
    throw err;
  } finally {
    cliente.release();
  }
}

async function listarComisionesPagos() {
  const { rows } = await pool.query(
    `SELECT p.*, u.nombre AS registrado_por_nombre FROM comisiones_pagos p
     LEFT JOIN usuarios u ON u.id = p.registrado_por ORDER BY p.creado_en DESC`
  );
  return rows;
}

// Red de seguridad: crea la comision automatica de cualquier contrato
// aprobado que por algun motivo no la tenga todavia (ej. importado
// directo como aprobado). decidirContrato() ya la genera al aprobar
// normalmente -- esto es solo para casos que se saltaron ese camino.
async function regenerarComisionesFaltantes(usuarioId) {
  const { rows: faltantes } = await pool.query(
    `SELECT c.* FROM contratos c
     WHERE c.estado = 'aprobado' AND c.promotor_nombre IS NOT NULL AND c.monto > 0
       AND NOT EXISTS (SELECT 1 FROM comisiones_semanas s WHERE s.contrato_id = c.id)`
  );
  let agregadas = 0;
  for (const contrato of faltantes) {
    const mesNom = MESES[new Date(contrato.fecha).getMonth()] + ' ' + new Date(contrato.fecha).getFullYear();
    const monto = Number(contrato.monto) || 0;
    const esCredito = contrato.tipo_venta === 'credito';
    const c8 = esCredito ? Math.round(monto * 0.08) : 0;
    const c16 = esCredito ? 0 : Math.round(monto * 0.16);
    const total = c8 + c16;
    const { rows } = await pool.query(
      `INSERT INTO comisiones_semanas (fecha_desde, fecha_hasta, mes_pago, automatica, contrato_id,
         factura_texto, tipo_venta, monto_venta, total, pagado, registrado_por)
       VALUES ($1,$1,$2,TRUE,$3,$4,$5,$6,$7,FALSE,$8) RETURNING id`,
      [contrato.fecha, mesNom, contrato.id, contrato.numero_factura, contrato.tipo_venta, monto, total, usuarioId]
    );
    await pool.query(
      `INSERT INTO comisiones_semana_promotores (semana_id, promotor_nombre, venta_credito, venta_contado, comision_8, comision_16, total)
       VALUES ($1,$2,$3,$4,$5,$6,$7)`,
      [rows[0].id, contrato.promotor_nombre, esCredito ? monto : 0, esCredito ? 0 : monto, c8, c16, total]
    );
    agregadas++;
  }
  return agregadas;
}

// ── CUENTAS POR PAGAR ─────────────────────────────────────────────
async function listarCuentasPorPagar() {
  const { rows } = await pool.query(
    `SELECT c.*,
            COALESCE(
              (SELECT json_agg(json_build_object('id',a.id,'monto',a.monto,'fecha',a.fecha,'nota',a.nota) ORDER BY a.fecha)
               FROM cuenta_por_pagar_abonos a WHERE a.cuenta_id = c.id), '[]'
            ) AS abonos
     FROM cuentas_por_pagar c ORDER BY c.creado_en DESC`
  );
  return rows;
}

async function crearCuentaPorPagar({ proveedor, concepto, monto, vencimiento, notas }) {
  const { rows } = await pool.query(
    `INSERT INTO cuentas_por_pagar (proveedor, concepto, monto, vencimiento, notas)
     VALUES ($1,$2,$3,$4,$5) RETURNING *`,
    [proveedor, concepto || null, monto, vencimiento || null, notas || null]
  );
  return rows[0];
}

async function abonarCuentaPorPagar(cuentaId, monto, nota) {
  const cliente = await pool.connect();
  try {
    await cliente.query('BEGIN');
    const { rows } = await cliente.query(`SELECT monto FROM cuentas_por_pagar WHERE id = $1 FOR UPDATE`, [cuentaId]);
    if (!rows[0]) { await cliente.query('ROLLBACK'); return null; }
    await cliente.query(
      `INSERT INTO cuenta_por_pagar_abonos (cuenta_id, monto, nota) VALUES ($1,$2,$3)`,
      [cuentaId, monto, nota || null]
    );
    const { rows: sumaRows } = await cliente.query(
      `SELECT COALESCE(SUM(monto),0) AS pagado FROM cuenta_por_pagar_abonos WHERE cuenta_id = $1`, [cuentaId]
    );
    const pagado = Number(sumaRows[0].pagado);
    const estado = pagado >= Number(rows[0].monto) ? 'pagado' : 'parcial';
    const { rows: actualizado } = await cliente.query(
      `UPDATE cuentas_por_pagar SET estado = $2 WHERE id = $1 RETURNING *`, [cuentaId, estado]
    );
    await cliente.query('COMMIT');
    return actualizado[0];
  } catch (err) {
    await cliente.query('ROLLBACK');
    throw err;
  } finally {
    cliente.release();
  }
}

// ── CRM ───────────────────────────────────────────────────────────
// Usa la MISMA tabla `clientes` que Facturacion (via resolverCliente)
// en vez de una tabla aparte -- asi un cliente institucional cargado
// desde CRM es el mismo registro si despues aparece en una factura,
// en vez de quedar duplicado como en el HTML original (arreglo `crm`
// suelto, sin relacion con los clientes de Facturacion).
async function listarClientesCrm() {
  const { rows } = await pool.query(
    `SELECT c.id, c.nombre, c.telefono1, c.cedula, c.tipo, c.notas, c.creado_en,
            c.estado_crm, c.proximo_seguimiento, c.vendedor_id, v.nombre AS vendedor_nombre,
            COALESCE(
              (SELECT json_agg(json_build_object('texto',n.texto,'fecha',n.creado_en) ORDER BY n.creado_en)
               FROM cliente_notas n WHERE n.cliente_id = c.id), '[]'
            ) AS historial,
            COALESCE(
              (SELECT json_agg(json_build_object(
                 'id',ct.id,'fac',ct.numero_factura,'fecha',ct.fecha,'monto',ct.monto,
                 'saldo',ct.saldo,'estado',ct.estado
               ) ORDER BY ct.fecha DESC)
               FROM contratos ct WHERE ct.cliente_id = c.id), '[]'
            ) AS compras
     FROM clientes c
     LEFT JOIN usuarios v ON v.id = c.vendedor_id
     ORDER BY c.proximo_seguimiento NULLS LAST, c.nombre`
  );
  return rows;
}

async function crearClienteCrm({ nombre, telefono1, cedula, tipo, notas, estadoCrm, proximoSeguimiento, vendedorId }) {
  const cedulaLimpia = (cedula || '').trim();
  if (cedulaLimpia) {
    const existente = await pool.query(`SELECT id FROM clientes WHERE cedula = $1`, [cedulaLimpia]);
    if (existente.rows[0]) {
      const { rows } = await pool.query(
        `UPDATE clientes SET nombre = $2, telefono1 = COALESCE($3, telefono1), tipo = $4, notas = COALESCE($5, notas),
           estado_crm = COALESCE($6, estado_crm), proximo_seguimiento = COALESCE($7, proximo_seguimiento),
           vendedor_id = COALESCE($8, vendedor_id)
         WHERE id = $1 RETURNING *`,
        [existente.rows[0].id, nombre, telefono1 || null, tipo || 'Particular', notas || null,
         estadoCrm || null, proximoSeguimiento || null, vendedorId || null]
      );
      return rows[0];
    }
  }
  const { rows } = await pool.query(
    `INSERT INTO clientes (nombre, telefono1, cedula, tipo, notas, estado_crm, proximo_seguimiento, vendedor_id)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *`,
    [nombre, telefono1 || null, cedulaLimpia || null, tipo || 'Particular', notas || null,
     estadoCrm || 'nuevo', proximoSeguimiento || null, vendedorId || null]
  );
  return rows[0];
}

// proximoSeguimiento: undefined = no tocar; null = limpiar la fecha; fecha = setearla
async function actualizarClienteCrm(id, { estadoCrm, proximoSeguimiento, vendedorId }) {
  const { rows } = await pool.query(
    `UPDATE clientes SET
       estado_crm = COALESCE($2, estado_crm),
       proximo_seguimiento = CASE WHEN $3::boolean THEN $4::date ELSE proximo_seguimiento END,
       vendedor_id = COALESCE($5, vendedor_id)
     WHERE id = $1 RETURNING *`,
    [id, estadoCrm || null, proximoSeguimiento !== undefined, proximoSeguimiento || null, vendedorId || null]
  );
  return rows[0] || null;
}

async function agregarNotaCliente(clienteId, texto, usuarioId) {
  const { rows } = await pool.query(
    `INSERT INTO cliente_notas (cliente_id, texto, creado_por) VALUES ($1,$2,$3) RETURNING *`,
    [clienteId, texto, usuarioId]
  );
  return rows[0];
}

// ── CONTABILIDAD ──────────────────────────────────────────────────
async function listarAsientos() {
  const { rows } = await pool.query(`SELECT * FROM asientos_contables ORDER BY fecha DESC, creado_en DESC`);
  return rows;
}

async function crearAsiento({ fecha, descripcion, cuenta, tipo, debe, haber }, usuarioId) {
  const { rows } = await pool.query(
    `INSERT INTO asientos_contables (fecha, descripcion, cuenta, tipo, debe, haber, creado_por)
     VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *`,
    [fecha || new Date().toISOString().slice(0, 10), descripcion, cuenta || null, tipo || null, debe || 0, haber || 0, usuarioId]
  );
  return rows[0];
}

// ── NOMINA (Ley RD: AFP 2.87%, SFS 3.04%, ISR escalonado) ────────────
// Mismas tablas y formula que calcISR()/calcDesc() en el HTML original
// (linea ~2999-3013) -- se replican aca para que el calculo de
// impuestos/descuentos de nomina sea autoritativo en el servidor, no
// algo que el navegador podria mandar ya calculado (y potencialmente
// alterado) al guardar.
const ISR_TRAMOS = [
  { hasta: 416220, tasa: 0, exceso: 0, base: 0 },
  { hasta: 624329, tasa: 0.15, exceso: 416220.01, base: 0 },
  { hasta: 867123, tasa: 0.20, exceso: 624329.01, base: 31212 },
  { hasta: Infinity, tasa: 0.25, exceso: 867123.01, base: 79776 },
];
function calcularISR(baseAnual) {
  for (const t of ISR_TRAMOS) {
    if (baseAnual <= t.hasta) return t.base + Math.max(0, baseAnual - t.exceso) * t.tasa;
  }
  return 0;
}
function calcularDescuentos(bruto) {
  const afp = bruto * 0.0287, sfs = bruto * 0.0304;
  const baseAnual = (bruto - afp - sfs) * 12;
  const isr = Math.max(0, calcularISR(baseAnual) / 12);
  const tot = afp + sfs + isr;
  const escala = baseAnual <= 416220 ? 'Exento' : baseAnual <= 624329 ? '15%' : baseAnual <= 867123 ? '20%' : '25%';
  return { afp, sfs, isr, tot, neto: bruto - tot, escala };
}

async function listarEmpleados({ soloActivos = true } = {}) {
  const { rows } = await pool.query(
    `SELECT * FROM empleados ${soloActivos ? 'WHERE activo = TRUE' : ''} ORDER BY nombre`
  );
  return rows;
}

async function crearEmpleado({ nombre, cedula, codigo, banco, cuenta, cargo, departamento, salario, fechaIngreso }) {
  const cod = (codigo || '').trim() || null;
  const { rows } = await pool.query(
    `INSERT INTO empleados (nombre, cedula, codigo, banco, cuenta, cargo, departamento, salario_bruto, fecha_ingreso)
     VALUES ($1,$2,$3,COALESCE($4,'KRV-EMP-'||LPAD((SELECT COUNT(*)+1 FROM empleados)::text,3,'0')),$5,$6,$7,$8,$9)
     RETURNING *`,
    [nombre, cedula || null, cod, banco || null, cuenta || null, cargo || null, departamento || null, salario, fechaIngreso || new Date().toISOString().slice(0, 10)]
  );
  return rows[0];
}

async function desactivarEmpleado(id) {
  await pool.query(`UPDATE empleados SET activo = FALSE WHERE id = $1`, [id]);
}

async function listarNominas() {
  const { rows } = await pool.query(
    `SELECT n.*,
            COALESCE(
              (SELECT json_agg(json_build_object(
                 'nombre',d.nombre,'cedula',d.cedula,'codigo',d.codigo,'banco',d.banco,'cuenta',d.cuenta,
                 'cargo',d.cargo,'bruto',d.bruto,'afp',d.afp,'sfs',d.sfs,'isr',d.isr,
                 'totalDesc',d.total_descuento,'neto',d.neto,'escala',d.escala_isr
               ))
               FROM nomina_detalle d WHERE d.nomina_id = n.id), '[]'
            ) AS det
     FROM nominas n ORDER BY n.mes DESC, n.quincena DESC`
  );
  return rows;
}

async function procesarNomina({ mes, quincena }, usuarioId) {
  const cliente = await pool.connect();
  try {
    await cliente.query('BEGIN');
    const existente = await cliente.query(`SELECT id FROM nominas WHERE mes = $1 AND quincena = $2`, [mes, quincena]);
    if (existente.rows[0]) { await cliente.query('ROLLBACK'); return { error: 'Ya existe esa nómina' }; }
    const activos = await cliente.query(`SELECT * FROM empleados WHERE activo = TRUE ORDER BY nombre`);
    if (!activos.rows.length) { await cliente.query('ROLLBACK'); return { error: 'No hay empleados activos' }; }

    const dia = quincena === 'primera' ? 15 : new Date(Number(mes.split('-')[0]), Number(mes.split('-')[1]), 0).getDate();
    const fechaPago = `${mes}-${String(Math.min(30, dia)).padStart(2, '0')}`;

    let totalNeto = 0, totalBruto = 0;
    const detalles = activos.rows.map((e) => {
      const bruto = Number(e.salario_bruto) / 2;
      const d = calcularDescuentos(Number(e.salario_bruto));
      const fila = {
        nombre: e.nombre, cedula: e.cedula, codigo: e.codigo, banco: e.banco, cuenta: e.cuenta, cargo: e.cargo,
        bruto, afp: d.afp / 2, sfs: d.sfs / 2, isr: d.isr / 2, totalDesc: d.tot / 2, neto: bruto - d.tot / 2, escala: d.escala,
      };
      totalNeto += fila.neto; totalBruto += fila.bruto;
      return fila;
    });

    const { rows } = await cliente.query(
      `INSERT INTO nominas (mes, quincena, fecha_pago, total_neto, total_bruto, cantidad_empleados)
       VALUES ($1,$2,$3,$4,$5,$6) RETURNING *`,
      [mes, quincena, fechaPago, totalNeto, totalBruto, activos.rows.length]
    );
    const nominaId = rows[0].id;
    for (const emp of activos.rows) {
      const f = detalles.find((d) => d.codigo === emp.codigo && d.nombre === emp.nombre);
      await cliente.query(
        `INSERT INTO nomina_detalle (nomina_id, empleado_id, nombre, cedula, codigo, banco, cuenta, cargo, bruto, afp, sfs, isr, total_descuento, neto, escala_isr)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`,
        [nominaId, emp.id, f.nombre, f.cedula, f.codigo, f.banco, f.cuenta, f.cargo, f.bruto, f.afp, f.sfs, f.isr, f.totalDesc, f.neto, f.escala]
      );
    }
    await cliente.query('COMMIT');
    return { id: nominaId, totalNeto };
  } catch (err) {
    await cliente.query('ROLLBACK');
    throw err;
  } finally {
    cliente.release();
  }
}

// ── LABORATORIO ──────────────────────────────────────────────────────
// proximo_vencimiento: la fecha de vencimiento más próxima entre las
// compras registradas de esa materia prima (aproximado -- el sistema no
// hace seguimiento de qué entrada específica se está consumiendo, así
// que es "lo más viejo que compraste y aún no vence", no un FIFO real).
// bajo_minimo: aviso de reorden antes de que el stock llegue a cero.
async function listarMateriasPrimas({ soloActivas = true } = {}) {
  const { rows } = await pool.query(
    `SELECT m.*,
       (SELECT MIN(e.fecha_vencimiento) FROM lab_entradas e
        WHERE e.materia_prima_id = m.id AND e.fecha_vencimiento >= CURRENT_DATE) AS proximo_vencimiento,
       (m.stock <= m.stock_minimo AND m.stock_minimo > 0) AS bajo_minimo
     FROM lab_materias_primas m
     ${soloActivas ? 'WHERE m.activo = TRUE' : ''}
     ORDER BY m.tipo, m.nombre`
  );
  return rows;
}

async function crearMateriaPrima({ nombre, tipo, unidad, costoUnitario, stockMinimo }) {
  const { rows } = await pool.query(
    `INSERT INTO lab_materias_primas (nombre, tipo, unidad, costo_unitario, stock_minimo) VALUES ($1,$2,$3,$4,$5) RETURNING *`,
    [nombre, tipo || 'quimico', unidad || 'gramos', costoUnitario || 0, stockMinimo || 0]
  );
  return rows[0];
}

async function actualizarMateriaPrima(id, { nombre, tipo, unidad, costoUnitario, stockMinimo }) {
  const { rows } = await pool.query(
    `UPDATE lab_materias_primas SET
       nombre = COALESCE($2, nombre), tipo = COALESCE($3, tipo),
       unidad = COALESCE($4, unidad), costo_unitario = COALESCE($5, costo_unitario),
       stock_minimo = COALESCE($6, stock_minimo)
     WHERE id = $1 RETURNING *`,
    [id, nombre, tipo, unidad, costoUnitario, stockMinimo]
  );
  return rows[0] || null;
}

async function desactivarMateriaPrima(id) {
  await pool.query(`UPDATE lab_materias_primas SET activo = FALSE WHERE id = $1`, [id]);
}
async function reactivarMateriaPrima(id) {
  await pool.query(`UPDATE lab_materias_primas SET activo = TRUE WHERE id = $1`, [id]);
}

// Entrada de materia prima -- la unica forma normal de subir el stock.
// Si la entrada trae costo total, el costo por unidad de la materia
// prima se actualiza a un promedio ponderado (lo que ya había en stock,
// a su costo actual, más esta compra) -- así el costo de fabricar no se
// queda pegado al primer precio que se cargó ni salta de golpe al
// último precio pagado.
async function registrarEntradaLab(materiaPrimaId, cantidad, { costoTotal, proveedor, loteProveedor, fechaVencimiento }, usuarioId) {
  const cliente = await pool.connect();
  try {
    await cliente.query('BEGIN');
    const cant = Number(cantidad) || 0;
    if (cant <= 0) { await cliente.query('ROLLBACK'); return null; }
    const { rows: mpRows } = await cliente.query(
      `SELECT * FROM lab_materias_primas WHERE id = $1 FOR UPDATE`, [materiaPrimaId]
    );
    const mp = mpRows[0];
    if (!mp) { await cliente.query('ROLLBACK'); return null; }
    await cliente.query(
      `INSERT INTO lab_entradas (materia_prima_id, cantidad, costo_total, proveedor, lote_proveedor, fecha_vencimiento, registrado_por)
       VALUES ($1,$2,$3,$4,$5,$6,$7)`,
      [materiaPrimaId, cant, costoTotal || null, proveedor || null, loteProveedor || null, fechaVencimiento || null, usuarioId]
    );
    const stockActual = Number(mp.stock) || 0;
    const costoActual = Number(mp.costo_unitario) || 0;
    let nuevoCostoUnitario = costoActual;
    if (costoTotal != null && Number(costoTotal) > 0) {
      const valorInventarioActual = stockActual * costoActual;
      nuevoCostoUnitario = (valorInventarioActual + Number(costoTotal)) / (stockActual + cant);
    }
    const { rows } = await cliente.query(
      `UPDATE lab_materias_primas SET stock = stock + $2, costo_unitario = $3 WHERE id = $1 RETURNING *`,
      [materiaPrimaId, cant, nuevoCostoUnitario]
    );
    await cliente.query('COMMIT');
    return rows[0];
  } catch (err) {
    await cliente.query('ROLLBACK');
    throw err;
  } finally {
    cliente.release();
  }
}

async function listarEntradasLab(materiaPrimaId) {
  const { rows } = await pool.query(
    `SELECT e.*, m.nombre AS materia_prima_nombre, m.unidad, u.nombre AS registrado_por_nombre
     FROM lab_entradas e
     JOIN lab_materias_primas m ON m.id = e.materia_prima_id
     LEFT JOIN usuarios u ON u.id = e.registrado_por
     ${materiaPrimaId ? 'WHERE e.materia_prima_id = $1' : ''}
     ORDER BY e.creado_en DESC LIMIT 200`,
    materiaPrimaId ? [materiaPrimaId] : []
  );
  return rows;
}

// Factor para llevar cualquier unidad de peso/volumen a gramos, y así
// poder sumar ingredientes que se cargaron en unidades distintas
// (ej. aceite por galón + polvo por gramo) en un solo "peso del lote".
// El galón se aproxima a densidad de agua (~1g/mL): suficiente para un
// negocio, no para un laboratorio de precisión.
const LAB_A_GRAMOS = { gramos: 1, kilogramos: 1000, onzas: 28.3495, galon: 3785.41 };

// Calcula, a partir de los ingredientes de una receta y su costo
// ACTUAL (no el de cuando se guardó), cuánto pesa el lote, cuántas
// unidades del producto rinde y cuánto cuesta fabricar cada una.
// Se recalcula siempre al vuelo -- si sube el precio de una materia
// prima, se refleja solo, sin tener que volver a guardar la receta.
//
// Separa "ingredientes" (químico/natural: entran a la fórmula, su peso
// SÍ suma al lote) de "empaque" (pote/tapa/etiqueta: no tienen peso
// relevante a la fórmula, se consumen 1 por unidad terminada, no por
// lote). La merma (%) reduce las unidades que realmente se logran
// envasar, sin cambiar cuánta materia prima se gastó.
function _labCalcularReceta(items, contenidoPorUnidad, contenidoUnidad, precioReferencia, mermaPct) {
  const ingredientes = items.filter((it) => it.tipo !== 'empaque');
  const empaques = items.filter((it) => it.tipo === 'empaque');

  const pesoTotalGramos = ingredientes.reduce((s, it) => s + Number(it.cantidad) * (LAB_A_GRAMOS[it.unidad] || 1), 0);
  const costoIngredientesLote = ingredientes.reduce((s, it) => s + Number(it.cantidad) * Number(it.costoUnitario || 0), 0);
  const costoEmpaquePorUnidad = empaques.reduce((s, it) => s + Number(it.cantidad) * Number(it.costoUnitario || 0), 0);

  const contenidoGramos = Number(contenidoPorUnidad || 0) * (LAB_A_GRAMOS[contenidoUnidad] || 1);
  const merma = Math.min(Math.max(Number(mermaPct) || 0, 0), 100) / 100;
  const unidadesPorLoteBruto = contenidoGramos > 0 ? pesoTotalGramos / contenidoGramos : 0;
  const unidadesPorLote = unidadesPorLoteBruto * (1 - merma);

  const costoTotalLote = costoIngredientesLote + costoEmpaquePorUnidad * unidadesPorLote;
  const costoPorUnidad = unidadesPorLote > 0 ? costoTotalLote / unidadesPorLote : 0;

  const precio = Number(precioReferencia || 0);
  const margenPct = precio > 0 && costoPorUnidad > 0 ? ((precio - costoPorUnidad) / precio) * 100 : null;

  // Lista INCI (orden de etiqueta): ingredientes de mayor a menor peso.
  // El empaque no es parte de la fórmula, no entra en esta lista.
  const inci = ingredientes
    .slice()
    .sort((a, b) => Number(b.cantidad) * (LAB_A_GRAMOS[b.unidad] || 1) - Number(a.cantidad) * (LAB_A_GRAMOS[a.unidad] || 1))
    .map((it) => it.nombre);

  return {
    pesoTotalGramos, costoTotalLote, unidadesPorLote, costoPorUnidad, margenPct,
    costoEmpaquePorUnidad, unidadesPorLoteBruto, mermaPct: Number(mermaPct) || 0, inci,
  };
}

async function listarRecetas() {
  const { rows } = await pool.query(
    `SELECT r.*, p.nombre AS producto_nombre, p.precio_referencia,
       COALESCE(
         (SELECT json_agg(json_build_object(
            'id', ri.id, 'materiaPrimaId', ri.materia_prima_id, 'nombre', m.nombre,
            'unidad', m.unidad, 'tipo', m.tipo, 'cantidad', ri.cantidad, 'costoUnitario', m.costo_unitario
          ) ORDER BY m.nombre)
          FROM lab_receta_items ri JOIN lab_materias_primas m ON m.id = ri.materia_prima_id
          WHERE ri.receta_id = r.id), '[]'
       ) AS items
     FROM lab_recetas r JOIN productos p ON p.id = r.producto_id
     ORDER BY p.nombre`
  );
  return rows.map((r) => ({
    ...r,
    calculo: _labCalcularReceta(r.items, r.contenido_por_unidad, r.contenido_unidad, r.precio_referencia, r.merma_pct),
  }));
}

// Crea o reemplaza por completo la receta de un producto (borra los
// items viejos e inserta los nuevos) -- se edita como un formulario
// completo, no linea por linea.
async function guardarReceta(productoId, { contenidoPorUnidad, contenidoUnidad, mermaPct, notas, items }) {
  const cliente = await pool.connect();
  try {
    await cliente.query('BEGIN');
    const { rows } = await cliente.query(
      `INSERT INTO lab_recetas (producto_id, contenido_por_unidad, contenido_unidad, merma_pct, notas)
       VALUES ($1,$2,$3,$4,$5)
       ON CONFLICT (producto_id) DO UPDATE SET
         contenido_por_unidad = $2, contenido_unidad = $3, merma_pct = $4, notas = $5, actualizado_en = now()
       RETURNING *`,
      [productoId, contenidoPorUnidad || 1, contenidoUnidad || 'gramos', mermaPct || 0, notas || null]
    );
    const receta = rows[0];
    await cliente.query(`DELETE FROM lab_receta_items WHERE receta_id = $1`, [receta.id]);
    for (const it of items || []) {
      if (!it.materiaPrimaId || !(Number(it.cantidad) > 0)) continue;
      await cliente.query(
        `INSERT INTO lab_receta_items (receta_id, materia_prima_id, cantidad) VALUES ($1,$2,$3)`,
        [receta.id, it.materiaPrimaId, Number(it.cantidad)]
      );
    }
    await cliente.query('COMMIT');
    return receta;
  } catch (err) {
    await cliente.query('ROLLBACK');
    throw err;
  } finally {
    cliente.release();
  }
}

async function listarProducciones() {
  const { rows } = await pool.query(
    `SELECT pr.*, p.nombre AS producto_nombre, u.nombre AS registrado_por_nombre,
       COALESCE(
         (SELECT json_agg(json_build_object(
            'materiaPrimaId', pi.materia_prima_id, 'nombre', m.nombre,
            'unidad', m.unidad, 'cantidad', pi.cantidad_consumida
          ))
          FROM lab_produccion_items pi JOIN lab_materias_primas m ON m.id = pi.materia_prima_id
          WHERE pi.produccion_id = pr.id), '[]'
       ) AS items
     FROM lab_producciones pr
     JOIN lab_recetas r ON r.id = pr.receta_id
     JOIN productos p ON p.id = r.producto_id
     LEFT JOIN usuarios u ON u.id = pr.registrado_por
     ORDER BY pr.creado_en DESC LIMIT 100`
  );
  return rows;
}

// Fabrica `lotes` veces la receta: valida que haya suficiente materia
// prima de CADA ingrediente/empaque antes de descontar nada (todo o
// nada), y si se pide, suma el producto terminado a almacen_stock
// (bodega). Los ingredientes (químico/natural) escalan con `lotes`;
// el empaque (pote/tapa/etiqueta) escala con las UNIDADES terminadas
// (que ya vienen reducidas por la merma), porque un pote se gasta por
// unidad envasada, no por cuántas veces se repite la fórmula.
async function registrarProduccion(recetaId, lotes, sumarAlmacen, usuarioId) {
  const cliente = await pool.connect();
  try {
    await cliente.query('BEGIN');
    const lotesNum = Number(lotes) || 0;
    if (lotesNum <= 0) { await cliente.query('ROLLBACK'); return { error: 'Lotes inválidos' }; }

    const { rows: recRows } = await cliente.query(`SELECT * FROM lab_recetas WHERE id = $1`, [recetaId]);
    const receta = recRows[0];
    if (!receta) { await cliente.query('ROLLBACK'); return null; }

    const { rows: items } = await cliente.query(
      `SELECT ri.materia_prima_id, ri.cantidad, m.nombre, m.stock, m.unidad, m.tipo, m.costo_unitario AS "costoUnitario"
       FROM lab_receta_items ri JOIN lab_materias_primas m ON m.id = ri.materia_prima_id
       WHERE ri.receta_id = $1 FOR UPDATE OF m`,
      [recetaId]
    );
    if (!items.length) { await cliente.query('ROLLBACK'); return { error: 'La receta no tiene ingredientes' }; }

    const calc = _labCalcularReceta(items, receta.contenido_por_unidad, receta.contenido_unidad, 0, receta.merma_pct);
    const unidadesProducidas = calc.unidadesPorLote * lotesNum;
    const costoTotal = calc.costoTotalLote * lotesNum;
    const costoPorUnidad = unidadesProducidas > 0 ? costoTotal / unidadesProducidas : 0;
    if (!(unidadesProducidas > 0)) { await cliente.query('ROLLBACK'); return { error: 'La receta no tiene "contenido por unidad" válido -- no se puede calcular cuántas unidades rinde' }; }

    const necesarios = items.map((it) => ({
      ...it,
      necesario: it.tipo === 'empaque' ? Number(it.cantidad) * unidadesProducidas : Number(it.cantidad) * lotesNum,
    }));
    const faltantes = [];
    necesarios.forEach((it) => {
      if (it.necesario > Number(it.stock)) {
        faltantes.push(`${it.nombre}: hacen falta ${(it.necesario - Number(it.stock)).toFixed(3)} ${it.unidad}`);
      }
    });
    if (faltantes.length) { await cliente.query('ROLLBACK'); return { error: 'Stock insuficiente', faltantes }; }

    const { rows: prodRows } = await cliente.query(
      `INSERT INTO lab_producciones (receta_id, lotes, unidades_producidas, costo_total, costo_por_unidad, sumo_almacen, registrado_por)
       VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *`,
      [recetaId, lotesNum, unidadesProducidas, costoTotal, costoPorUnidad, !!sumarAlmacen, usuarioId]
    );
    const produccion = prodRows[0];

    for (const it of necesarios) {
      await cliente.query(`UPDATE lab_materias_primas SET stock = stock - $2 WHERE id = $1`, [it.materia_prima_id, it.necesario]);
      await cliente.query(
        `INSERT INTO lab_produccion_items (produccion_id, materia_prima_id, cantidad_consumida) VALUES ($1,$2,$3)`,
        [produccion.id, it.materia_prima_id, it.necesario]
      );
    }

    if (sumarAlmacen) {
      await cliente.query(
        `INSERT INTO almacen_stock (producto_id, ubicacion, cantidad) VALUES ($1,'bodega',$2)
         ON CONFLICT (producto_id, ubicacion) DO UPDATE SET cantidad = almacen_stock.cantidad + $2`,
        [receta.producto_id, Math.round(unidadesProducidas)]
      );
    }

    await cliente.query('COMMIT');
    return produccion;
  } catch (err) {
    await cliente.query('ROLLBACK');
    throw err;
  } finally {
    cliente.release();
  }
}

// ── IA (Sarah) — clave del negocio cifrada en el servidor, nunca en el
// HTML (Etapa 6). AES-256-GCM con IA_CIFRADO_SECRET del .env; si falta
// esa variable, cifrar/descifrar falla ruidosamente en vez de usar una
// clave débil por defecto -- un secreto "de repuesto" hardcodeado
// arruinaría el propósito de cifrar.
function _iaClaveCifrado() {
  const secreto = process.env.IA_CIFRADO_SECRET;
  if (!secreto || secreto.length < 64) {
    throw new Error('Falta IA_CIFRADO_SECRET en el .env (32 bytes en hexadecimal, 64 caracteres)');
  }
  return Buffer.from(secreto.slice(0, 64), 'hex');
}
function _iaCifrar(texto) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', _iaClaveCifrado(), iv);
  const cifrado = Buffer.concat([cipher.update(texto, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, cifrado]).toString('base64');
}
function _iaDescifrar(valor) {
  const buf = Buffer.from(valor, 'base64');
  const iv = buf.subarray(0, 12);
  const tag = buf.subarray(12, 28);
  const cifrado = buf.subarray(28);
  const decipher = crypto.createDecipheriv('aes-256-gcm', _iaClaveCifrado(), iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(cifrado), decipher.final()]).toString('utf8');
}

async function guardarClaveIA(proveedor, apiKey) {
  const cifrada = _iaCifrar(apiKey);
  const { rows } = await pool.query(
    `INSERT INTO config_ia (proveedor, api_key_cifrada, activo, actualizado_en)
     VALUES ($1,$2,TRUE,now())
     ON CONFLICT (proveedor) DO UPDATE SET api_key_cifrada = $2, activo = TRUE, actualizado_en = now()
     RETURNING proveedor, activo, actualizado_en`,
    [proveedor, cifrada]
  );
  return rows[0];
}
async function desactivarClaveIA(proveedor) {
  await pool.query(`UPDATE config_ia SET activo = FALSE WHERE proveedor = $1`, [proveedor]);
}
// Nunca devuelve la clave descifrada -- solo si hay una guardada y si
// está activa, para que la pantalla de administración pueda mostrar
// el estado sin exponer el secreto.
async function listarConfigIA() {
  const { rows } = await pool.query(
    `SELECT proveedor, activo, actualizado_en, (api_key_cifrada IS NOT NULL) AS tiene_clave FROM config_ia ORDER BY proveedor`
  );
  return rows;
}

// Uso interno del proxy de chat -- la única función que sí descifra,
// y su resultado nunca sale del servidor hacia el cliente.
async function _iaProveedorActivo() {
  const { rows } = await pool.query(
    `SELECT proveedor, api_key_cifrada FROM config_ia
     WHERE activo = TRUE AND api_key_cifrada IS NOT NULL
     ORDER BY CASE proveedor WHEN 'claude' THEN 1 WHEN 'openai' THEN 2 WHEN 'gemini' THEN 3 ELSE 4 END
     LIMIT 1`
  );
  if (!rows[0]) return null;
  return { proveedor: rows[0].proveedor, apiKey: _iaDescifrar(rows[0].api_key_cifrada) };
}

// Llama al proveedor de IA que Gerencia haya activado, con la clave del
// negocio guardada en el servidor. Nunca lanza excepción -- devuelve
// {texto} o {error}, para que la ruta HTTP decida el código de estado.
async function llamarIA(mensajes, sistema) {
  let activo;
  try {
    activo = await _iaProveedorActivo();
  } catch (err) {
    return { error: 'Sarah no está disponible: ' + err.message };
  }
  if (!activo) return { error: 'Sarah no tiene una clave de API configurada todavía. Pídele a Gerencia que la active en Configuración.' };
  const { proveedor, apiKey } = activo;
  try {
    if (proveedor === 'openai') {
      const r = await fetch('https://api.openai.com/v1/chat/completions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + apiKey },
        body: JSON.stringify({
          model: 'gpt-4o-mini',
          messages: [{ role: 'system', content: sistema }].concat(mensajes),
          max_tokens: 800, temperature: 0.8,
        }),
      });
      const d = await r.json();
      if (!r.ok) throw new Error((d.error && d.error.message) || r.status);
      return { texto: d.choices[0].message.content };
    }
    if (proveedor === 'gemini') {
      const parts = [{ text: sistema + '\n\n' }];
      mensajes.forEach((m) => parts.push({ text: (m.role === 'user' ? 'User: ' : 'Assistant: ') + m.content + '\n' }));
      const r = await fetch('https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=' + apiKey, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ contents: [{ role: 'user', parts }], generationConfig: { maxOutputTokens: 800, temperature: 0.8 } }),
      });
      const d = await r.json();
      if (!r.ok) throw new Error((d.error && d.error.message) || r.status);
      return { texto: d.candidates[0].content.parts[0].text };
    }
    if (proveedor === 'claude') {
      const r = await fetch('https://api.anthropic.com/v1/messages', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'x-api-key': apiKey, 'anthropic-version': '2023-06-01' },
        body: JSON.stringify({ model: 'claude-haiku-4-5-20251001', max_tokens: 800, system: sistema, messages: mensajes }),
      });
      const d = await r.json();
      if (!r.ok) throw new Error((d.error && d.error.message) || r.status);
      return { texto: d.content[0].text };
    }
    return { error: 'Proveedor de IA no reconocido: ' + proveedor };
  } catch (err) {
    return { error: 'No se pudo contactar la IA (' + proveedor + '): ' + err.message };
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
  listarMateriasPrimas,
  crearMateriaPrima,
  actualizarMateriaPrima,
  desactivarMateriaPrima,
  reactivarMateriaPrima,
  registrarEntradaLab,
  listarEntradasLab,
  listarRecetas,
  guardarReceta,
  listarProducciones,
  registrarProduccion,
  guardarClaveIA,
  desactivarClaveIA,
  listarConfigIA,
  llamarIA,
  resolverCliente,
  siguienteNumeroFactura,
  crearContrato,
  listarContratos,
  decidirContrato,
  buscarContratosParaRuta,
  listarRutaSeleccionHoy,
  agregarARutaSeleccion,
  quitarDeRutaSeleccion,
  actualizarEstadoRuta,
  editarClienteDeContrato,
  eliminarContrato,
  editarDatosCobranza,
  crearContratoLegacyCobrador,
  registrarAbonoContrato,
  listarStock,
  registrarEntradaAlmacen,
  listarEntradasAlmacen,
  registrarMovimientoAlmacen,
  listarComisionesSemanas,
  crearSemanaComisionManual,
  marcarComisionesSemanasPagadas,
  listarComisionesPagos,
  regenerarComisionesFaltantes,
  listarCuentasPorPagar,
  crearCuentaPorPagar,
  abonarCuentaPorPagar,
  listarClientesCrm,
  crearClienteCrm,
  actualizarClienteCrm,
  agregarNotaCliente,
  listarAsientos,
  crearAsiento,
  listarEmpleados,
  crearEmpleado,
  desactivarEmpleado,
  listarNominas,
  procesarNomina,
};
