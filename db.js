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
            COALESCE(
              (SELECT json_agg(json_build_object('texto',n.texto,'fecha',n.creado_en) ORDER BY n.creado_en)
               FROM cliente_notas n WHERE n.cliente_id = c.id), '[]'
            ) AS historial
     FROM clientes c ORDER BY c.nombre`
  );
  return rows;
}

async function crearClienteCrm({ nombre, telefono1, cedula, tipo, notas }) {
  const cedulaLimpia = (cedula || '').trim();
  if (cedulaLimpia) {
    const existente = await pool.query(`SELECT id FROM clientes WHERE cedula = $1`, [cedulaLimpia]);
    if (existente.rows[0]) {
      const { rows } = await pool.query(
        `UPDATE clientes SET nombre = $2, telefono1 = COALESCE($3, telefono1), tipo = $4, notas = COALESCE($5, notas)
         WHERE id = $1 RETURNING *`,
        [existente.rows[0].id, nombre, telefono1 || null, tipo || 'Particular', notas || null]
      );
      return rows[0];
    }
  }
  const { rows } = await pool.query(
    `INSERT INTO clientes (nombre, telefono1, cedula, tipo, notas) VALUES ($1,$2,$3,$4,$5) RETURNING *`,
    [nombre, telefono1 || null, cedulaLimpia || null, tipo || 'Particular', notas || null]
  );
  return rows[0];
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
  agregarNotaCliente,
  listarAsientos,
  crearAsiento,
  listarEmpleados,
  crearEmpleado,
  desactivarEmpleado,
  listarNominas,
  procesarNomina,
};
