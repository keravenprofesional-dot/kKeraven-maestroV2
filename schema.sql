-- ═══════════════════════════════════════════════════════════════════
-- KERPLUS — Esquema de base de datos (PostgreSQL 16)
-- Se ejecuta en cada arranque del backend: todo debe ser idempotente
-- (CREATE TABLE IF NOT EXISTS, ADD COLUMN IF NOT EXISTS, etc.)
-- ═══════════════════════════════════════════════════════════════════

-- ── USUARIOS Y PERMISOS ──────────────────────────────────────────────
-- Reemplaza el arreglo USUARIOS[] del HTML original. El PIN nunca se
-- guarda en claro: pin_hash es un hash bcrypt, verificado en el backend.
CREATE TABLE IF NOT EXISTS usuarios (
  id              SERIAL PRIMARY KEY,
  nombre          TEXT NOT NULL,
  rol             TEXT NOT NULL CHECK (rol IN ('gerente','subgerente','coordinador','supervisor','almacen','promotor')),
  rol_label       TEXT NOT NULL,
  pin_hash        TEXT NOT NULL,
  color           TEXT DEFAULT '#B8860B',
  activo          BOOLEAN NOT NULL DEFAULT TRUE,
  editable        BOOLEAN NOT NULL DEFAULT TRUE,
  -- Permisos por usuario (lo que pidió el usuario: acceso configurable
  -- por persona, no solo fijo por rol). NULL = usa los permisos por
  -- defecto del rol (definidos en el backend, no en esta tabla).
  permisos_custom JSONB,
  intentos_fallidos SMALLINT NOT NULL DEFAULT 0,
  bloqueado_hasta TIMESTAMPTZ,
  creado_en       TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_usuarios_rol ON usuarios(rol);

-- ── CONTADORES (numeración atómica de facturas) ──────────────────────
-- Mismo patrón que Seguimiento de Almas: UPDATE atómico, nunca MAX()+1.
CREATE TABLE IF NOT EXISTS contadores (
  clave   TEXT PRIMARY KEY,
  valor   INTEGER NOT NULL DEFAULT 0
);
INSERT INTO contadores (clave, valor) VALUES ('factura', 0) ON CONFLICT (clave) DO NOTHING;

-- ── CATÁLOGO DE PRODUCTOS ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS productos (
  id                SERIAL PRIMARY KEY,
  nombre            TEXT NOT NULL UNIQUE,
  precio_referencia NUMERIC(12,2) DEFAULT 0,
  categoria         TEXT, -- Duo Kit 10 oz / 32 oz / 16 oz / Bálsamo / Individuales / Línea de Rizo / Tratamientos / Líneas Premium / Otros
  activo            BOOLEAN NOT NULL DEFAULT TRUE
);

-- ── CLIENTES (tabla única — hoy fragmentado entre Facturación, ──────
-- Cobrador y CRM; con esto un mismo cliente se referencia desde los 3)
CREATE TABLE IF NOT EXISTS clientes (
  id            SERIAL PRIMARY KEY,
  cedula        TEXT,
  nombre        TEXT NOT NULL,
  telefono1     TEXT,
  telefono2     TEXT,
  email         TEXT,
  institucion   TEXT,
  barrio        TEXT,
  referencia    TEXT,
  direccion     TEXT,
  zona          TEXT,
  tipo          TEXT DEFAULT 'Particular', -- Farmacia/Salón/Clínica/Hospital/Escuela/Municipio/Institución/Particular
  notas         TEXT,
  estado_crm        TEXT NOT NULL DEFAULT 'nuevo' CHECK (estado_crm IN ('nuevo','contactado','interesado','cliente','inactivo')),
  proximo_seguimiento DATE,
  vendedor_id       INTEGER REFERENCES usuarios(id) ON DELETE SET NULL,
  creado_en     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_clientes_cedula ON clientes(cedula) WHERE cedula IS NOT NULL AND cedula <> '';
CREATE INDEX IF NOT EXISTS idx_clientes_nombre ON clientes(nombre);

-- Historial de contacto (reemplaza cl.historial[] del CRM)
CREATE TABLE IF NOT EXISTS cliente_notas (
  id            SERIAL PRIMARY KEY,
  cliente_id    INTEGER NOT NULL REFERENCES clientes(id) ON DELETE CASCADE,
  texto         TEXT NOT NULL,
  creado_por    INTEGER REFERENCES usuarios(id) ON DELETE SET NULL,
  creado_en     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_cliente_notas_cliente ON cliente_notas(cliente_id);

-- ── CONTRATOS / FACTURACIÓN ───────────────────────────────────────────
CREATE TABLE IF NOT EXISTS contratos (
  id              SERIAL PRIMARY KEY,
  numero_factura  TEXT NOT NULL UNIQUE,
  fecha           DATE NOT NULL DEFAULT CURRENT_DATE,
  cliente_id      INTEGER NOT NULL REFERENCES clientes(id) ON DELETE RESTRICT,
  promotor_id     INTEGER REFERENCES usuarios(id) ON DELETE SET NULL,
  promotor_nombre TEXT, -- respaldo textual si el promotor no es un usuario del sistema (ej. "PROMOTOR A" fijo)
  zona            TEXT,
  canal           TEXT NOT NULL DEFAULT 'ruta' CHECK (canal IN ('oficina','ruta','embajadora')),
  tipo_venta      TEXT NOT NULL CHECK (tipo_venta IN ('credito','contado')),
  plazo_dias      SMALLINT,
  fecha_limite    DATE,
  monto           NUMERIC(12,2) NOT NULL,
  descuento       NUMERIC(12,2) NOT NULL DEFAULT 0,
  neto            NUMERIC(12,2) NOT NULL,
  saldo           NUMERIC(12,2) NOT NULL,
  observaciones   TEXT,
  foto_frente_url   TEXT,
  foto_reverso_url  TEXT,
  foto_factura_url  TEXT,
  gps_lat         DOUBLE PRECISION,
  gps_lng         DOUBLE PRECISION,
  gps_plus_code   TEXT,
  gps_precision_m DOUBLE PRECISION,
  estado          TEXT NOT NULL DEFAULT 'pendiente' CHECK (estado IN ('pendiente','aprobado','rechazado','pendiente_fotos')),
  origen          TEXT NOT NULL DEFAULT 'manual' CHECK (origen IN ('manual','excel','cobrador')),
  creado_por      INTEGER REFERENCES usuarios(id) ON DELETE SET NULL,
  creado_en       TIMESTAMPTZ NOT NULL DEFAULT now(),
  decidido_por    INTEGER REFERENCES usuarios(id) ON DELETE SET NULL,
  decidido_en     TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_contratos_cliente ON contratos(cliente_id);
CREATE INDEX IF NOT EXISTS idx_contratos_estado ON contratos(estado);
CREATE INDEX IF NOT EXISTS idx_contratos_promotor ON contratos(promotor_id);

CREATE TABLE IF NOT EXISTS contrato_productos (
  id            SERIAL PRIMARY KEY,
  contrato_id   INTEGER NOT NULL REFERENCES contratos(id) ON DELETE CASCADE,
  producto_id   INTEGER NOT NULL REFERENCES productos(id) ON DELETE RESTRICT,
  cantidad      INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_contrato_productos_contrato ON contrato_productos(contrato_id);

-- Abonos/cobros contra un contrato (reemplaza c.abonos[])
CREATE TABLE IF NOT EXISTS contrato_abonos (
  id            SERIAL PRIMARY KEY,
  contrato_id   INTEGER NOT NULL REFERENCES contratos(id) ON DELETE CASCADE,
  fecha         DATE NOT NULL DEFAULT CURRENT_DATE,
  monto         NUMERIC(12,2) NOT NULL,
  via           TEXT, -- 'cobros' | 'ruta' | 'cobrador' | 'manual' -- de donde vino el pago
  nota          TEXT,
  registrado_por INTEGER REFERENCES usuarios(id) ON DELETE SET NULL,
  creado_en     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_contrato_abonos_contrato ON contrato_abonos(contrato_id);

-- ── ALMACÉN (bodega y ruta unificados en una sola tabla de stock) ────
CREATE TABLE IF NOT EXISTS almacen_stock (
  producto_id   INTEGER NOT NULL REFERENCES productos(id) ON DELETE CASCADE,
  ubicacion     TEXT NOT NULL CHECK (ubicacion IN ('bodega','ruta')),
  cantidad      INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (producto_id, ubicacion)
);

CREATE TABLE IF NOT EXISTS almacen_entradas (
  id            SERIAL PRIMARY KEY,
  fecha         DATE NOT NULL DEFAULT CURRENT_DATE,
  proveedor     TEXT,
  registrado_por INTEGER REFERENCES usuarios(id) ON DELETE SET NULL,
  creado_en     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS almacen_entrada_items (
  id            SERIAL PRIMARY KEY,
  entrada_id    INTEGER NOT NULL REFERENCES almacen_entradas(id) ON DELETE CASCADE,
  producto_id   INTEGER NOT NULL REFERENCES productos(id) ON DELETE RESTRICT,
  cantidad      INTEGER NOT NULL
);

-- Movimientos entre bodega y ruta, y ventas directas en ruta (movAlm)
CREATE TABLE IF NOT EXISTS almacen_movimientos (
  id            SERIAL PRIMARY KEY,
  fecha         DATE NOT NULL DEFAULT CURRENT_DATE,
  tipo          TEXT NOT NULL CHECK (tipo IN ('venta','carga')),
  cliente_texto TEXT, -- nombre libre del cliente cuando es venta en ruta
  registrado_por INTEGER REFERENCES usuarios(id) ON DELETE SET NULL,
  creado_en     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS almacen_movimiento_items (
  id            SERIAL PRIMARY KEY,
  movimiento_id INTEGER NOT NULL REFERENCES almacen_movimientos(id) ON DELETE CASCADE,
  producto_id   INTEGER NOT NULL REFERENCES productos(id) ON DELETE RESTRICT,
  cantidad      INTEGER NOT NULL
);

-- Despacho de salida a ruta + arqueo al regreso
CREATE TABLE IF NOT EXISTS despachos (
  id            SERIAL PRIMARY KEY,
  fecha         DATE NOT NULL DEFAULT CURRENT_DATE,
  responsable   TEXT,
  creado_en     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS despacho_items (
  id                SERIAL PRIMARY KEY,
  despacho_id       INTEGER NOT NULL REFERENCES despachos(id) ON DELETE CASCADE,
  producto_id       INTEGER NOT NULL REFERENCES productos(id) ON DELETE RESTRICT,
  cantidad_salida   INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS arqueos (
  id            SERIAL PRIMARY KEY,
  despacho_id   INTEGER REFERENCES despachos(id) ON DELETE SET NULL,
  fecha         DATE NOT NULL DEFAULT CURRENT_DATE,
  responsable   TEXT,
  creado_en     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS arqueo_items (
  id                  SERIAL PRIMARY KEY,
  arqueo_id           INTEGER NOT NULL REFERENCES arqueos(id) ON DELETE CASCADE,
  producto_id         INTEGER NOT NULL REFERENCES productos(id) ON DELETE RESTRICT,
  cantidad_salida     INTEGER NOT NULL,
  cantidad_regreso    INTEGER NOT NULL,
  cantidad_vendida    INTEGER NOT NULL
);

-- ── COMISIONES ─────────────────────────────────────────────────────
-- Semanas de comisión: pueden ser automáticas (generadas al aprobar un
-- contrato) o cargadas manualmente con varios promotores.
CREATE TABLE IF NOT EXISTS comisiones_semanas (
  id                SERIAL PRIMARY KEY,
  fecha_desde       DATE NOT NULL,
  fecha_hasta       DATE,
  mes_pago          TEXT,
  automatica        BOOLEAN NOT NULL DEFAULT FALSE,
  contrato_id       INTEGER REFERENCES contratos(id) ON DELETE SET NULL, -- solo si automatica
  factura_texto     TEXT,
  tipo_venta        TEXT CHECK (tipo_venta IN ('credito','contado')),
  monto_venta       NUMERIC(12,2),
  total             NUMERIC(12,2) NOT NULL,
  pagado            BOOLEAN NOT NULL DEFAULT FALSE,
  registrado_por    INTEGER REFERENCES usuarios(id) ON DELETE SET NULL,
  creado_en         TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_comisiones_semanas_pagado ON comisiones_semanas(pagado);

-- Detalle por promotor cuando la semana es manual (varios promotores)
CREATE TABLE IF NOT EXISTS comisiones_semana_promotores (
  id                SERIAL PRIMARY KEY,
  semana_id         INTEGER NOT NULL REFERENCES comisiones_semanas(id) ON DELETE CASCADE,
  promotor_nombre   TEXT NOT NULL,
  venta_credito     NUMERIC(12,2) NOT NULL DEFAULT 0,
  venta_contado     NUMERIC(12,2) NOT NULL DEFAULT 0,
  comision_8        NUMERIC(12,2) NOT NULL DEFAULT 0,
  comision_16       NUMERIC(12,2) NOT NULL DEFAULT 0,
  total             NUMERIC(12,2) NOT NULL DEFAULT 0
);

-- Registro de pago del día 5 (marca semanas pendientes como pagadas)
CREATE TABLE IF NOT EXISTS comisiones_pagos (
  id                SERIAL PRIMARY KEY,
  fecha             DATE NOT NULL DEFAULT CURRENT_DATE,
  mes               TEXT,
  cantidad_semanas  INTEGER NOT NULL,
  total             NUMERIC(12,2) NOT NULL,
  registrado_por    INTEGER REFERENCES usuarios(id) ON DELETE SET NULL,
  creado_en         TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ── NÓMINA (Ley RD: AFP 2.87%, SFS 3.04%, ISR escalonado) ────────────
CREATE TABLE IF NOT EXISTS empleados (
  id              SERIAL PRIMARY KEY,
  nombre          TEXT NOT NULL,
  cedula          TEXT,
  codigo          TEXT UNIQUE,
  banco           TEXT,
  cuenta          TEXT,
  cargo           TEXT,
  departamento    TEXT,
  salario_bruto   NUMERIC(12,2) NOT NULL,
  fecha_ingreso   DATE NOT NULL DEFAULT CURRENT_DATE,
  activo          BOOLEAN NOT NULL DEFAULT TRUE,
  creado_en       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS nominas (
  id                    SERIAL PRIMARY KEY,
  mes                   TEXT NOT NULL, -- formato AAAA-MM
  quincena              TEXT NOT NULL CHECK (quincena IN ('primera','segunda')),
  fecha_pago            DATE NOT NULL,
  total_neto            NUMERIC(14,2) NOT NULL,
  total_bruto           NUMERIC(14,2) NOT NULL,
  cantidad_empleados    INTEGER NOT NULL,
  creado_en             TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (mes, quincena)
);

-- Detalle "congelado" al momento del procesamiento (no debe cambiar
-- retroactivamente si luego se edita el salario del empleado)
CREATE TABLE IF NOT EXISTS nomina_detalle (
  id              SERIAL PRIMARY KEY,
  nomina_id       INTEGER NOT NULL REFERENCES nominas(id) ON DELETE CASCADE,
  empleado_id     INTEGER REFERENCES empleados(id) ON DELETE SET NULL,
  nombre          TEXT NOT NULL,
  cedula          TEXT,
  codigo          TEXT,
  banco           TEXT,
  cuenta          TEXT,
  cargo           TEXT,
  bruto           NUMERIC(12,2) NOT NULL,
  afp             NUMERIC(12,2) NOT NULL,
  sfs             NUMERIC(12,2) NOT NULL,
  isr             NUMERIC(12,2) NOT NULL,
  total_descuento NUMERIC(12,2) NOT NULL,
  neto            NUMERIC(12,2) NOT NULL,
  escala_isr      TEXT
);
CREATE INDEX IF NOT EXISTS idx_nomina_detalle_nomina ON nomina_detalle(nomina_id);

-- ── CONTABILIDAD ──────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS asientos_contables (
  id            SERIAL PRIMARY KEY,
  fecha         DATE NOT NULL DEFAULT CURRENT_DATE,
  descripcion   TEXT NOT NULL,
  cuenta        TEXT,
  tipo          TEXT CHECK (tipo IN ('Ingreso','Gasto','Activo','Pasivo','Capital','Ajuste')),
  debe          NUMERIC(12,2) NOT NULL DEFAULT 0,
  haber         NUMERIC(12,2) NOT NULL DEFAULT 0,
  creado_por    INTEGER REFERENCES usuarios(id) ON DELETE SET NULL,
  creado_en     TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ── CUENTAS POR PAGAR ─────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS cuentas_por_pagar (
  id            SERIAL PRIMARY KEY,
  proveedor     TEXT NOT NULL,
  concepto      TEXT,
  monto         NUMERIC(12,2) NOT NULL,
  vencimiento   DATE,
  notas         TEXT,
  estado        TEXT NOT NULL DEFAULT 'pendiente' CHECK (estado IN ('pendiente','parcial','pagado')),
  creado_en     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS cuenta_por_pagar_abonos (
  id            SERIAL PRIMARY KEY,
  cuenta_id     INTEGER NOT NULL REFERENCES cuentas_por_pagar(id) ON DELETE CASCADE,
  monto         NUMERIC(12,2) NOT NULL,
  fecha         DATE NOT NULL DEFAULT CURRENT_DATE,
  nota          TEXT
);

-- ── MÓDULO COBRADOR (cobranza de campo, hoy CB_clientes) ─────────────
-- Cada fila es una cuenta por cobrar ligada a un cliente y, cuando
-- corresponde, al contrato/factura que la originó.
CREATE TABLE IF NOT EXISTS cobrador_cuentas (
  id                  SERIAL PRIMARY KEY,
  cliente_id          INTEGER NOT NULL REFERENCES clientes(id) ON DELETE RESTRICT,
  contrato_id         INTEGER REFERENCES contratos(id) ON DELETE SET NULL,
  numero_referencia    TEXT, -- el "No." original del Cobrador (puede ser el nro. de factura)
  monto               NUMERIC(12,2) NOT NULL,
  saldo                NUMERIC(12,2) NOT NULL,
  fecha_limite         DATE,
  promesa_pago         TEXT,
  notas                TEXT,
  creado_en             TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_cobrador_cuentas_cliente ON cobrador_cuentas(cliente_id);

CREATE TABLE IF NOT EXISTS cobrador_abonos (
  id            SERIAL PRIMARY KEY,
  cuenta_id     INTEGER NOT NULL REFERENCES cobrador_cuentas(id) ON DELETE CASCADE,
  monto         NUMERIC(12,2) NOT NULL,
  fecha         DATE NOT NULL DEFAULT CURRENT_DATE,
  nota          TEXT
);

-- Envíos de WhatsApp programados (recordatorios de cobro)
CREATE TABLE IF NOT EXISTS cobrador_envios_programados (
  id                SERIAL PRIMARY KEY,
  mensaje           TEXT,
  fecha_programada  TIMESTAMPTZ NOT NULL,
  destinatarios     JSONB NOT NULL DEFAULT '[]', -- lista de cobrador_cuentas.id, no es dato crítico financiero
  enviado           BOOLEAN NOT NULL DEFAULT FALSE,
  creado_en         TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ── LABORATORIO (fabricación de productos capilares/cosméticos) ──────
-- Catálogo de materias primas con inventario real (no solo referencia):
-- el stock sube con entradas (compras) y baja cuando se usa en una
-- producción. Las recetas conectan una materia prima con un producto
-- terminado del catálogo (`productos`) ya existente.
CREATE TABLE IF NOT EXISTS lab_materias_primas (
  id              SERIAL PRIMARY KEY,
  nombre          TEXT NOT NULL UNIQUE,
  tipo            TEXT NOT NULL DEFAULT 'quimico' CHECK (tipo IN ('quimico','natural')),
  unidad          TEXT NOT NULL DEFAULT 'gramos' CHECK (unidad IN ('gramos','kilogramos','onzas','galon')),
  costo_unitario  NUMERIC(12,4) NOT NULL DEFAULT 0,
  stock           NUMERIC(14,3) NOT NULL DEFAULT 0,
  activo          BOOLEAN NOT NULL DEFAULT TRUE,
  creado_en       TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Entradas (compras) de materia prima -- lo único que sube el stock
-- fuera de una corrección manual.
CREATE TABLE IF NOT EXISTS lab_entradas (
  id                SERIAL PRIMARY KEY,
  materia_prima_id  INTEGER NOT NULL REFERENCES lab_materias_primas(id) ON DELETE RESTRICT,
  cantidad          NUMERIC(14,3) NOT NULL,
  costo_total       NUMERIC(12,2),
  proveedor         TEXT,
  fecha             DATE NOT NULL DEFAULT CURRENT_DATE,
  registrado_por    INTEGER REFERENCES usuarios(id) ON DELETE SET NULL,
  creado_en         TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_lab_entradas_materia ON lab_entradas(materia_prima_id);

-- Receta/fórmula de un producto terminado: una sola por producto
-- (se reemplazan los ingredientes al guardar, como una edición completa).
-- Cuántas unidades rinde y cuánto cuesta fabricar cada una NO se
-- guardan aquí -- se calculan al vuelo (db.js) a partir del peso/volumen
-- total de los ingredientes y de contenido_por_unidad, para que si
-- cambia el costo de una materia prima el cálculo se actualice solo,
-- sin tener que volver a guardar cada receta (mismo criterio que
-- asientosAuto()/ALMA_SELECT: derivar, no cachear un valor que se
-- desactualiza).
CREATE TABLE IF NOT EXISTS lab_recetas (
  id                    SERIAL PRIMARY KEY,
  producto_id           INTEGER NOT NULL UNIQUE REFERENCES productos(id) ON DELETE CASCADE,
  contenido_por_unidad  NUMERIC(12,3) NOT NULL DEFAULT 1, -- cuánto lleva CADA unidad vendida (ej. 300 = 300 gramos por pote)
  contenido_unidad      TEXT NOT NULL DEFAULT 'gramos' CHECK (contenido_unidad IN ('gramos','kilogramos','onzas','galon')),
  notas                 TEXT,
  actualizado_en        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS lab_receta_items (
  id                SERIAL PRIMARY KEY,
  receta_id         INTEGER NOT NULL REFERENCES lab_recetas(id) ON DELETE CASCADE,
  materia_prima_id  INTEGER NOT NULL REFERENCES lab_materias_primas(id) ON DELETE RESTRICT,
  cantidad          NUMERIC(14,3) NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_lab_receta_items_receta ON lab_receta_items(receta_id);

-- Producción: fabricar `lotes` veces la receta. Descuenta cada materia
-- prima (cantidad de la receta × lotes) y, si se pidió, suma el
-- producto terminado a almacen_stock (bodega) -- misma tabla que ya
-- usa el Almacén Principal, para no duplicar el inventario de producto
-- terminado en dos lados.
-- unidades_producidas/costo_total/costo_por_unidad SÍ se guardan acá
-- (a diferencia de lab_recetas) porque son un snapshot histórico de lo
-- que realmente pasó en esa producción -- no deben cambiar si después
-- se edita la receta o cambia el precio de una materia prima.
CREATE TABLE IF NOT EXISTS lab_producciones (
  id                  SERIAL PRIMARY KEY,
  receta_id           INTEGER NOT NULL REFERENCES lab_recetas(id) ON DELETE RESTRICT,
  lotes               NUMERIC(12,3) NOT NULL DEFAULT 1,
  unidades_producidas NUMERIC(12,2) NOT NULL DEFAULT 0,
  costo_total         NUMERIC(12,2) NOT NULL DEFAULT 0,
  costo_por_unidad    NUMERIC(12,4) NOT NULL DEFAULT 0,
  sumo_almacen        BOOLEAN NOT NULL DEFAULT TRUE,
  fecha               DATE NOT NULL DEFAULT CURRENT_DATE,
  registrado_por      INTEGER REFERENCES usuarios(id) ON DELETE SET NULL,
  creado_en           TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Snapshot de lo consumido en cada producción -- si la receta cambia
-- después, el historial de qué se gastó realmente no se altera.
CREATE TABLE IF NOT EXISTS lab_produccion_items (
  id                SERIAL PRIMARY KEY,
  produccion_id     INTEGER NOT NULL REFERENCES lab_producciones(id) ON DELETE CASCADE,
  materia_prima_id  INTEGER NOT NULL REFERENCES lab_materias_primas(id) ON DELETE RESTRICT,
  cantidad_consumida NUMERIC(14,3) NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_lab_produccion_items_produccion ON lab_produccion_items(produccion_id);

-- ── CONFIGURACIÓN DE IA (Keva) ────────────────────────────────────────
-- La clave del negocio vive acá cifrada, nunca en el HTML (Etapa 6).
CREATE TABLE IF NOT EXISTS config_ia (
  proveedor       TEXT PRIMARY KEY CHECK (proveedor IN ('openai','gemini','claude')),
  api_key_cifrada TEXT,
  activo          BOOLEAN NOT NULL DEFAULT FALSE,
  actualizado_en  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Nota: la tabla de sesiones de login (connect-pg-simple) se crea sola
-- desde el backend en la Etapa 2 — no se define a mano acá.

-- ── MIGRACIONES (para bases de datos que ya existían antes de este cambio) ──
ALTER TABLE contratos ADD COLUMN IF NOT EXISTS canal TEXT NOT NULL DEFAULT 'ruta';
ALTER TABLE contrato_abonos ADD COLUMN IF NOT EXISTS via TEXT;
DO $$ BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'contratos_canal_check'
  ) THEN
    ALTER TABLE contratos ADD CONSTRAINT contratos_canal_check CHECK (canal IN ('oficina','ruta','embajadora'));
  END IF;
END $$;
ALTER TABLE clientes ADD COLUMN IF NOT EXISTS estado_crm TEXT NOT NULL DEFAULT 'nuevo';
ALTER TABLE clientes ADD COLUMN IF NOT EXISTS proximo_seguimiento DATE;
ALTER TABLE clientes ADD COLUMN IF NOT EXISTS vendedor_id INTEGER REFERENCES usuarios(id) ON DELETE SET NULL;
DO $$ BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'clientes_estado_crm_check'
  ) THEN
    ALTER TABLE clientes ADD CONSTRAINT clientes_estado_crm_check CHECK (estado_crm IN ('nuevo','contactado','interesado','cliente','inactivo'));
  END IF;
END $$;

-- Cobrador: fecha en que el cliente promete pagar (dato operativo de cobranza,
-- distinto de fecha_limite que es la fecha de vencimiento del contrato).
ALTER TABLE contratos ADD COLUMN IF NOT EXISTS promesa_pago DATE;

-- ── Laboratorio: envase/empaque como materia prima más, punto de reorden,
-- lote/vencimiento en compras, merma de producción ──
ALTER TABLE lab_materias_primas ADD COLUMN IF NOT EXISTS stock_minimo NUMERIC(14,3) NOT NULL DEFAULT 0;
-- Ensancha el CHECK de tipo para admitir 'empaque' (pote, tapa, etiqueta...):
-- se consume 1 por unidad producida, no escala con el tamaño del lote como
-- un ingrediente químico/natural. Se hace drop+recreate porque es un CHECK
-- que ya existía con menos opciones, no una columna nueva.
ALTER TABLE lab_materias_primas DROP CONSTRAINT IF EXISTS lab_materias_primas_tipo_check;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'lab_materias_primas_tipo_check') THEN
    ALTER TABLE lab_materias_primas ADD CONSTRAINT lab_materias_primas_tipo_check CHECK (tipo IN ('quimico','natural','empaque'));
  END IF;
END $$;
-- Ensancha el CHECK de unidad para admitir 'unidad' (piezas contables:
-- potes, tapas, etiquetas -- no tienen peso/volumen relevante a la fórmula).
ALTER TABLE lab_materias_primas DROP CONSTRAINT IF EXISTS lab_materias_primas_unidad_check;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'lab_materias_primas_unidad_check') THEN
    ALTER TABLE lab_materias_primas ADD CONSTRAINT lab_materias_primas_unidad_check CHECK (unidad IN ('gramos','kilogramos','onzas','galon','unidad'));
  END IF;
END $$;
ALTER TABLE lab_entradas ADD COLUMN IF NOT EXISTS lote_proveedor TEXT;
ALTER TABLE lab_entradas ADD COLUMN IF NOT EXISTS fecha_vencimiento DATE;

-- ── Ruta con Mapa: selección manual de la ruta del día ──────────────
-- Antes, la ruta se armaba sola con TODO contrato aprobado con GPS y saldo.
-- Ahora gerente/supervisor eligen a mano (buscando por factura/cédula/
-- teléfono/nombre) a quién visitar hoy; el mapa solo usa esta lista.
CREATE TABLE IF NOT EXISTS ruta_seleccion (
  id            SERIAL PRIMARY KEY,
  contrato_id   INTEGER NOT NULL REFERENCES contratos(id) ON DELETE CASCADE,
  fecha         DATE NOT NULL DEFAULT CURRENT_DATE,
  estado        TEXT NOT NULL DEFAULT 'pendiente' CHECK (estado IN ('pendiente','pagado','abonado','no_pago','saltado')),
  monto_resultado NUMERIC(12,2),
  nota          TEXT,
  visitado_en   TIMESTAMPTZ,
  agregado_por  INTEGER REFERENCES usuarios(id) ON DELETE SET NULL,
  creado_en     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_ruta_seleccion_contrato_fecha ON ruta_seleccion(contrato_id, fecha);
CREATE INDEX IF NOT EXISTS idx_ruta_seleccion_fecha ON ruta_seleccion(fecha);
ALTER TABLE lab_recetas ADD COLUMN IF NOT EXISTS merma_pct NUMERIC(5,2) NOT NULL DEFAULT 0;

-- ── Código único por producto (SKU interno, formato PRD-0001) ───────
ALTER TABLE productos ADD COLUMN IF NOT EXISTS codigo TEXT;
INSERT INTO contadores (clave, valor) VALUES ('producto', 0) ON CONFLICT (clave) DO NOTHING;
-- Rellena codigo para productos que ya existian antes de este cambio,
-- en orden de id, usando el mismo contador atomico que usaran los nuevos.
DO $$
DECLARE r RECORD; n INTEGER;
BEGIN
  FOR r IN SELECT id FROM productos WHERE codigo IS NULL ORDER BY id LOOP
    UPDATE contadores SET valor = valor + 1 WHERE clave = 'producto' RETURNING valor INTO n;
    UPDATE productos SET codigo = 'PRD-' || LPAD(n::text, 4, '0') WHERE id = r.id;
  END LOOP;
END $$;
CREATE UNIQUE INDEX IF NOT EXISTS idx_productos_codigo ON productos(codigo) WHERE codigo IS NOT NULL;
