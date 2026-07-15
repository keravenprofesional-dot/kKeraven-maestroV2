-- ═══════════════════════════════════════════════════════════════════
-- Catálogo inicial de materias primas para el Laboratorio (química
-- capilar y cosmética). Es un punto de partida -- se edita libremente
-- desde la pestaña "Almacén de Laboratorio" (agregar, editar, dar de
-- baja). Idempotente: se puede correr varias veces sin duplicar.
-- Precios y stock arrancan en 0; se cargan con la primera entrada real.
-- ═══════════════════════════════════════════════════════════════════

INSERT INTO lab_materias_primas (nombre, tipo, unidad) VALUES
  -- ── Aceites naturales ──
  ('Aceite de Coco',                  'natural', 'galon'),
  ('Aceite de Argán',                 'natural', 'galon'),
  ('Aceite de Ricino',                'natural', 'galon'),
  ('Aceite de Oliva',                 'natural', 'galon'),
  ('Aceite de Jojoba',                'natural', 'galon'),
  ('Aceite de Almendras Dulces',      'natural', 'galon'),
  ('Aceite de Aguacate',              'natural', 'galon'),
  ('Aceite de Girasol',               'natural', 'galon'),
  ('Aceite Mineral',                  'quimico', 'galon'),
  ('Aceite Esencial de Romero',       'natural', 'onzas'),
  ('Aceite Esencial de Lavanda',      'natural', 'onzas'),
  ('Aceite de Semilla de Uva',        'natural', 'galon'),

  -- ── Mantecas ──
  ('Manteca de Karité',               'natural', 'kilogramos'),
  ('Manteca de Cacao',                'natural', 'kilogramos'),
  ('Manteca de Mango',                'natural', 'kilogramos'),

  -- ── Proteínas e hidrolizados ──
  ('Queratina Hidrolizada',           'quimico', 'kilogramos'),
  ('Colágeno Hidrolizado',            'quimico', 'kilogramos'),
  ('Proteína de Trigo Hidrolizada',   'quimico', 'kilogramos'),
  ('Proteína de Seda Hidrolizada',    'quimico', 'kilogramos'),
  ('Aminoácidos Capilares',           'quimico', 'kilogramos'),

  -- ── Humectantes ──
  ('Glicerina Vegetal',               'natural', 'galon'),
  ('Pantenol (Provitamina B5)',       'quimico', 'kilogramos'),
  ('Ácido Hialurónico',               'quimico', 'gramos'),
  ('Sorbitol',                        'quimico', 'kilogramos'),
  ('Propilenglicol',                  'quimico', 'galon'),
  ('Urea Cosmética',                  'quimico', 'kilogramos'),

  -- ── Emulsificantes ──
  ('BTMS-50 (Emulsificante Catiónico)','quimico', 'kilogramos'),
  ('Alcohol Cetílico',                'quimico', 'kilogramos'),
  ('Alcohol Cetearílico',             'quimico', 'kilogramos'),
  ('Emulsificante E-2000',            'quimico', 'kilogramos'),
  ('Polisorbato 20',                  'quimico', 'kilogramos'),
  ('Polisorbato 80',                  'quimico', 'kilogramos'),

  -- ── Tensioactivos / surfactantes (base de shampoo) ──
  ('Sodium Lauryl Sulfate (SLS)',     'quimico', 'kilogramos'),
  ('Sodium Laureth Sulfate (SLES)',   'quimico', 'kilogramos'),
  ('Cocamidopropil Betaína',          'quimico', 'kilogramos'),
  ('Decyl Glucoside',                 'quimico', 'kilogramos'),
  ('Cocamida DEA',                    'quimico', 'kilogramos'),

  -- ── Conservantes ──
  ('Fenoxietanol',                    'quimico', 'kilogramos'),
  ('Metilisotiazolinona',             'quimico', 'gramos'),
  ('Ácido Sórbico',                   'quimico', 'kilogramos'),
  ('Ácido Benzoico',                  'quimico', 'kilogramos'),
  ('Benzoato de Sodio',               'quimico', 'kilogramos'),

  -- ── Espesantes / reguladores de viscosidad ──
  ('Carbómero',                       'quimico', 'kilogramos'),
  ('Goma Xantana',                    'natural', 'kilogramos'),
  ('Hidroxietilcelulosa (HEC)',       'quimico', 'kilogramos'),
  ('Cloruro de Sodio (Espesante)',    'quimico', 'kilogramos'),

  -- ── Siliconas ──
  ('Dimeticona',                      'quimico', 'kilogramos'),
  ('Ciclometicona',                   'quimico', 'kilogramos'),
  ('Amodimeticona',                   'quimico', 'kilogramos'),

  -- ── Ácidos y reguladores de pH ──
  ('Ácido Cítrico',                   'quimico', 'kilogramos'),
  ('Ácido Láctico',                   'quimico', 'kilogramos'),

  -- ── Extractos naturales ──
  ('Extracto de Aloe Vera',           'natural', 'galon'),
  ('Extracto de Romero',              'natural', 'galon'),
  ('Extracto de Manzanilla',          'natural', 'galon'),
  ('Extracto de Té Verde',            'natural', 'galon'),
  ('Extracto de Ortiga',              'natural', 'galon'),
  ('Gel de Sábila (Aloe Vera Puro)',  'natural', 'galon'),

  -- ── Vitaminas y activos ──
  ('Vitamina E (Tocoferol)',          'quimico', 'kilogramos'),
  ('Vitamina A (Retinol)',            'quimico', 'gramos'),
  ('Biotina',                         'quimico', 'gramos'),
  ('Niacinamida',                     'quimico', 'kilogramos'),

  -- ── Otros / base ──
  ('Agua Destilada',                  'natural', 'galon'),
  ('Colorante Cosmético',             'quimico', 'onzas'),
  ('Fragancia / Esencia',             'quimico', 'onzas'),
  ('Mentol',                          'quimico', 'kilogramos'),
  ('Miel de Abeja',                   'natural', 'kilogramos'),
  ('Cera de Abeja',                   'natural', 'kilogramos')
ON CONFLICT (nombre) DO NOTHING;

-- ── Empaque (pote/tapa/etiqueta/funda/caja) -- se consume 1 por unidad
-- terminada, no por lote (ver lógica en db.js _labCalcularReceta). Los
-- tamaños siguen las presentaciones que ya vende el catálogo (10oz,
-- 32oz, 16oz, 8oz, 4oz -- ver seed_productos.sql). Los costos son un
-- estimado de referencia para el mercado dominicano -- AJÚSTALOS a lo
-- que realmente te cobra tu proveedor desde la pestaña de edición.
INSERT INTO lab_materias_primas (nombre, tipo, unidad, costo_unitario) VALUES
  ('Pote plástico 4 oz',              'empaque', 'unidad', 18),
  ('Pote plástico 8 oz',              'empaque', 'unidad', 25),
  ('Pote plástico 10 oz',             'empaque', 'unidad', 28),
  ('Pote plástico 16 oz',             'empaque', 'unidad', 35),
  ('Pote plástico 32 oz',             'empaque', 'unidad', 48),
  ('Envase gotero 4 oz',              'empaque', 'unidad', 30),
  ('Envase spray 4 oz',               'empaque', 'unidad', 32),
  ('Envase bomba/dispensador 8 oz',   'empaque', 'unidad', 40),
  ('Tapa rosca genérica',             'empaque', 'unidad', 6),
  ('Etiqueta impresa',                'empaque', 'unidad', 8),
  ('Funda/bolsa plástica',            'empaque', 'unidad', 3),
  ('Caja individual (línea premium)', 'empaque', 'unidad', 25)
ON CONFLICT (nombre) DO NOTHING;
