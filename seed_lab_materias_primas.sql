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
