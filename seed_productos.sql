-- ═══════════════════════════════════════════════════════════════════
-- Catálogo de productos KERAVEN — extraído tal cual del archivo original
-- (arreglo PRODS + precios PED_PRICES + categorías pedGetCat, líneas
-- 596, 2287-2313 de keraven_maestro_v2_37.html). Idempotente: se puede
-- correr varias veces sin duplicar (ON CONFLICT DO NOTHING).
-- ═══════════════════════════════════════════════════════════════════

INSERT INTO productos (nombre, precio_referencia, categoria) VALUES
  ('MASCARILLA COCO 10OZ',        450,  'Duo Kit 10 oz'),
  ('MASCARILLA CACAO 10OZ',       450,  'Duo Kit 10 oz'),
  ('MASCARILLA ZANAHORIA 10OZ',   450,  'Duo Kit 10 oz'),
  ('MASCARILLA BANANA 10OZ',      450,  'Duo Kit 10 oz'),
  ('MASCARILLA DETOX NEGRO 10OZ', 450,  'Duo Kit 10 oz'),
  ('MASCARILLA JENGIBRE 10OZ',    450,  'Duo Kit 10 oz'),
  ('MASCARILLA COCO 32OZ',        900,  '32 oz'),
  ('MASCARILLA CACAO 32OZ',       900,  '32 oz'),
  ('MASCARILLA ZANAHORIA 32OZ',   900,  '32 oz'),
  ('MASCARILLA BANANA 32OZ',      900,  '32 oz'),
  ('MASCARILLA DETOX 32OZ',       900,  '32 oz'),
  ('MASCARILLA JENGIBRE 32OZ',    900,  '32 oz'),
  ('SHAMPOO COCO 10OZ',           450,  'Duo Kit 10 oz'),
  ('SHAMPOO CACAO 10OZ',          450,  'Duo Kit 10 oz'),
  ('SHAMPOO ZANAHORIA 10OZ',      450,  'Duo Kit 10 oz'),
  ('SHAMPOO BANANA 10OZ',         450,  'Duo Kit 10 oz'),
  ('SHAMPOO DETOX 10OZ',          450,  'Duo Kit 10 oz'),
  ('SHAMPOO JENGIBRE 10OZ',       450,  'Duo Kit 10 oz'),
  ('SHAMPOO COCO 32OZ',           900,  '32 oz'),
  ('SHAMPOO CACAO 32OZ',          900,  '32 oz'),
  ('SHAMPOO ZANAHORIA 32OZ',      900,  '32 oz'),
  ('SHAMPOO BANANA 32OZ',         900,  '32 oz'),
  ('SHAMPOO DETOX 32OZ',          900,  '32 oz'),
  ('SHAMPOO JENGIBRE 32OZ',       900,  '32 oz'),
  ('SHAMPOO GOLDEN BLACK',        900,  'Otros'),
  ('BALSAMO GOLDEN BLACK 32OZ',   900,  'Bálsamo'),
  ('ESCULTOR RIZOS 16OZ',         900,  'Línea de Rizo'),
  ('SPRAY RIZOS 4OZ',             900,  'Línea de Rizo'),
  ('SHAMPOO RIZOS 16OZ',          900,  'Línea de Rizo'),
  ('MASCARILLA RIZOS 16OZ',       900,  'Línea de Rizo'),
  ('GOTERO CRECIMIENTO 4OZ',      900,  'Individuales'),
  ('GOTICA BRILLO 4OZ',           900,  'Individuales'),
  ('LEAVEN IN 8OZ',               900,  'Individuales'),
  ('LACEADOR 8OZ',                900,  'Individuales'),
  ('GEL INTIMO 8OZ',              900,  'Individuales'),
  ('CIRUGIA CAPILAR 16OZ',       1700,  'Tratamientos'),
  ('LINEA GOLDEN BLACK',         5300,  'Líneas Premium'),
  ('LINEA CURATIVA',             4900,  'Líneas Premium'),
  ('LINEA RIZOS',                2700,  'Líneas Premium')
ON CONFLICT (nombre) DO NOTHING;

-- Stock inicial en 0 para bodega y ruta, para cada producto del catálogo
INSERT INTO almacen_stock (producto_id, ubicacion, cantidad)
SELECT id, 'bodega', 0 FROM productos
ON CONFLICT (producto_id, ubicacion) DO NOTHING;
INSERT INTO almacen_stock (producto_id, ubicacion, cantidad)
SELECT id, 'ruta', 0 FROM productos
ON CONFLICT (producto_id, ubicacion) DO NOTHING;
