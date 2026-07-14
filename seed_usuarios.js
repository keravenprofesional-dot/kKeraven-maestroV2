'use strict';
// Carga los usuarios originales (linea 598-607 de keraven_maestro_v2_37.html)
// con sus mismos PIN de siempre, pero ahora guardados con hash bcrypt en vez
// de texto plano. Se corre una sola vez: "npm run seed:usuarios".
//
// IMPORTANTE: estos PIN (1234, 2345, etc.) son debiles -- se mantienen
// iguales solo para no obligar a redistribuir PIN nuevos de un dia para
// otro. Una vez que el panel de Usuarios este migrado (Etapa 3), se
// recomienda cambiarlos desde ahi, en especial el del Gerente y el
// Sub-Gerente que hoy comparten el mismo PIN (1234).

require('dotenv').config();
const db = require('./db');

const USUARIOS_ORIGINALES = [
  { nombre: 'José Augusto Durán García', rol: 'gerente',    rolLabel: 'Gerente General',   pin: '1234', color: '#B8860B' },
  { nombre: 'Leticia Sofía López',       rol: 'subgerente', rolLabel: 'Sub Gerente',        pin: '1234', color: '#856408' },
  { nombre: 'Manuel Ventura',      rol: 'coordinador', rolLabel: 'Coordinador Operativo',   pin: '2345', color: '#185FA5' },
  { nombre: 'Supervisor',          rol: 'supervisor',  rolLabel: 'Supervisor de Ruta',      pin: '3456', color: '#0F6E56' },
  { nombre: 'Encargado Almacén',   rol: 'almacen',     rolLabel: 'Encargado de Almacén',    pin: '6789', color: '#5B4E8A' },
  { nombre: 'Promotor A',          rol: 'promotor',    rolLabel: 'Promotor',                pin: '4444', color: '#C05621' },
  { nombre: 'Promotor B',          rol: 'promotor',    rolLabel: 'Promotor',                pin: '5555', color: '#2C7A7B' },
  { nombre: 'Promotor C',          rol: 'promotor',    rolLabel: 'Promotor',                pin: '6666', color: '#702459' },
];

(async () => {
  await db.init();
  const existentes = await db.listarUsuariosActivos();
  if (existentes.length > 0) {
    console.log(`Ya hay ${existentes.length} usuario(s) en la base de datos. No se vuelve a sembrar (para no duplicar).`);
    process.exit(0);
  }
  for (const u of USUARIOS_ORIGINALES) {
    const creado = await db.crearUsuario(u);
    console.log(`Creado: ${creado.nombre} (${creado.rol_label}) — id ${creado.id}`);
  }
  console.log('Listo. Recuerda cambiar los PIN repetidos/débiles desde el panel de Usuarios apenas puedas.');
  process.exit(0);
})().catch((err) => {
  console.error('Error sembrando usuarios:', err);
  process.exit(1);
});
