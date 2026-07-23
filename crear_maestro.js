'use strict';
// Crea la cuenta Maestro (soporte tecnico) inicial -- corre UNA sola vez:
//   node crear_maestro.js <usuario> <pin-6-digitos> ["Nombre completo"]
//   node crear_maestro.js Yave 123456 "Yave"
//
// Nadie puede crear esta cuenta desde la UI a proposito: el modulo
// Usuarios es exclusivo del rol 'maestro', y todavia no existe ninguno
// (huevo-y-gallina). Por eso corre por fuera, igual que seed_usuarios.js.
// El PIN nunca queda escrito en este archivo -- se pasa como argumento al
// ejecutarlo, no se guarda en ningun lado salvo hasheado en la base.

require('dotenv').config();
const bcrypt = require('bcrypt');
const db = require('./db');

const [, , usuarioArg, pinArg, nombreArg] = process.argv;

(async () => {
  if (!usuarioArg || !pinArg) {
    console.error('Uso: node crear_maestro.js <usuario> <pin-6-digitos> ["Nombre completo"]');
    process.exit(1);
  }
  if (!/^[A-Za-z][A-Za-z0-9]{2,20}$/.test(usuarioArg)) {
    console.error('El usuario debe empezar con una letra y tener entre 3 y 21 caracteres (letras/numeros, sin espacios).');
    process.exit(1);
  }
  if (!/^\d{6}$/.test(pinArg)) {
    console.error('El PIN debe ser de 6 digitos numericos.');
    process.exit(1);
  }

  await db.init();

  const existente = await db.buscarUsuarioPorLogin(usuarioArg);
  if (existente) {
    console.error(`Ya existe una cuenta con el usuario "${usuarioArg}" (rol ${existente.rol}). No se crea de nuevo.`);
    process.exit(1);
  }

  const nombre = nombreArg || usuarioArg;
  const pinHash = await bcrypt.hash(pinArg, 10);
  const { rows } = await db.pool.query(
    `INSERT INTO usuarios (nombre, usuario, rol, rol_label, pin_hash, color)
     VALUES ($1, $2, 'maestro', 'Maestro (Soporte Técnico)', $3, $4)
     RETURNING id, nombre, usuario, rol, rol_label`,
    [nombre, usuarioArg, pinHash, '#6B4FA0']
  );

  console.log(`Creado: ${rows[0].nombre} (@${rows[0].usuario}) — id ${rows[0].id}, rol ${rows[0].rol_label}`);
  console.log('Listo. Ya puede iniciar sesión con ese usuario y el PIN que le diste.');
  process.exit(0);
})().catch((err) => {
  console.error('Error creando el usuario Maestro:', err);
  process.exit(1);
});
