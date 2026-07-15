// ── Respaldo y restauración de la base de datos ──────────────────────
// Usa pg_dump/pg_restore por línea de comandos (formato "custom", -F c)
// en vez de manejar SQL a mano -- es el mecanismo estándar y confiable
// de Postgres. En Windows busca la instalación típica si no está en el
// PATH; en Linux/Docker confía en que la imagen tenga postgresql-client
// instalado (ver Dockerfile).
const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');

const BACKUPS_DIR = path.join(__dirname, 'backups');

function _pgBinPath(nombre) {
  if (os.platform() === 'win32') {
    for (const v of ['17', '16', '15', '14']) {
      const candidato = `C:\\Program Files\\PostgreSQL\\${v}\\bin\\${nombre}.exe`;
      if (fs.existsSync(candidato)) return candidato;
    }
  }
  return nombre; // confía en el PATH
}

function _parseDatabaseUrl(url) {
  const u = new URL(url);
  return {
    host: u.hostname,
    port: u.port || '5432',
    user: decodeURIComponent(u.username),
    password: decodeURIComponent(u.password),
    database: u.pathname.replace(/^\//, ''),
  };
}

function _ejecutar(bin, args, env) {
  return new Promise((resolve, reject) => {
    const proc = spawn(_pgBinPath(bin), args, { env: { ...process.env, ...env } });
    let stderr = '';
    proc.stderr.on('data', (d) => { stderr += d.toString(); });
    proc.on('close', (code) => resolve({ code, stderr }));
    proc.on('error', (err) => reject(new Error(`No se pudo ejecutar ${bin}: ${err.message}`)));
  });
}

async function crearBackup(etiqueta) {
  await fs.promises.mkdir(BACKUPS_DIR, { recursive: true });
  const db = _parseDatabaseUrl(process.env.DATABASE_URL);
  const marca = new Date().toISOString().replace(/[:.]/g, '-');
  const limpio = etiqueta ? String(etiqueta).trim().replace(/[^a-zA-Z0-9_-]+/g, '_').slice(0, 40) : '';
  const nombre = `kerplus_${marca}${limpio ? '__' + limpio : ''}.dump`;
  const archivo = path.join(BACKUPS_DIR, nombre);

  const { code, stderr } = await _ejecutar(
    'pg_dump',
    ['-h', db.host, '-p', db.port, '-U', db.user, '-d', db.database, '-F', 'c', '-f', archivo],
    { PGPASSWORD: db.password }
  );
  if (code !== 0) {
    await fs.promises.unlink(archivo).catch(() => {});
    throw new Error('pg_dump falló: ' + stderr.slice(-500));
  }
  return { archivo: nombre, creadoEn: new Date().toISOString() };
}

async function listarBackups() {
  await fs.promises.mkdir(BACKUPS_DIR, { recursive: true });
  const archivos = await fs.promises.readdir(BACKUPS_DIR);
  const info = await Promise.all(
    archivos.filter((f) => f.endsWith('.dump')).map(async (f) => {
      const st = await fs.promises.stat(path.join(BACKUPS_DIR, f));
      return { archivo: f, tamanoBytes: st.size, creadoEn: st.birthtime && st.birthtime.getTime() > 0 ? st.birthtime : st.ctime };
    })
  );
  return info.sort((a, b) => new Date(b.creadoEn) - new Date(a.creadoEn));
}

// Sobrescribe TODO lo que haya en la base de datos con lo del respaldo
// elegido. Antes de tocar nada, crea un respaldo del estado actual --
// si la restauración fue un error, ese respaldo "antes_de_restaurar"
// permite deshacerlo.
async function restaurarBackup(nombreArchivo) {
  const nombreSeguro = path.basename(String(nombreArchivo || '')); // evita path traversal
  const archivo = path.join(BACKUPS_DIR, nombreSeguro);
  if (!nombreSeguro.endsWith('.dump') || !fs.existsSync(archivo)) {
    throw new Error('Ese respaldo no existe');
  }
  const antes = await crearBackup('antes_de_restaurar');
  const db = _parseDatabaseUrl(process.env.DATABASE_URL);
  const { code, stderr } = await _ejecutar(
    'pg_restore',
    ['-h', db.host, '-p', db.port, '-U', db.user, '-d', db.database, '--clean', '--if-exists', '--no-owner', '--no-privileges', archivo],
    { PGPASSWORD: db.password }
  );
  // pg_restore a veces devuelve código distinto de 0 por avisos menores
  // (ej. un rol que no existe en este servidor) sin que la restauración
  // haya fallado de verdad -- por eso NO se lanza como excepción, pero
  // tampoco se le miente al que lo pidió: ok refleja el código real, y
  // avisos siempre va para que la pantalla pueda mostrar la advertencia
  // si algo no quedó perfecto.
  return { ok: code === 0, avisos: stderr.slice(-800), backupDeSeguridad: antes.archivo };
}

module.exports = { crearBackup, listarBackups, restaurarBackup, BACKUPS_DIR };
