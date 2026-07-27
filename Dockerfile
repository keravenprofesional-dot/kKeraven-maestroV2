# ── Etapa de build: compila el addon nativo de bcrypt (python3/make/g++,
# necesarios solo para "npm install" en Alpine) -- no viajan a la imagen final.
FROM node:20-alpine AS build
WORKDIR /app
RUN apk add --no-cache python3 make g++
COPY package.json package-lock.json* ./
RUN npm install --omit=dev

# ── Etapa final: solo lo necesario para correr ───────────────────────
FROM node:20-alpine
WORKDIR /app
# postgresql-client: lo necesita backup.js (pg_dump/pg_restore) para los
# respaldos desde Configuración -- sin esto, Node no encuentra los binarios.
RUN apk add --no-cache postgresql-client
COPY --from=build /app/node_modules ./node_modules
COPY . .
# Corre como el usuario no-root "node" (ya viene en la imagen oficial) en vez
# de root -- si la app se ve comprometida, el proceso no tiene privilegios de
# root dentro del contenedor. chown despues de copiar todo: server.js crea
# carpetas en tiempo de ejecucion (ej. backups/, ver crearCarpetasFaltantes en
# db.js) y necesitan ser escribibles por "node", no solo por root.
RUN chown -R node:node /app
USER node
EXPOSE 3000
CMD ["node", "server.js"]
