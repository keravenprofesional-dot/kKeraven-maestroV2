FROM node:20-alpine
WORKDIR /app
# postgresql-client: lo necesita backup.js (pg_dump/pg_restore) para los
# respaldos desde Configuración -- sin esto, Node no encuentra los binarios.
# python3/make/g++: bcrypt (nativo, reemplazo de bcryptjs) necesita compilar
# su addon en el build -- sin esto, "npm install" falla en Alpine.
RUN apk add --no-cache postgresql-client python3 make g++
COPY package.json package-lock.json* ./
RUN npm install --omit=dev
COPY . .
EXPOSE 3000
CMD ["node", "server.js"]
