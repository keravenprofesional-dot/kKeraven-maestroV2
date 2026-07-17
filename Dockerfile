FROM node:20-alpine
WORKDIR /app
# postgresql-client: lo necesita backup.js (pg_dump/pg_restore) para los
# respaldos desde Configuración -- sin esto, Node no encuentra los binarios.
RUN apk add --no-cache postgresql-client
COPY package.json package-lock.json* ./
RUN npm install --omit=dev
COPY . .
EXPOSE 3000
CMD ["node", "server.js"]
