# Cómo probar KERPLUS (Etapa 2 — backend)

## 1. Levantar los contenedores
```
docker compose up -d --build
```

## 2. Ver que ambos contenedores estén corriendo
```
docker compose ps
```

## 3. Sembrar los usuarios originales (una sola vez)
```
docker compose exec kerplus-app npm run seed:usuarios
```

## 4. Probar el login por API (ejemplo con el Gerente, PIN 1234)
```
curl -s -c cookies.txt -X POST http://localhost:8086/api/login \
  -H "Content-Type: application/json" \
  -d '{"usuarioId":1,"pin":"1234"}'
```
Debe devolver el usuario y sus permisos en JSON.

## 5. Ver el catálogo de productos ya autenticado
```
curl -s -b cookies.txt http://localhost:8086/api/productos
```
Debe devolver los 39 productos con precios y categorías.

## 6. Probar que un PIN incorrecto NO entra
```
curl -s -X POST http://localhost:8086/api/login \
  -H "Content-Type: application/json" \
  -d '{"usuarioId":1,"pin":"0000"}'
```
Debe devolver error 401.

## 7. Ver los logs si algo falla
```
docker compose logs kerplus-app
docker compose logs db
```
