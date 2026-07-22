# Agente de KERPLUS

KERPLUS usa un único agente consolidado, no un framework de múltiples
agentes por especialidad. Vive en `agents/keraven.md` y cubre, dentro de un
solo archivo: arquitectura, backend, base de datos, Docker/infraestructura,
Synology/NAS, seguridad, autenticación, API, frontend, UI/UX, QA, testing,
code review, performance, DevOps, documentación, refactorización, reportes,
y coordinación de pedidos multi-parte — más el conocimiento de dominio de
negocio de KERPLUS/Keraven Maestro en su propia sección.

No contiene ni hereda nada de otros proyectos o verticales (iglesias,
nutrición clínica/pediátrica, apps móviles Ionic/Capacitor) — es exclusivo
de KERPLUS.

Cómo usarlo: leer primero `PROJECT.md` y `STACK.md` como contexto de
negocio/stack real, y luego `agents/keraven.md` para las reglas técnicas y
de dominio. `CLAUDE.md` tiene precedencia sobre `agents/keraven.md` si hay
conflicto en un detalle específico de KERPLUS (puertos, roles, esquema,
definición de "cambio crítico").
