# Semana 6 Políticas como código

Aplicación mínima Go y frontend HTML para verificar políticas OPA/Conftest.
Las tareas de la demostración se almacenan en memoria. No contiene el código
de la plantilla original ni acredita implementaciones de semanas anteriores.
Las políticas son reutilizables en el proyecto del curso; conservar sus controles
existentes al integrar los jobs. No reemplazar un pipeline ajeno sin revisarlo.

## Requisitos

- Conftest 0.71.1 (OPA 1.21.1).
- Go 1.27.3 para pruebas nativas.
- Docker Engine/Desktop y Compose para la ejecución en contenedores.
- GitLab con ejecutor compatible para comprobar los pipelines reales.

## Políticas

1. `policy/dockerfile/security.rego`: la etapa final debe declarar un UID numérico
   no cero; se considera el último USER y se detectan ENV/ARG con nombres sensibles.
2. `policy/compose/security.rego`: todos los servicios declaran UID numérico no
   cero; rechaza privileged y socket Docker; rechaza secretos literales y puertos
   publicados o de destino inferiores a 1024, incluidos rangos y sintaxis larga.

Variables sensibles solo pueden referenciar un secreto por ruta `/run/secrets/`
en una variable `_FILE`, o una expansión obligatoria `${VARIABLE:?mensaje}`.
El escaneo se aplica al YAML fuente SIN resolver: normalizar con secretos reales
podría exponerlos en salida. Estas reglas no son un detector universal de secretos;
revisar nombres no habituales, archivos externos e historial con controles adicionales.

Los secretos sintéticos de `fixtures/insecure/` son valores ficticios deliberados
para probar rechazos. No desplegar esos archivos ni usarlos para configurar cuentas.

## Verificación local reproducible

```text
python scripts/validate-local.py --conftest RUTA_A_CONFTEST
cd backend
go vet ./...
go test -v ./...
```

El script exige códigos 1 en los casos inseguros y códigos 0 en los corregidos.
Un error inesperado detiene la verificación. Los registros se guardan en artifacts/.

## Secretos de laboratorio y despliegue

```text
python scripts/init-secrets.py
powershell -File scripts/deploy.ps1 -Conftest RUTA_A_CONFTEST
```

El generador no muestra el secreto. `.secrets/`, `.env` y variantes están excluidos
de Git y del contexto de Docker; `.env.example` se conserva como documentación.
El contenedor solo recibe el archivo que necesita. En Windows, proteger la carpeta
con los permisos de la cuenta. En Linux, conservar el archivo privado y otorgar
lectura al UID 10001 mediante una ACL; no hacer el secreto legible para todos.
Compose puede no aplicar uid/gid/mode cuando el origen es un archivo vinculado.

Abrir http://127.0.0.1:8080/. `/healthz` es público; `/api/tasks` exige Bearer token.
No incluir la clave ni el campo completado en capturas. La aplicación no persiste
la clave en el almacenamiento del navegador. Esta demostración requiere TLS y
gestión de identidad por usuario antes de un uso productivo.

## GitLab CI/CD

`verify` ejecuta pruebas Go y Rego. `policy:gate` evalúa los archivos reales con
`allow_failure: false`. La etapa `build` solo comienza si todo lo anterior pasa.
Se construye/publica únicamente desde la rama predeterminada protegida.
Las credenciales temporales del registro se toman de variables predefinidas;
no se configuran manualmente ni se guardan como artefactos.

La imagen BuildKit rootless usa el modo documentado por GitLab con
`--oci-worker-no-process-sandbox`. Requiere un ejecutor compatible y aislado;
rootless no elimina todos los riesgos del runner ni justifica habilitar privilegios
o desactivar protecciones de un ejecutor compartido. Revisar la política corporativa.

Para la prueba roja: en una rama de ensayo introducir `user: "0:0"` en el servicio
web, registrar el cambio y ejecutar el pipeline. El job policy:gate debe fallar.
Corregir a `10001:10001`, registrar otro commit y repetir. Conservar URL, ID de
pipeline, commit y logs de ambas ejecuciones. No alterar las reglas para ocultar
el error ni convertir un fallo del gate en opcional.

Una prueba unitaria que espera rechazo y termina correctamente NO es una ejecución
roja de GitLab. Los registros locales tampoco equivalen a capturas de GitLab.

## Variables CI/CD sensibles

En Settings > CI/CD > Variables, usar tipo File para secretos que consuman los
jobs; protegerlas para ramas/tags protegidos y marcarlas ocultas/enmascaradas
cuando corresponda. No exponerlas a forks o scripts no revisados. El API key
de ejecución local no se necesita para construir la imagen y no debe entregarse
al job de build. Capturar solo nombres, tipo y flags, sin el valor del secreto.

No incluir archivos .env reales, claves, tokens ni salidas de `env` o `printenv`
en el repositorio, artefactos o evidencias. Ver USO_IA.md para la declaración de apoyo.
