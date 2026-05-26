# mini-firmador

Servicio REST local en Rust que servira como bridge entre un navegador y un token
PKCS#11 para firma digital.

Esta fase expone endpoints de salud y version, selecciona una libreria PKCS#11
compatible y enumera slots con tokens presentes. Soporta el driver propietario
Feitian ePass2003 y OpenSC, y lista certificados X.509 publicos del token. No
implementa procesamiento PDF/XML. Incluye una interfaz Tauri administrativa
minima que reutiliza el mismo core y el mismo servidor local. La firma de hash
requiere un PIN provisto en cada solicitud y no lo almacena.

## Requisitos

- Rust estable con Cargo
- El modulo PKCS#11 correspondiente al token, por ejemplo el driver Feitian
  ePass2003 o OpenSC.
- `pcscd` activo cuando el token o lector requiera acceso PC/SC.

## PKCS#11, Feitian y OpenSC

PKCS#11 es la interfaz estandar que permite a una aplicacion comunicarse con
tokens criptograficos. Algunos dispositivos, como ePass2003, requieren el
modulo propietario Feitian (`libcastle.so.1.0.0`) aunque OpenSC pueda detectar
el lector. OpenSC provee una implementacion generica mediante
`opensc-pkcs11.so`. `pcscd` es el servicio que suele comunicar estos modulos
con lectores de tarjetas inteligentes.

El servicio selecciona el modulo en este orden:

1. La ruta configurada en `MINI_FIRMADOR_PKCS11`.
2. La ruta persistida en `~/.config/mini-firmador/config.toml`.
3. El driver Feitian ePass2003 en su ruta comun de instalacion.
4. Rutas comunes de OpenSC en Linux.

Si `MINI_FIRMADOR_PKCS11` esta definida pero no existe, el servicio informa el
error en los endpoints PKCS#11 en lugar de usar automaticamente otro modulo.
Si una ruta persistida no existe, el servicio registra la situacion y continua
con la autodeteccion.

## Configuracion persistente

Al iniciar, el servicio crea y carga automaticamente:

```text
~/.config/mini-firmador/config.toml
```

En Linux esta ruta se obtiene mediante el directorio de configuracion del
usuario. El archivo inicial tiene este formato:

```toml
[server]
host = "127.0.0.1"
port = 4637
https = true

[pkcs11]
library_path = "/usr/lib/libcastle.so.1.0.0"

[cors]
allowed_origins = [
  "http://localhost:3000",
  "http://127.0.0.1:3000",
]
```

`POST /config` actualiza solo los campos enviados y persiste el resultado. La
ruta PKCS#11 actualizada se usa en las siguientes operaciones. Como el
servidor no se reinicia automaticamente, los cambios de `server` y `cors`
entran en vigor al siguiente inicio.

La variable `MINI_FIRMADOR_PKCS11` mantiene prioridad absoluta sobre el valor
guardado en el TOML.

Con `server.https = true`, el servicio genera automaticamente un certificado
self-signed para `localhost` y `127.0.0.1` en:

```text
~/.config/mini-firmador/certs/localhost.crt
~/.config/mini-firmador/certs/localhost.key
```

El certificado local no se instala en el trust store del sistema. Por eso
`curl` requiere `-k` hasta que el certificado se configure como confiable.
Al cargar un archivo creado por una version anterior sin `server.https`, el
antiguo puerto por defecto `4856` se migra automaticamente a `4637`; puertos
personalizados se conservan.

## Ejecutar

```bash
cargo run
```

Por defecto el servidor escucha en `https://localhost:4637/`.

Para desarrollo sin TLS, establezca `https = false` en el bloque `[server]`;
en ese modo escucha en `http://127.0.0.1:4637/`.

```bash
curl http://127.0.0.1:4637/
curl http://127.0.0.1:4637/status
```

## Interfaz Tauri

La aplicacion de escritorio inicia el mismo servicio Axum local y comparte su
`AppState` con los comandos Tauri; no duplica operaciones PKCS#11 ni logica de
firma. Para levantarla en desarrollo:

```bash
cargo install tauri-cli --version "^2" --locked
cargo tauri dev
```

No ejecute `cargo run` al mismo tiempo: la aplicacion Tauri ya arranca el
servicio local en el puerto configurado.

La ventana permite:

- Ver estado, version, modo HTTPS, puerto y driver PKCS#11 detectado.
- Elegir una biblioteca `.so` o `.so.*` y guardarla en `config.toml`.
- Consultar tokens y certificados publicos.
- Ver sesiones de firma pendientes y autorizar o rechazar visualmente su flujo.

La interfaz no solicita ni almacena PIN, y todavia no ejecuta una firma
criptografica. La aprobacion visual solo completa el flujo temporal devolviendo
el Base64 normalizado; los endpoints internos se mantienen para desarrollo.

## Consumo desde NextJS

El servicio habilita CORS solamente para aplicaciones web servidas desde:

- `http://localhost:3000`
- `http://127.0.0.1:3000`

No se habilita el origen comodin (`*`). Las solicitudes desde otros orígenes
no reciben autorización CORS por defecto.

Ejemplo de consulta desde un componente o acción cliente de NextJS:

```ts
const response = await fetch("https://localhost:4637/certificates", {
  method: "GET",
  headers: {
    "Content-Type": "application/json",
  },
});

if (!response.ok) {
  throw new Error("No se pudieron cargar los certificados");
}

const certificates = await response.json();
```

Para `POST /sign/hash`, el navegador puede enviar JSON desde esos mismos
orígenes; el PIN debe existir solo en la solicitud iniciada por el usuario y
no debe almacenarse en el frontend.

## Verificar

```bash
cargo check
curl -k https://localhost:4637/
curl -k https://localhost:4637/status
curl -k https://localhost:4637/version
curl -k https://localhost:4637/config
curl -k https://localhost:4637/pkcs11/library
curl -k https://localhost:4637/tokens
curl -k https://localhost:4637/certificates
```

Para probar explicitamente un ePass2003 con el driver propietario:

```bash
export MINI_FIRMADOR_PKCS11=/usr/lib/ePass2003-Linux-x64/redist/libcastle.so.1.0.0
cargo run

curl -k https://localhost:4637/pkcs11/library
curl -k https://localhost:4637/tokens
curl -k https://localhost:4637/certificates
```

Respuestas esperadas:

```json
{"status":"ok","service":"mini-firmador"}
```

```json
{"name":"mini-firmador","version":"0.1.0"}
```

Si el driver Feitian se selecciona automaticamente:

```json
{"found":true,"path":"/usr/lib/ePass2003-Linux-x64/redist/libcastle.so.1.0.0","source":"auto"}
```

Si se selecciona usando la variable de entorno, `source` es `"env"`.
Si se selecciona desde `config.toml`, `source` es `"config"`.

El listado de slots incluye datos publicos del token cuando esta presente:

```json
[{"slot_id":1,"token_present":true,"label":"ePass2003","manufacturer":"Feitian Technologies Co., Ltd","model":"ePass2003","serial_number":"..."}]
```

Los certificados publicos encontrados se devuelven con su identificador,
certificado DER en base64 y metadatos X.509:

```json
[{"slot_id":1,"id":"01","label":"Certificado de firma","certificate_der_base64":"MIIC...","subject":"CN=...","issuer":"CN=...","serial_number":"...","not_before":"2024-...","not_after":"2026-..."}]
```

## API de configuracion

Consultar la configuracion activa:

```bash
curl -k https://localhost:4637/config
```

Actualizar, por ejemplo, solamente el driver PKCS#11:

```bash
curl -k -X POST https://localhost:4637/config \
  -H "Content-Type: application/json" \
  -d '{
    "pkcs11": {
      "library_path": "/usr/lib/libcastle.so.1.0.0"
    }
  }'
```

La configuracion no contiene PIN, certificados privados, sesiones ni datos
sensibles del token.

## Firma compatible sincrona

El endpoint `POST /sign` recibe el payload compatible de archivo y formato
`"jws"`. La solicitud HTTP queda abierta mientras espera autorizacion local.
La interfaz Tauri detecta la sesion pendiente y abre un modal para aprobar o
rechazar la operacion. El modal solo muestra nombres y tamanos aproximados de
los archivos; no recibe ni muestra su contenido completo.

Todavia no se genera un JWS ni se realiza una operacion de firma con el token.
El resultado aprobado devuelve los mismos archivos con Base64 normalizado.

Terminal 1:

```bash
curl -k -X POST https://localhost:4637/sign \
  -H "Content-Type: application/json" \
  --data-raw '{
    "archivo": [
      {
        "base64": "data:application/json;base64,eyJob2xhIjoibXVuZG8ifQ==",
        "name": "solicitud.json"
      }
    ],
    "format": "jws",
    "language": "es"
  }'
```

La terminal queda esperando. En la aplicacion Tauri aparece el modal
`Solicitud de firma`; al pulsar **Aprobar**, la terminal responde:

```json
{
  "files": [
    {
      "base64": "eyJob2xhIjoibXVuZG8ifQ==",
      "name": "solicitud.json"
    }
  ]
}
```

Repita la solicitud y pulse **Rechazar** en el modal. El request `POST /sign`
pendiente responde:

```json
{"error":"User cancelled signing operation"}
```

El panel de sesiones tambien ofrece botones `Aprobar` y `Rechazar`. Cerrar el
modal no resuelve la solicitud: permanece pendiente y puede abrirse nuevamente
desde el panel. Una misma sesion no genera modales automaticos duplicados.

Los endpoints `/sign/sessions/{id}/approve` y `/reject` se conservan como
herramientas internas de desarrollo.

Si una solicitud no se resuelve en cinco minutos, responde con HTTP 408:

```json
{"error":"Signing request expired"}
```

El campo `base64` de entrada tambien puede enviarse sin el prefijo `data:`;
la salida siempre contiene Base64 estandar limpio.

## Firma de hash

El endpoint `POST /sign/hash` acepta un hash codificado en base64 y firma sus
bytes con el mecanismo `RSA_PKCS`. El flujo recomendado selecciona el
certificado cuya clave privada debe utilizarse.

1. Listar los certificados publicos del token y copiar el campo `id` elegido:

```bash
curl -k https://localhost:4637/certificates
```

2. Generar un hash SHA-256 base64 de prueba:

```bash
HASH=$(echo -n "hola" | openssl dgst -sha256 -binary | base64)
```

3. Firmar indicando el `certificate_id`. Reemplace los valores de ejemplo
localmente; el PIN no se registra ni se conserva por el servicio:

```bash
curl -k -X POST https://localhost:4637/sign/hash \
  -H "Content-Type: application/json" \
  -d '{
    "slot_id": 1,
    "certificate_id": "PEGAR_ID_DEL_CERTIFICADO",
    "pin": "CAMBIAR_POR_PIN_REAL",
    "hash_base64": "PEGAR_HASH_BASE64",
    "mechanism": "RSA_PKCS"
  }'
```

Respuesta:

```json
{"slot_id":1,"signature_base64":"...","algorithm":"RSA_PKCS","certificate_id":"PEGAR_ID_DEL_CERTIFICADO"}
```

**Advertencia de seguridad:** el token puede bloquearse tras intentos de PIN
incorrectos. `mini-firmador` realiza un solo intento de login por solicitud y
no reintenta automaticamente cuando la autenticacion falla.

Si se omite `certificate_id`, el servicio conserva el modo compatible anterior
y selecciona una clave privada disponible, registrando una advertencia. No se
recomienda omitirlo si el token contiene mas de un certificado.

## Verificacion local

El endpoint `POST /verify/hash` verifica una firma `RSA_PKCS` usando solo el
certificado publico devuelto por `/certificates`. No requiere PIN y no accede
a la clave privada ni al token.

```bash
curl -k -X POST https://localhost:4637/verify/hash \
  -H "Content-Type: application/json" \
  -d '{
    "certificate_der_base64": "BASE64_CERT_DER_OBTENIDO_DE_CERTIFICATES",
    "hash_base64": "BASE64_DEL_HASH",
    "signature_base64": "BASE64_DE_LA_FIRMA",
    "mechanism": "RSA_PKCS"
  }'
```

Respuesta cuando la firma corresponde al hash y certificado:

```json
{"valid":true,"algorithm":"RSA_PKCS"}
```

Una firma no válida responde exitosamente con `"valid": false`.

Si no se encuentra la biblioteca PKCS#11, `/tokens` responde con HTTP 500:

```json
{"error":"PKCS#11 library not found"}
```

## Estructura

- `src-tauri`: aplicacion de escritorio y comandos que consumen el core.
- `ui`: interfaz HTML/CSS/JavaScript minima para administracion local.
- `src/server`: rutas y handlers HTTP.
- `src/config`: configuracion del servicio local.
- `src/core`: operaciones reutilizables de PKCS#11, criptografia y firma.
- `src/error`: errores convertibles a respuestas HTTP.
- `src/models`: modelos JSON de la API.
- `src/utils`: utilidades compartidas futuras.
