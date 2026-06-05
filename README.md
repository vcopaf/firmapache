# mini-firmador

Servicio REST local en Rust que servira como bridge entre un navegador y un token
PKCS#11 para firma digital.

Esta fase expone endpoints de salud y version, selecciona una libreria PKCS#11
compatible y enumera slots con tokens presentes. Soporta el driver propietario
Feitian ePass2003 y OpenSC, y lista certificados X.509 publicos del token.
Incluye una interfaz Tauri administrativa que reutiliza el mismo core y el
mismo servidor local. Soporta JWS compact RS256 y firma PDF basica con
`ETSI.CAdES.detached`. La firma de hash requiere un PIN provisto en cada
solicitud y no lo almacena.

## Requisitos

- Rust estable con Cargo
- El modulo PKCS#11 correspondiente al token, por ejemplo el driver Feitian
  ePass2003 o OpenSC.
- `pcscd` activo cuando el token o lector requiera acceso PC/SC.
- OpenSSL de sistema para soporte PKCS#12/PFX de desarrollo (`openssl` y
  cabeceras de desarrollo si la distribucion las separa).

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

[signing]
default_identity_id = ""

[development]
enabled = false
auto_sign = false
default_identity_id = ""
pin_env = "MINI_FIRMADOR_DEV_PIN"
fallback_to_modal = true

[[development.pkcs12_tokens]]
id = "dev-token-qa"
label = "Token virtual QA"
path = "/home/user/certs/dev-token.p12"
password_env = "MINI_FIRMADOR_DEV_P12_PASSWORD"
```

`POST /config` actualiza solo los campos enviados y persiste el resultado. La
ruta PKCS#11 actualizada se usa en las siguientes operaciones. Como el
servidor no se reinicia automaticamente, los cambios de `server` y `cors`
entran en vigor al siguiente inicio.

La variable `MINI_FIRMADOR_PKCS11` mantiene prioridad absoluta sobre el valor
guardado en el TOML.

El bloque `[signing]` guarda solamente la identidad publica predeterminada para
firmar. No guarda PIN ni sesiones. Una identidad tiene la forma:

```text
pkcs11:{token_serial}:{slot_id}:{certificate_id}
```

Si el token no expone serial, se usa un identificador basado en `slot_id` y
`certificate_id`.

El bloque `[development]` existe solo para pruebas locales. Permite autofirmar
solicitudes `POST /sign` con token PKCS#11 fisico usando una identidad
configurada y un PIN leido desde una variable de entorno. El PIN nunca se guarda
en `config.toml`.

Tambien puede registrar tokens virtuales `.p12` o `.pfx` para desarrollo. En
ese caso solo se guarda la ruta del archivo y el nombre de la variable de
entorno que contiene la contraseña; no se guarda la contraseña ni la clave
privada desencriptada.

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
- Editar host, puerto y modo HTTPS del servidor local.
- Elegir una biblioteca `.so` o `.so.*` y guardarla en `config.toml`.
- Consultar tokens y certificados publicos.
- Actualizar manualmente la cache de tokens/certificados.
- Firmar manualmente archivos JSON locales como JWS compact.
- Firmar manualmente archivos PDF con una firma detached
  `ETSI.CAdES.detached`.
- Ver sesiones de firma pendientes, seleccionar identidad de firma y aprobar o rechazar
  visualmente su flujo.

La aplicacion vive en la bandeja del sistema. Al cerrar la ventana principal, la
app se oculta pero el servidor local sigue activo. Desde el tray se puede abrir
MiniFirmador, mostrar sesiones pendientes, reiniciar el servidor embebido o
salir completamente.

### Configurar servidor local desde la UI

En **Configuracion > Servidor local** se pueden editar:

- `host`, por ejemplo `127.0.0.1` o `localhost`;
- `port`, entre `1024` y `65535`;
- `https`, activado o desactivado.

La UI muestra la URL activa, por ejemplo:

```text
https://localhost:4637/
```

Los cambios se guardan en `~/.config/mini-firmador/config.toml`, pero requieren
reiniciar el servidor local para aplicarse. Use el boton **Reiniciar servidor**
desde la misma seccion o desde el menu del tray.

`0.0.0.0` se acepta para casos controlados, pero muestra una advertencia porque
expone el firmador en la red. No se recomienda para uso normal.

Pruebas rapidas:

```bash
curl -k https://localhost:4637/status
```

Si HTTPS esta desactivado:

```bash
curl http://127.0.0.1:4637/status
```

Si cambia el puerto, por ejemplo a `4638`, reinicie el servidor y pruebe:

```bash
curl -k https://localhost:4638/status
```

### Modo desarrollo con autofirma

El modo desarrollo viene desactivado por defecto. Cuando esta apagado, el flujo
normal no cambia: `POST /sign` crea una sesion pendiente y abre la ventana
`Solicitud de firma` para que el usuario seleccione identidad e ingrese PIN.

Configuracion de ejemplo:

```toml
[development]
enabled = true
auto_sign = true
default_identity_id = "pkcs11:..."
pin_env = "MINI_FIRMADOR_DEV_PIN"
fallback_to_modal = true
```

Uso:

```bash
export MINI_FIRMADOR_DEV_PIN="12345678"
cargo tauri dev
```

Con `enabled = true` y `auto_sign = true`, `POST /sign` intenta firmar
automaticamente usando `development.default_identity_id` y el PIN leido desde
`development.pin_env`. Funciona para `format = "jws"` y `format = "pdf"`.

Si falta identidad, el PIN no existe en el entorno o la autofirma falla:

- con `fallback_to_modal = true`, MiniFirmador continua con la ventana de firma
  interactiva normal;
- con `fallback_to_modal = false`, `POST /sign` responde un error JSON claro.

La UI incluye una seccion **Modo desarrollo** para activar/desactivar esta
funcion, elegir la identidad, configurar el nombre de la variable de entorno y
probar si el PIN esta disponible. No pide ni guarda el PIN.

Advertencia: no use este modo con tokens oficiales en produccion. Permite firmar
sin confirmacion visual.

### Tokens virtuales P12/PFX de desarrollo

MiniFirmador puede importar archivos `.p12` o `.pfx` existentes como identidades
virtuales de desarrollo (`provider = "pkcs12"`). Esto no reemplaza a PKCS#11 en
produccion: sirve para QA, pruebas automatizadas y ambientes locales donde no se
quiere depender de un token fisico.

Tambien puede crear un token virtual nuevo desde la UI. La app genera una clave
RSA 2048, un certificado X.509 self-signed con SHA256withRSA, KeyUsage
`digitalSignature` y `nonRepudiation`, y empaqueta clave privada + certificado
en un `.p12/.pfx` protegido por la contraseña indicada. La clave privada no se
escribe fuera del `.p12/.pfx`.

Configuracion de ejemplo:

```toml
[[development.pkcs12_tokens]]
id = "dev-token-qa"
label = "Token virtual QA"
path = "/home/user/certs/dev-token.p12"
password_env = "MINI_FIRMADOR_DEV_P12_PASSWORD"
```

Uso:

```bash
export MINI_FIRMADOR_DEV_P12_PASSWORD="clave"
cargo tauri dev
```

La UI permite importar el archivo, probar si la variable de entorno existe y
mostrar el certificado publico cuando la contraseña esta disponible. Las
identidades se muestran junto a las fisicas:

```text
[PKCS#12 DEV] Token virtual QA
  CN=Certificado Dev QA
```

Para autofirma, seleccione la identidad `pkcs12:...` como identidad de
desarrollo y active `auto_sign`. `POST /sign` sigue recibiendo el mismo payload
puro; no se agrega PIN, ruta, contraseña ni `identity_id` al contrato publico.

En firma manual, si selecciona una identidad P12, el campo de PIN se trata como
`PIN / contraseña P12` para esa firma. La contraseña no se guarda.

Crear token virtual desde la app:

1. En **Configuracion > Tokens virtuales P12/PFX**, pulse **Guardar como...** y
   elija una ruta `.p12` o `.pfx`.
2. Complete ID, etiqueta, CN, organizacion, pais, vigencia y contraseña.
3. Pulse **Crear token virtual**.
4. MiniFirmador guarda el archivo y lo registra automaticamente en
   `development.pkcs12_tokens` con `password_env = ""`.

Con `password_env = ""`, el token se puede usar en firma manual escribiendo la
contraseña en la UI. Para usarlo en autofirma, configure una variable de entorno
y actualice el TOML, por ejemplo:

```bash
export MINI_FIRMADOR_DEV_P12_PASSWORD="clave"
```

```toml
[[development.pkcs12_tokens]]
id = "dev-token-local"
label = "Token virtual local"
path = "/home/user/dev-token.p12"
password_env = "MINI_FIRMADOR_DEV_P12_PASSWORD"
```

Limitaciones de seguridad:

- no usar como modo produccion;
- no guardar contraseñas en `config.toml`;
- no exportar contraseñas en diagnostico;
- no guardar claves privadas desencriptadas en disco;
- no mantener la clave privada cargada mas tiempo del necesario para firmar.

Cuando llega una solicitud compatible, MiniFirmador abre una ventana dedicada
`Solicitud de firma` sobre el escritorio. Esa ventana pide certificado y PIN,
muestra estados de carga como `Firmando... no retire el token`, y deshabilita
los botones mientras se completa la operacion. El PIN solo existe durante esa
aprobacion y no se almacena.

## Cache de tokens y certificados

MiniFirmador carga tokens y certificados en segundo plano al iniciar Tauri para
que la ventana de firma abra rapido y no repita lecturas PKCS#11 innecesarias.
La cache guarda solamente metadata publica:

- tokens detectados;
- certificados publicos;
- DER publico del certificado en Base64;
- identidades de firma normalizadas;
- hora de carga y driver PKCS#11 usado.

No se cachea PIN, sesiones PKCS#11 logueadas, claves privadas ni contenido de
archivos. El PIN se pide solo al firmar y se limpia despues de usarlo.

La cache se invalida cuando cambia la configuracion del driver PKCS#11, cuando
se pulsa **Actualizar tokens/certificados** o cuando falla una lectura durante
la recarga. La UI muestra cantidad de tokens, cantidad de certificados, hora de
ultima carga y driver cacheado.

Los endpoints `GET /tokens` y `GET /certificates`, el modal de firma y la firma
manual prefieren la cache. Si el certificado seleccionado no esta en cache, el
core hace una recarga controlada como fallback antes de fallar.

Cada certificado utilizable se muestra como una **identidad de firma** agrupada
por token. Esto evita depender visualmente solo del `slot_id` cuando hay varios
tokens o varios certificados conectados.

La UI permite marcar una identidad con **Usar como predeterminado**. Si no hay
predeterminada y existe una sola identidad disponible, MiniFirmador la selecciona
automaticamente. Si la identidad guardada ya no esta conectada, se muestra como
no disponible y la UI advierte:

```text
El token o certificado seleccionado ya no está disponible. Actualice tokens/certificados.
```

Para invalidar o actualizar la cache, pulse **Actualizar tokens/certificados**.
Tambien se invalida al cambiar el driver PKCS#11 o cuando una lectura detecta
que el token seleccionado ya no esta disponible.

## Firma manual

La seccion **Firma manual** permite seleccionar un archivo local sin depender de
una web externa. MiniFirmador detecta automaticamente el tipo de archivo y el
formato de salida:

- JSON: genera JWS compact y abre **Guardar como** automaticamente.
- PDF: valida header `%PDF-` y marcador `%%EOF`, genera una firma PDF con
  `/Filter /Adobe.PPKLite`, `/SubFilter /ETSI.CAdES.detached`, `/ByteRange` y
  CMS/CAdES detached SHA-256, y abre **Guardar como** automaticamente.
- Otros formatos: se muestran como no soportados.

1. Abrir MiniFirmador con `cargo tauri dev`.
2. Esperar o pulsar **Actualizar tokens/certificados** si el token se conecto
   despues de abrir la app.
3. En **Firma manual**, pulsar **Seleccionar archivo**.
4. Si el archivo es JSON o PDF, seleccionar identidad de firma, escribir el PIN y
   pulsar **Firmar**.
5. Al terminar, la app abre el dialogo **Guardar como** con nombre sugerido
   `archivo.jws` para JSON o `archivo-firmado.pdf` para PDF.

El archivo guardado contiene el JWS compact en texto:

```text
header.payload.signature
```

Para PDF, el archivo guardado conserva el documento original con una firma
digital invisible. Puede inspeccionarse con:

```bash
pdfsig archivo-firmado.pdf
```

La compatibilidad esperada es:

```text
Signature Type: ETSI.CAdES.detached
Signing Hash Algorithm: SHA-256
```

Limitaciones actuales de PDF: no se implementa TSA, LTV, OCSP ni CRL. La firma
es detached y usa el certificado seleccionado desde el token PKCS#11. El PIN no
se guarda ni se registra.

## Validacion y diagnostico

La seccion **Validacion y diagnostico** permite revisar archivos firmados y el
estado local del firmador sin exponer informacion sensible.

Validacion JWS:

- acepta JWS compact directo o `Base64(JWS compact)`;
- separa `header.payload.signature`;
- muestra `alg`, presencia de `x5c`, subject del certificado si puede parsearse
  y tamano del payload;
- verifica la firma RS256 usando el certificado `x5c`.

Validacion PDF:

- detecta `/ByteRange`, `/Contents`, `/Filter /Adobe.PPKLite`,
  `/SubFilter /ETSI.CAdES.detached`, `/M`, `/Name`, `/Reason`, `/Location` y
  `/ContactInfo`;
- muestra diagnostico estructural;
- para validacion criptografica PDF completa, por ahora recomienda:

```bash
pdfsig archivo.pdf
```

Diagnostico del sistema:

- version de la app;
- configuracion no sensible del servidor;
- ruta de driver PKCS#11 configurada y detectada;
- disponibilidad basica de PC/SC;
- tokens publicos detectados;
- certificados publicos resumidos y expiracion;
- identidades de firma disponibles;
- identidad predeterminada configurada;
- certificados expirados y certificados que vencen en menos de 30 dias;
- ultimo error PKCS#11 conocido durante el diagnostico, si existe.

El boton **Exportar diagnostico** guarda un `.json` sin PIN, claves privadas,
firmas completas, archivos firmados completos ni contenido de documentos.

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

El endpoint `POST /sign` recibe el payload compatible de archivo y formato.
Actualmente soporta:

- `format = "jws"`: genera JWS compact RS256.
- `format = "pdf"`: genera PDF firmado con `ETSI.CAdES.detached`.

La solicitud HTTP queda abierta mientras espera autorizacion local.
La interfaz Tauri detecta la sesion pendiente y abre la ventana independiente
`Solicitud de firma` para aprobar o rechazar la operacion. La ventana solo
muestra nombres y tamanos aproximados de los archivos; no muestra su contenido
completo.

Al aprobar, el usuario selecciona un certificado, escribe el PIN del token y el
core genera la firma correspondiente al formato solicitado. Para JWS genera:

```text
BASE64URL(header).BASE64URL(payload).BASE64URL(signature)
```

El campo `x5c` del header contiene el certificado DER en Base64 estandar. El
JWS compact resultante se devuelve codificado nuevamente como Base64 estandar en
`response.files[].base64`.

Para PDF, `response.files[].base64` contiene el PDF firmado completo en Base64
estandar y el nombre del archivo se conserva igual al recibido.

Levantar la aplicacion:

```bash
cargo tauri dev
```

Puede cerrar la ventana principal despues de iniciar: MiniFirmador queda en
segundo plano en el tray y el servicio `https://localhost:4637/` sigue
respondiendo.

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

La terminal queda esperando. En la aplicacion Tauri aparece la ventana
`Solicitud de firma`:

1. Seleccione una identidad de firma.
2. Escriba el PIN del token.
3. Pulse **Firmar JWS** o **Firmar PDF**, segun el formato.

La terminal responde:

```json
{
  "files": [
    {
      "base64": "BASE64_DEL_JWS_COMPACT",
      "name": "solicitud.json"
    }
  ]
}
```

Para inspeccionar el JWS devuelto:

```bash
echo "BASE64_DEL_JWS_COMPACT" | base64 -d
```

Debe verse una cadena con tres partes separadas por puntos:

```text
header.payload.signature
```

Ejemplo PDF:

```bash
curl -k -X POST https://localhost:4637/sign \
  -H "Content-Type: application/json" \
  --data-raw '{
    "archivo": [
      {
        "base64": "data:application/pdf;base64,BASE64_PDF",
        "name": "documento.pdf"
      }
    ],
    "format": "pdf",
    "language": "es"
  }'
```

La app abre `Solicitud de firma`; el usuario selecciona certificado, ingresa PIN
y aprueba. Para guardar la respuesta como PDF:

```bash
echo "BASE64_RESPUESTA" | base64 -d > firmado.pdf
pdfsig firmado.pdf
```

Debe mostrar `Signature Type: ETSI.CAdES.detached`.

Repita la solicitud y pulse **Rechazar** en la ventana. El request `POST /sign`
pendiente responde:

```json
{"error":"User cancelled signing operation"}
```

El panel de sesiones tambien ofrece botones `Aprobar` y `Rechazar`. Cerrar la
ventana de firma no resuelve la solicitud: permanece pendiente y puede abrirse
nuevamente desde el panel o desde el menu del tray. Una misma sesion no genera
ventanas automaticas duplicadas.

Si falta certificado o PIN, la UI no permite aprobar. Si el login PKCS#11 falla,
se muestra el error y no se reintenta automaticamente.

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
