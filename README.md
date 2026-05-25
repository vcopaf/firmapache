# mini-firmador

Servicio REST local en Rust que servira como bridge entre un navegador y un token
PKCS#11 para firma digital.

Esta fase expone endpoints de salud y version, selecciona una libreria PKCS#11
compatible y enumera slots con tokens presentes. Soporta el driver propietario
Feitian ePass2003 y OpenSC, y lista certificados X.509 publicos del token. No
implementa firma, PIN, procesamiento PDF/XML ni interfaz de escritorio.

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
2. El driver Feitian ePass2003 en su ruta comun de instalacion.
3. Rutas comunes de OpenSC en Linux.

Si `MINI_FIRMADOR_PKCS11` esta definida pero no existe, el servicio informa el
error en los endpoints PKCS#11 en lugar de usar automaticamente otro modulo.

## Ejecutar

```bash
cargo run
```

El servidor escucha en `http://127.0.0.1:4856`.

## Verificar

```bash
cargo check
curl http://127.0.0.1:4856/status
curl http://127.0.0.1:4856/version
curl http://127.0.0.1:4856/pkcs11/library
curl http://127.0.0.1:4856/tokens
curl http://127.0.0.1:4856/certificates
```

Para probar explicitamente un ePass2003 con el driver propietario:

```bash
export MINI_FIRMADOR_PKCS11=/usr/lib/ePass2003-Linux-x64/redist/libcastle.so.1.0.0
cargo run

curl http://127.0.0.1:4856/pkcs11/library
curl http://127.0.0.1:4856/tokens
curl http://127.0.0.1:4856/certificates
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

El listado de slots incluye datos publicos del token cuando esta presente:

```json
[{"slot_id":1,"token_present":true,"label":"ePass2003","manufacturer":"Feitian Technologies Co., Ltd","model":"ePass2003","serial_number":"..."}]
```

Los certificados publicos encontrados se devuelven con su identificador y
metadatos X.509:

```json
[{"slot_id":1,"id":"01","label":"Certificado de firma","subject":"CN=...","issuer":"CN=...","serial_number":"...","not_before":"2024-...","not_after":"2026-..."}]
```

Si no se encuentra la biblioteca PKCS#11, `/tokens` responde con HTTP 500:

```json
{"error":"PKCS#11 library not found"}
```

## Estructura

- `src/api`: rutas y handlers HTTP.
- `src/config`: configuracion del servicio local.
- `src/error`: errores convertibles a respuestas HTTP.
- `src/models`: modelos JSON de la API.
- `src/pkcs11`: deteccion del proveedor y espacio para token y firma PKCS#11.
- `src/utils`: utilidades compartidas futuras.
