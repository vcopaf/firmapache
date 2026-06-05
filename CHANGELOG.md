# Changelog

Todos los cambios notables de FirMapache se documentan en este archivo.

El formato sigue la idea de [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
y el versionado esperado es compatible con SemVer mientras el proyecto madura.

## [0.1.0] - 2026-06-05

Canal: `stable`. Documento de release:
[docs/releases/v0.1.0.md](docs/releases/v0.1.0.md).

### Agregado

- Servicio HTTPS local en `https://localhost:4637/`.
- Endpoint compatible `POST /sign` para firma JWS y PDF.
- Flujo sincrono de firma con ventana local de aprobacion.
- Firma JWS compact RS256 compatible con `x5c`.
- Firma PDF con `ETSI.CAdES.detached`, `/ByteRange`, `/Contents` y metadata de
  diccionario de firma.
- Firma manual de archivos JSON y PDF desde la app Tauri.
- Firma manual multiarchivo con seleccion multiple, progreso, resumen y ZIP para
  multiples resultados.
- Soporte PKCS#11 para tokens fisicos, incluyendo ePass2003 con driver Feitian.
- Soporte PKCS#12/PFX para tokens virtuales de QA y desarrollo.
- Identidades de firma normalizadas para PKCS#11 y PKCS#12.
- Configuracion persistente en `~/.config/firmapache/config.toml`.
- Configuracion de servidor local desde UI: host, puerto y HTTPS.
- Bandeja del sistema, ejecucion en segundo plano y ventana dedicada de firma.
- Cache de tokens/certificados y watcher PC/SC.
- Autofirma configurable para entornos controlados.
- Validacion JWS, diagnostico estructural PDF y diagnostico exportable.

### Seguridad

- El PIN no forma parte del contrato publico de `POST /sign`.
- No se guardan claves privadas desencriptadas.
- El diagnostico exportado excluye PIN, claves privadas, firmas completas y
  contenido de documentos.

### Limitaciones conocidas

- PDF/PAdES no incluye TSA, LTV, OCSP ni CRL.
- El certificado HTTPS local es self-signed y requiere confianza manual del
  sistema si se desea evitar `curl -k`.
