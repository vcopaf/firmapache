# Security Policy

## Versiones soportadas

FirMapache esta en etapa inicial. La rama principal y la version `0.1.x` reciben
correcciones de seguridad mientras el proyecto evoluciona.

| Version | Soporte |
| --- | --- |
| 0.1.x | Soportada |
| < 0.1.0 | No soportada |

## Reportar vulnerabilidades

Por favor reporte vulnerabilidades de forma privada antes de abrir un issue
publico.

Contacto:

```text
vcopafabian@gmail.com
```

Incluya, si es posible:

- version o commit afectado;
- sistema operativo;
- pasos para reproducir;
- impacto esperado;
- logs relevantes sin PIN, claves privadas ni contenido sensible.

## Alcance de seguridad

FirMapache no debe almacenar:

- PIN de token fisico fuera de la operacion de firma;
- claves privadas desencriptadas;
- sesiones PKCS#11 logueadas persistentes;
- contenido completo de documentos en diagnosticos;
- firmas completas en reportes exportados.

Los tokens virtuales PKCS#12/PFX son una herramienta para QA y entornos
controlados. Si se decide recordar una contraseña localmente, debe hacerse solo
en equipos confiables.
