# Paquete Arch Linux

Este directorio contiene un `PKGBUILD` local para construir FirMapache como
paquete nativo de Arch Linux. Esta base puede adaptarse luego para AUR.

## Dependencias

Instale las dependencias de compilacion y runtime:

```bash
sudo pacman -S --needed rust cargo nodejs npm pkgconf webkit2gtk-4.1 \
  libayatana-appindicator openssl pcsclite ccid opensc
```

## Construir e instalar

Desde la raiz del repositorio:

```bash
cd packaging/arch
makepkg -si
```

O, desde la raiz del repositorio, puede usar el script auxiliar:

```bash
./scripts/build-arch-package.sh
```

## PC/SC

Para tokens fisicos, active `pcscd`:

```bash
sudo systemctl enable --now pcscd
```

## ePass2003 / Feitian

FirMapache no empaqueta el driver propietario Feitian. Si usa ePass2003,
configure la ruta del driver PKCS#11 desde la UI o en `config.toml`.

Rutas comunes:

```text
/usr/lib/libcastle.so.1.0.0
/usr/lib/ePass2003-Linux-x64/redist/libcastle.so.1.0.0
/usr/lib/ePass2003_adsib/redist/libcastle.so.1.0.0
```

## Ejecutar

```bash
firmapache
```

## AUR

Antes de publicar en AUR, regenere `.SRCINFO`:

```bash
makepkg --printsrcinfo > .SRCINFO
```
