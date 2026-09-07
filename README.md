<div align="center">

```
███████╗ ██████╗███╗   ██╗       ██╗   ██╗███╗   ██╗ ██████╗ 
██╔════╝██╔════╝████╗  ██║       ██║   ██║████╗  ██║██╔═══██╗
███████╗██║     ██╔██╗ ██║ █████╗██║   ██║██╔██╗ ██║██║   ██║
╚════██║██║     ██║╚██╗██║ ╚════╝██║   ██║██║╚██╗██║██║   ██║
███████║╚██████╗██║ ╚████║       ╚██████╔╝██║ ╚████║╚██████╔╝
╚══════╝ ╚═════╝╚═╝  ╚═══╝        ╚═════╝ ╚═╝  ╚═══╝ ╚═════╝ 
```

### 🕵️ Scanner de red rápido y silencioso, escrito en Python

![Python](https://img.shields.io/badge/Python-3.x-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows-000000?style=for-the-badge&logo=linux&logoColor=white)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-red?style=for-the-badge)

</div>

---

## ⚡ Features

- 🌐 **Escaneo de IPs** — detecta hosts activos en la red
- 🔓 **Escaneo de puertos** — identifica puertos abiertos en los hosts encontrados
- 🖥️ **Detección de sistema operativo** — estima el SO de cada host escaneado

---

## 💻 Instalación

```bash
git clone https://github.com/tu-usuario/tu-repo.git
cd tu-repo
pip install -r requirements.txt
```

---

## 🚀 Uso

```bash
python scanner.py -t 192.168.1.0/24
```

| Argumento | Descripción |
|-----------|-------------|
| `-t`      | Rango de IPs o IP objetivo |
| `-p`      | Rango de puertos a escanear |
| `-o`      | Detectar sistema operativo |

---

## 🖥️ Demo

> Acá va un screenshot o GIF del scanner corriendo en terminal (fondo negro, texto verde).  
> Ejemplo: `docs/demo.gif`

```
[+] Escaneando 192.168.1.0/24 ...
[+] Host activo: 192.168.1.1  (puertos: 22, 80, 443)
[+] Host activo: 192.168.1.14 (puertos: 445)
[+] SO detectado: Linux (kernel 5.x)
```

---

## ⚠️ Disclaimer

Este proyecto fue creado con fines **educativos**. Usalo únicamente en redes propias o con autorización explícita. El autor no se responsabiliza por el mal uso de esta herramienta.

---

## 📜 Licencia

Distribuido bajo licencia MIT. Ver [`LICENSE`](LICENSE) para más información.

<div align="center">

Hecho con 🐍 y demasiado café

</div>
