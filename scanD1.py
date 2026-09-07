import subprocess
import socket
import ipaddress
import re
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor

# Puertos comunes a revisar. Podés agregar o quitar los que quieras.
PUERTOS_COMUNES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    135: "MSRPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    515: "Printer",
    631: "IPP",
    3306: "MySQL",
    3389: "RDP",
    5000: "UPnP/Flask",
    5432: "PostgreSQL",
    5353: "mDNS",
    5555: "ADB (Android)",
    62078: "iPhone-sync",
    8008: "Chromecast",
    8009: "Chromecast",
    8080: "HTTP-alt",
    8443: "HTTPS-alt",
    9100: "Printer-JetDirect",
}

# OUI (primeros 3 bytes de la MAC) -> fabricante, para no depender de internet.
# No es exhaustivo, pero cubre los fabricantes más comunes de celus, laptops y routers.
OUI_VENDORS = {
    "00:1A:11": "Google", "F4:F5:D8": "Google", "3C:5A:B4": "Google",
    "A4:77:33": "Google", "48:D6:D5": "Google", "94:EB:2C": "Google",
    "F0:F8:F2": "Apple", "AC:BC:32": "Apple", "3C:15:C2": "Apple",
    "A8:5C:2C": "Apple", "F0:18:98": "Apple", "DC:A9:04": "Apple",
    "88:E9:FE": "Apple", "40:B3:95": "Apple", "F4:5C:89": "Apple",
    "5C:59:48": "Samsung", "8C:BF:A6": "Samsung", "38:AA:3C": "Samsung",
    "AC:5F:3E": "Samsung", "E8:50:8B": "Samsung", "C0:BD:D1": "Samsung",
    "2C:54:CF": "Xiaomi", "F0:B4:29": "Xiaomi", "64:09:80": "Xiaomi",
    "8C:BE:BE": "Xiaomi", "50:8F:4C": "Xiaomi",
    "70:B3:D5": "Huawei", "48:7B:6B": "Huawei", "00:E0:FC": "Huawei",
    "94:B4:0F": "Huawei",
    "3C:97:0E": "Motorola", "40:9C:28": "Motorola",
    "B8:27:EB": "Raspberry Pi", "DC:A6:32": "Raspberry Pi", "E4:5F:01": "Raspberry Pi",
    "00:1C:42": "PC virtual (VMware/Parallels)", "08:00:27": "PC virtual (VirtualBox)",
    "00:50:56": "PC virtual (VMware)", "00:15:5D": "PC virtual (Hyper-V)",
    "00:1B:63": "Apple", "3C:07:54": "Apple",
    "AC:22:0B": "Dell", "D4:BE:D9": "Dell", "F8:BC:12": "Dell",
    "3C:D9:2B": "HP", "94:57:A5": "HP", "A0:8C:FD": "HP",
    "00:21:5A": "Lenovo", "54:EE:75": "Lenovo", "6C:29:95": "Lenovo",
    "F0:79:59": "Intel (WiFi laptop)", "34:02:86": "Intel (WiFi laptop)",
    "00:1F:3B": "Intel (WiFi laptop)",
    "18:E8:29": "TP-Link (router)", "50:C7:BF": "TP-Link (router)",
    "C4:6E:1F": "TP-Link (router)", "A0:F3:C1": "TP-Link (router)",
    "B0:4E:26": "Amazon (Echo/Fire)", "44:65:0D": "Amazon (Echo/Fire)",
    "68:37:E9": "Amazon (Echo/Fire)",
}


def obtener_red_local():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip_local = s.getsockname()[0]
    finally:
        s.close()
    red = ipaddress.ip_network(ip_local + "/24", strict=False)
    return ip_local, red


def hacer_ping(ip):
    """Pingea la IP. Devuelve (ip, ttl) si responde, o None si no."""
    try:
        resultado = subprocess.run(
            ["ping", "-c", "1", "-W", "1", str(ip)],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
    except FileNotFoundError:
        return None
    if resultado.returncode != 0:
        return None
    match = re.search(r"ttl=(\d+)", resultado.stdout, re.IGNORECASE)
    ttl = int(match.group(1)) if match else None
    return (str(ip), ttl)


def escanear_host_activo(ip_range):
    with ThreadPoolExecutor(max_workers=50) as executor:
        resultados = list(executor.map(hacer_ping, ip_range))
    return {ip: ttl for r in resultados if r for ip, ttl in [r]}


def escanear_puerto(ip, puerto, timeout=0.5):
    """Intenta conectar al puerto TCP. No requiere root (no usa sockets crudos)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        resultado = s.connect_ex((ip, puerto))
        abierto = (resultado == 0)
    except socket.error:
        abierto = False
    finally:
        s.close()
    return puerto, abierto


def escanear_puertos_de_host(ip):
    resultados = []
    with ThreadPoolExecutor(max_workers=len(PUERTOS_COMUNES)) as executor:
        futuros = [executor.submit(escanear_puerto, ip, p) for p in PUERTOS_COMUNES]
        for f in futuros:
            resultados.append(f.result())
    return sorted(resultados)


MAC_DISPONIBLE = True  # se pone en False si /proc/net/arp no es legible (Android sin root)


def obtener_mac(ip):
    """Lee la tabla ARP del sistema (/proc/net/arp).
    En Android sin root esto normalmente NO funciona (Android 10+ lo bloquea
    por privacidad), así que si falla, el script sigue sin la MAC/fabricante."""
    global MAC_DISPONIBLE
    if not MAC_DISPONIBLE:
        return None
    try:
        with open("/proc/net/arp") as f:
            for linea in f.readlines()[1:]:
                campos = linea.split()
                if len(campos) >= 4 and campos[0] == str(ip):
                    mac = campos[3].upper()
                    if mac != "00:00:00:00:00:00":
                        return mac
    except FileNotFoundError:
        pass
    except PermissionError:
        MAC_DISPONIBLE = False
        print("(Aviso: no se puede leer /proc/net/arp sin root -> no habrá MAC/fabricante, "
              "se sigue con TTL/hostname/puertos)\n")
    return None


def vendor_por_mac(mac, usar_internet=False):
    """Busca el fabricante por los primeros 3 bytes de la MAC.
    Primero prueba la tabla local; si no lo encuentra y usar_internet=True,
    consulta la API pública macvendors.com (requiere señal a internet)."""
    if not mac:
        return None
    prefijo = mac[:8]
    if prefijo in OUI_VENDORS:
        return OUI_VENDORS[prefijo]
    if usar_internet:
        try:
            req = urllib.request.Request(f"https://api.macvendors.com/{mac}")
            with urllib.request.urlopen(req, timeout=1.5) as resp:
                return resp.read().decode().strip()
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError):
            return None
    return None


def obtener_hostname(ip):
    try:
        nombre, _, _ = socket.gethostbyaddr(str(ip))
        return nombre
    except (socket.herror, socket.gaierror, OSError):
        return None


def adivinar_tipo(ttl, vendor, hostname, puertos_abiertos):
    """Heurística simple para adivinar el tipo de dispositivo.
    Combina TTL (SO probable), fabricante por MAC, hostname y puertos abiertos."""
    hostname_l = (hostname or "").lower()
    vendor_l = (vendor or "").lower()
    abiertos = {p for p, a in puertos_abiertos if a}

    # Pistas por nombre de host
    if any(p in hostname_l for p in ["iphone"]):
        return "Celular (iPhone)"
    if any(p in hostname_l for p in ["ipad"]):
        return "Tablet (iPad)"
    if any(p in hostname_l for p in ["android"]):
        return "Celular/Tablet (Android)"
    if any(p in hostname_l for p in ["desktop-", "laptop-", "pc-"]):
        return "PC/Laptop (Windows)"
    if any(p in hostname_l for p in ["macbook"]):
        return "Laptop (Mac)"

    # Pistas por fabricante (MAC)
    if vendor:
        if "router" in vendor_l:
            return f"Router/AP ({vendor})"
        if "raspberry" in vendor_l:
            return f"Raspberry Pi ({vendor})"
        if "virtual" in vendor_l:
            return f"PC virtual ({vendor})"
        if vendor_l in ("dell", "hp", "lenovo") or "intel" in vendor_l:
            return f"PC/Laptop ({vendor})"
        if vendor_l in ("apple",):
            # Apple: distinguimos por TTL/puertos si se puede, si no queda ambiguo
            if 62078 in abiertos:
                return "Celular/Tablet (Apple)"
            return "Dispositivo Apple (iPhone/iPad/Mac)"
        if vendor_l in ("samsung", "xiaomi", "huawei", "motorola", "google"):
            return f"Celular/Tablet ({vendor})"
        if "amazon" in vendor_l:
            return f"Dispositivo IoT ({vendor})"

    # Pistas por puertos abiertos
    if 445 in abiertos or 139 in abiertos or 3389 in abiertos:
        return "PC (Windows, probable)"
    if 5555 in abiertos:
        return "Celular/Tablet (Android, ADB abierto)"
    if 8008 in abiertos or 8009 in abiertos:
        return "Chromecast/TV"
    if 9100 in abiertos or 631 in abiertos or 515 in abiertos:
        return "Impresora"

    # Pistas por TTL (heurística general del SO)
    if ttl is not None:
        if ttl >= 250:
            return "Router/dispositivo de red"
        if 100 <= ttl <= 128:
            return "PC (Windows, probable por TTL)"
        if 60 <= ttl < 100:
            return "Linux/Android/Mac (por TTL, sin más datos)"

    return "Desconocido"


def escanear(usar_internet_para_vendor=False):
    ip_local, red = obtener_red_local()
    print(f"IP local: {ip_local}")
    print(f"Buscando dispositivos activos en: {red}\n")

    hosts = list(red.hosts())
    activos_ttl = escanear_host_activo(hosts)
    activos = sorted(activos_ttl.keys(), key=lambda x: ipaddress.ip_address(x))

    print(f"Dispositivos activos: {len(activos)}\n")

    for ip in activos:
        ttl = activos_ttl[ip]
        mac = obtener_mac(ip)
        vendor = vendor_por_mac(mac, usar_internet=usar_internet_para_vendor)
        hostname = obtener_hostname(ip)
        puertos = escanear_puertos_de_host(ip)
        tipo = adivinar_tipo(ttl, vendor, hostname, puertos)

        print(f"--- {ip} ---")
        if hostname:
            print(f"  Nombre:    {hostname}")
        if mac:
            print(f"  MAC:       {mac}")
        if vendor:
            print(f"  Fabricante: {vendor}")
        if ttl is not None:
            print(f"  TTL:       {ttl}")
        print(f"  Tipo estimado: {tipo}")

        for puerto, abierto in puertos:
            if abierto:
                servicio = PUERTOS_COMUNES.get(puerto, "")
                print(f"  {puerto}/tcp  ABIERTO   {servicio}")
        print()


if __name__ == "__main__":
    # Poné usar_internet_para_vendor=True si querés que, cuando la MAC no esté
    # en la tabla local, consulte la API pública macvendors.com para identificar
    # el fabricante (necesita que el celu/Termux tenga señal a internet).
    escanear(usar_internet_para_vendor=False)
