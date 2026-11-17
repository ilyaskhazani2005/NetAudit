import ipaddress
import nmap

def is_authorized_target(target):
    """Vérifie que la cible est une IP ou plage IP privée autorisée (max /24)."""
    try:
        network = ipaddress.ip_network(target.strip(), strict=False)
        if not (network.is_private or network.is_loopback):
            return False, "Accès refusé : Seules les adresses IP privées (réseau local/labo) sont autorisées."
        if network.prefixlen < 24:
            return False, "Plage trop large : Utilisez un masque /24 maximum (ex: 192.168.1.0/24)."
        return True, str(network)
    except ValueError:
        return False, "Format IP invalide (exemples valides : 192.168.1.1 ou 192.168.1.0/24)."

def run_network_scan(target):
    """Exécute un scan Nmap et retourne les hôtes actifs, ports ouverts, services et versions."""
    valid, result_or_msg = is_authorized_target(target)
    if not valid:
        raise ValueError(result_or_msg)

    nm = nmap.PortScanner()
    # -sV : détection des versions | -T4 : scan rapide | --top-ports 100 : les 100 ports les plus courants
    nm.scan(hosts=result_or_msg, arguments="-sV -T4 --top-ports 100")

    hosts_list = []
    for host in nm.all_hosts():
        if nm[host].state() != "up":
            continue

        hostname = nm[host].hostname() or "Inconnu"
        ports_list = []

        for proto in nm[host].all_protocols():
            for port in sorted(nm[host][proto].keys()):
                port_info = nm[host][proto][port]
                if port_info["state"] == "open":
                    service = port_info.get("name", "inconnu")
                    product = port_info.get("product", "")
                    version = port_info.get("version", "")
                    full_version = f"{product} {version}".strip() or "Version non détectée"

                    ports_list.append({
                        "port": port,
                        "protocol": proto,
                        "state": port_info["state"],
                        "service": service,
                        "version": full_version
                    })

        hosts_list.append({
            "ip": host,
            "hostname": hostname,
            "state": "up",
            "ports": ports_list
        })

    return hosts_list

if __name__ == "__main__":
    print("Test de scan sur 127.0.0.1...")
    data = run_network_scan("127.0.0.1")
    print("Résultat :", data)
