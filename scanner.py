import ipaddress
import nmap

HIGH_RISK_PORTS = {
    21: "FTP (non chiffré) : Désactiver FTP et migrer vers SFTP ou FTPS.",
    23: "Telnet (trafic en clair) : Protocole critique. Désactiver immédiatement et utiliser SSH.",
    139: "NetBIOS exposé : Restreindre l'accès via le pare-feu au réseau local uniquement.",
    445: "SMB exposé : Risque élevé (ransomware/exploits). Bloquer depuis l'extérieur et mettre à jour.",
    3389: "RDP exposé : Protéger par VPN, activer NLA et limiter les tentatives de connexion.",
    5900: "VNC exposé : Chiffrer le flux via un tunnel SSH et renforcer le mot de passe."
}

MEDIUM_RISK_PORTS = {
    53: "DNS actif : Vérifier qu'il n'est pas ouvert en résolveur public (risque d'amplification DNS).",
    80: "HTTP non chiffré : Rediriger le trafic vers HTTPS (port 443) avec un certificat TLS.",
    110: "POP3 non chiffré : Migrer vers POP3S (port 995).",
    143: "IMAP non chiffré : Migrer vers IMAPS (port 993).",
    3306: "MySQL exposé : Ne jamais exposer la base de données sur le réseau ; lier à 127.0.0.1.",
    5432: "PostgreSQL exposé : Restreindre pg_hba.conf aux adresses IP strictement autorisées.",
    8080: "HTTP alternatif non chiffré : Sécuriser l'interface d'administration et activer HTTPS."
}

def evaluate_port_risk(port):
    """Évalue le niveau de risque et retourne une recommandation pour un port ouvert."""
    if port in HIGH_RISK_PORTS:
        return {
            "risk": "Élevé",
            "risk_color": "danger",
            "recommendation": HIGH_RISK_PORTS[port]
        }
    elif port in MEDIUM_RISK_PORTS:
        return {
            "risk": "Moyen",
            "risk_color": "warning",
            "recommendation": MEDIUM_RISK_PORTS[port]
        }
    else:
        return {
            "risk": "Faible",
            "risk_color": "success",
            "recommendation": "Service standard : vérifier que la version est à jour et bien configurée."
        }

def calculate_audit_score(hosts_data):
    """Calcule un score de sécurité global sur 100 à partir des ports détectés."""
    score = 100
    high_count = 0
    medium_count = 0
    low_count = 0

    for host in hosts_data:
        for p in host.get("ports", []):
            risk = p.get("risk") or evaluate_port_risk(p["port"])["risk"]
            if risk == "Élevé":
                score -= 20
                high_count += 1
            elif risk == "Moyen":
                score -= 10
                medium_count += 1
            else:
                score -= 2
                low_count += 1

    score = max(0, score)

    if score >= 80:
        label, color = "Bon (Réseau bien sécurisé)", "success"
    elif score >= 50:
        label, color = "Moyen (Durcissement recommandé)", "warning"
    else:
        label, color = "Critique (Action immédiate requise)", "danger"

    return {
        "score": score,
        "label": label,
        "color": color,
        "high_count": high_count,
        "medium_count": medium_count,
        "low_count": low_count
    }

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
    """Exécute un scan Nmap et retourne les hôtes actifs, ports ouverts, risques et recommandations."""
    valid, result_or_msg = is_authorized_target(target)
    if not valid:
        raise ValueError(result_or_msg)

    nm = nmap.PortScanner()
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
                    risk_info = evaluate_port_risk(port)

                    ports_list.append({
                        "port": port,
                        "protocol": proto,
                        "state": port_info["state"],
                        "service": service,
                        "version": full_version,
                        "risk": risk_info["risk"],
                        "risk_color": risk_info["risk_color"],
                        "recommendation": risk_info["recommendation"]
                    })

        hosts_list.append({
            "ip": host,
            "hostname": hostname,
            "state": "up",
            "ports": ports_list
        })

    return hosts_list
