import os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import networkx as nx

GRAPHS_DIR = os.path.join("static", "graphs")

def generate_network_graph(hosts_data, scan_id):
    """Génère une image PNG de la topologie réseau avec NetworkX et retourne son chemin."""
    os.makedirs(GRAPHS_DIR, exist_ok=True)
    output_path = os.path.join(GRAPHS_DIR, f"scan_{scan_id}.png")

    G = nx.Graph()
    scanner_node = "NetAudit\n(Scanner)"
    G.add_node(scanner_node, node_type="scanner")

    for host in hosts_data:
        ip = host["ip"]
        hostname = host.get("hostname", "Inconnu")
        ports = host.get("ports", [])

        if ports:
            ports_str = ", ".join([f"{p['port']}/{p['service']}" for p in ports[:4]])
            if len(ports) > 4:
                ports_str += "..."
        else:
            ports_str = "Aucun port ouvert"

        label = f"{ip}\n({hostname})\n[{ports_str}]"
        G.add_node(label, node_type="host")
        G.add_edge(scanner_node, label)

    plt.figure(figsize=(10, 6), facecolor="#121417")
    ax = plt.gca()
    ax.set_facecolor("#121417")

    pos = nx.spring_layout(G, seed=42, k=1.1)

    node_colors = [
        "#dc3545" if G.nodes[n].get("node_type") == "scanner" else "#0d6efd"
        for n in G.nodes()
    ]
    node_sizes = [
        3000 if G.nodes[n].get("node_type") == "scanner" else 2400
        for n in G.nodes()
    ]

    nx.draw_networkx_edges(G, pos, edge_color="#6c757d", width=2, style="dashed")
    nx.draw_networkx_nodes(
        G, pos, node_color=node_colors, node_size=node_sizes, edgecolors="white", linewidths=1.5
    )
    nx.draw_networkx_labels(
        G, pos, font_size=8.5, font_color="white", font_weight="bold"
    )

    plt.margins(0.22)
    title_text = (
        f"Cartographie Réseau - Audit #{scan_id} ({len(hosts_data)} machine(s) active(s))"
        if hosts_data
        else f"Cartographie Réseau - Audit #{scan_id} (Aucune machine détectée)"
    )
    plt.title(title_text, color="white", fontsize=12, fontweight="bold", pad=15)
    plt.axis("off")
    plt.tight_layout()
    plt.savefig(output_path, dpi=150, facecolor="#121417")
    plt.close()

    return f"graphs/scan_{scan_id}.png"
