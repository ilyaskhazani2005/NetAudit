import sqlite3
import json
from datetime import datetime

DB_NAME = "netaudit.db"

def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            scan_date TEXT NOT NULL,
            hosts_count INTEGER NOT NULL,
            open_ports_count INTEGER NOT NULL,
            results_json TEXT NOT NULL,
            graph_path TEXT
        )
    """)
    conn.commit()
    conn.close()

def save_scan(target, hosts_data, graph_path=""):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    scan_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    hosts_count = len(hosts_data)
    open_ports_count = sum(len(host["ports"]) for host in hosts_data)
    results_json = json.dumps(hosts_data)
    
    cursor.execute("""
        INSERT INTO scans (target, scan_date, hosts_count, open_ports_count, results_json, graph_path)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (target, scan_date, hosts_count, open_ports_count, results_json, graph_path))
    
    scan_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return scan_id

def get_all_scans():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT id, target, scan_date, hosts_count, open_ports_count FROM scans ORDER BY id DESC")
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def get_scan_by_id(scan_id):
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
    row = cursor.fetchone()
    conn.close()
    if row:
        data = dict(row)
        data["hosts"] = json.loads(data["results_json"])
        return data
    return None

if __name__ == "__main__":
    init_db()
    print("Base de données netaudit.db initialisée avec succès !")
