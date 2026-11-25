# NetAudit — Network Security Auditing & Topology Mapping

**NetAudit** is a full-stack web application designed for authorized local network discovery, vulnerability/risk assessment, topology visualization, and automated PDF audit reporting.

## Key Features
- **Automated Network Discovery & Port Scanning:** Leverages `Nmap` to detect active hosts, open ports, running services, and OS/service versions across local subnets.
- **Security Controls & Scope Validation:** Enforces private IPv4/CIDR validation to restrict scans to authorized internal networks.
- **Interactive Topology Graph:** Generates dynamic network maps using `NetworkX` to visualize host relationships and exposed services.
- **Audit History & Persistence:** Stores scan sessions, host inventories, and risk scores in a structured `SQLite` database.
- **Automated PDF Audit Reports:** Exports clean, executive-ready security audit reports directly from scan results.

## Tech Stack
- **Backend:** Python, Flask, `python-nmap`, NetworkX, SQLite
- **Frontend:** HTML5, CSS3, Bootstrap, JavaScript
- **Reporting:** HTML-to-PDF rendering

## Installation & Usage

1. **Clone the repository:**
   ```bash
   git clone [https://github.com/ilyaskhazani2005/NetAudit.git](https://github.com/ilyaskhazani2005/NetAudit.git)
   cd NetAudit
