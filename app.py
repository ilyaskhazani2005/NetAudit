import os
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, make_response
from weasyprint import HTML

from database import init_db, save_scan, get_all_scans, get_scan_by_id, DB_NAME
from scanner import run_network_scan, calculate_audit_score
from graph_builder import generate_network_graph

app = Flask(__name__)
init_db()

@app.route("/", methods=["GET", "POST"])
def index():
    error = None
    if request.method == "POST":
        target = request.form.get("target", "").strip()
        if not target:
            error = "Veuillez entrer une adresse IP ou une plage réseau (ex: 127.0.0.1 ou 192.168.1.0/24)."
        else:
            try:
                hosts_data = run_network_scan(target)
                scan_id = save_scan(target, hosts_data)
                graph_path = generate_network_graph(hosts_data, scan_id)

                conn = sqlite3.connect(DB_NAME)
                conn.execute("UPDATE scans SET graph_path = ? WHERE id = ?", (graph_path, scan_id))
                conn.commit()
                conn.close()

                return redirect(url_for("results", scan_id=scan_id))
            except ValueError as ve:
                error = str(ve)
            except Exception as e:
                error = f"Erreur lors du scan : {str(e)}"

    scans = get_all_scans()
    return render_template("index.html", scans=scans, error=error)

@app.route("/results/<int:scan_id>")
def results(scan_id):
    scan = get_scan_by_id(scan_id)
    if not scan:
        return redirect(url_for("index"))
    audit_summary = calculate_audit_score(scan["hosts"])
    return render_template("results.html", scan=scan, audit_summary=audit_summary)

@app.route("/export-pdf/<int:scan_id>")
def export_pdf(scan_id):
    scan = get_scan_by_id(scan_id)
    if not scan:
        return redirect(url_for("index"))
    audit_summary = calculate_audit_score(scan["hosts"])

    html_content = render_template("report_pdf.html", scan=scan, audit_summary=audit_summary)
    pdf_bytes = HTML(string=html_content, base_url=os.path.abspath(".")).write_pdf()

    response = make_response(pdf_bytes)
    response.headers["Content-Type"] = "application/pdf"
    response.headers["Content-Disposition"] = f"attachment; filename=NetAudit_Rapport_{scan_id}.pdf"
    return response

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000, threaded=True)
