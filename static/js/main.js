document.addEventListener("DOMContentLoaded", function () {
    // 1. Boutons de remplissage rapide des cibles IP
    const targetInput = document.getElementById("targetInput");
    document.querySelectorAll(".quick-ip").forEach(btn => {
        btn.addEventListener("click", function () {
            if (targetInput) {
                targetInput.value = this.dataset.ip;
                targetInput.focus();
            }
        });
    });

    // 2. Validation JS côté client + Chronomètre en direct pendant le scan
    const scanForm = document.getElementById("scanForm");
    if (scanForm && targetInput) {
        scanForm.addEventListener("submit", function (e) {
            const val = targetInput.value.trim();
            const ipRegex = /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/;
            if (!ipRegex.test(val)) {
                e.preventDefault();
                alert("Format IP invalide. Exemple attendu : 127.0.0.1 ou 192.168.56.0/24");
                return;
            }

            const spinner = document.getElementById("loadingSpinner");
            const scanBtn = document.getElementById("scanBtn");
            const timerSpan = document.getElementById("scanTimer");
            if (spinner) spinner.classList.remove("d-none");
            if (scanBtn) scanBtn.disabled = true;

            let seconds = 0;
            setInterval(() => {
                seconds++;
                if (timerSpan) timerSpan.textContent = seconds + "s";
            }, 1000);
        });
    }

    // 3. Filtrage instantané de l'historique des scans (index.html)
    const historySearch = document.getElementById("historySearch");
    if (historySearch) {
        historySearch.addEventListener("keyup", function () {
            const filter = this.value.toLowerCase();
            document.querySelectorAll("#historyTable tbody tr.scan-row").forEach(row => {
                row.style.display = row.textContent.toLowerCase().includes(filter) ? "" : "none";
            });
        });
    }

    // 4. Filtrage instantané des ports détectés (results.html)
    const portSearch = document.getElementById("portSearch");
    if (portSearch) {
        portSearch.addEventListener("keyup", function () {
            const filter = this.value.toLowerCase();
            document.querySelectorAll("tr.port-row").forEach(row => {
                row.style.display = row.textContent.toLowerCase().includes(filter) ? "" : "none";
            });
        });
    }

    // 5. Graphique interactif Chart.js pour la répartition des risques (results.html)
    const riskCanvas = document.getElementById("riskChart");
    if (riskCanvas && typeof Chart !== "undefined") {
        const high = parseInt(riskCanvas.dataset.high || "0", 10);
        const medium = parseInt(riskCanvas.dataset.medium || "0", 10);
        const low = parseInt(riskCanvas.dataset.low || "0", 10);

        new Chart(riskCanvas, {
            type: "doughnut",
            data: {
                labels: ["Risque Élevé", "Risque Moyen", "Risque Faible"],
                datasets: [{
                    data: [high, medium, low],
                    backgroundColor: ["#dc3545", "#ffc107", "#198754"],
                    borderColor: "#212529",
                    borderWidth: 2
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: "bottom",
                        labels: { color: "#ffffff", font: { size: 11 } }
                    }
                }
            }
        });
    }
});
