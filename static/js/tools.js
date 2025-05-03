
document.addEventListener('DOMContentLoaded', function() {
    // Gestion des états de l'application
    const appState = {
        results: [],
        selectedTool: null,
        currentProject: {
            name: "Site Web E-commerce",
            targetDomain: "example.com",
            targetIP: "192.168.1.100",
            targetType: "Web Application",
            technologies: ["PHP", "MySQL", "Apache"]
        }
    };

    // Références DOM
    const toolSelector = document.getElementById('toolSelector');
    const toolInterface = document.getElementById('toolInterface');
    const toolCards = document.querySelectorAll('.tool-card');
    const backToToolsBtn = document.querySelector('.back-to-tools');
    const toolNameEl = document.querySelector('.tool-name');
    const terminalOutput = document.querySelector('.terminal-output');
    const commandInput = document.querySelector('.command-input');
    const executeBtn = document.querySelector('.execute-btn');
    const clearTerminalBtn = document.getElementById('clearTerminal');
    const operationSelect = document.querySelector('.operation-select');
    const simpleCommandInput = document.querySelector('.simple-command-input');
    const simpleExecuteBtn = document.querySelector('.simple-execute-btn');
    const simpleOutput = document.querySelector('.simple-output');
    const simpleOutputText = document.querySelector('.simple-output-text');
    const clearOutputBtn = document.querySelector('.clear-output-btn');
    const resultsTableBody = document.getElementById('resultsTableBody');
    const remediationTableBody = document.getElementById('remediationTableBody');
    const remediationBtns = document.querySelectorAll('.apply-remediation');
    const remediationMethods = document.querySelectorAll('.remediation-method');
    
    // Toast de notification
    const toast = new bootstrap.Toast(document.getElementById('notificationToast'));
    const toastTitle = document.querySelector('.toast-title');
    const toastBody = document.querySelector('.toast-body');

    // Configuration des outils
    const tools = {
        "owaspzap": {
            name: "OWASP ZAP",
            icon: "globe",
            operations: [
                { label: "Scan complet", value: "full-scan" },
                { label: "Scan passif", value: "passive-scan" },
                { label: "Scan d'API", value: "api-scan" }
            ],
            getCommand: function(operation) {
                const domain = appState.currentProject?.targetDomain || "example.com";
                switch (operation) {
                    case "full-scan":
                        return `python zap.py -t http://${domain} -m scan`;
                    case "passive-scan":
                        return `python zap.py -t http://${domain} -m passive`;
                    case "api-scan":
                        return `python zap.py -t http://${domain}/api -m api`;
                    default:
                        return `python zap.py -t http://${domain} -m scan`;
                }
            }
        },
        "nmap": {
            name: "Nmap",
            icon: "search",
            operations: [
                { label: "Scan rapide", value: "quick-scan" },
                { label: "Détection de version", value: "version-detection" },
                { label: "Détection d'OS", value: "os-detection" },
                { label: "Scan complet", value: "comprehensive" }
            ],
            getCommand: function(operation) {
                const target = appState.currentProject?.targetIP || 
                            appState.currentProject?.targetDomain || 
                            "example.com";
                switch (operation) {
                    case "quick-scan":
                        return `nmap -F ${target}`;
                    case "version-detection":
                        return `nmap -sV ${target}`;
                    case "os-detection":
                        return `nmap -O ${target}`;
                    case "comprehensive":
                        return `nmap -sS -sV -A -T4 ${target}`;
                    default:
                        return `nmap -sV ${target}`;
                }
            }
        },
        "sqlmap": {
            name: "SQLMap",
            icon: "database",
            operations: [
                { label: "Détection de base de données", value: "database-detection" },
                { label: "Détection de tables", value: "tables-detection" },
                { label: "Extraction de données", value: "dump-data" }
            ],
            getCommand: function(operation) {
                const domain = appState.currentProject?.targetDomain || "example.com";
                switch (operation) {
                    case "database-detection":
                        return `sqlmap -u "http://${domain}/page.php?id=1" --dbs`;
                    case "tables-detection":
                        return `sqlmap -u "http://${domain}/page.php?id=1" -D <database> --tables`;
                    case "dump-data":
                        return `sqlmap -u "http://${domain}/page.php?id=1" -D <database> -T <table> --dump`;
                    default:
                        return `sqlmap -u "http://${domain}/page.php?id=1" --dbs`;
                }
            }
        }
    };

    // Configurer les événements pour les cartes d'outils
    toolCards.forEach(card => {
        card.addEventListener('click', () => {
            const toolId = card.getAttribute('data-tool-id');
            selectTool(toolId);
        });
    });

    // Sélection d'un outil
    function selectTool(toolId) {
        const tool = tools[toolId];
        if (tool) {
            appState.selectedTool = {
                id: toolId,
                ...tool
            };
            
            // Mettre à jour l'interface
            toolSelector.classList.add('d-none');
            toolInterface.classList.remove('d-none');
            toolNameEl.textContent = tool.name;
            
            // Mettre à jour les options du mode simple
            operationSelect.innerHTML = '';
            const defaultOption = document.createElement('option');
            defaultOption.value = '';
            defaultOption.textContent = 'Sélectionner une option';
            operationSelect.appendChild(defaultOption);
            
            tool.operations.forEach(op => {
                const option = document.createElement('option');
                option.value = op.value;
                option.textContent = op.label;
                operationSelect.appendChild(option);
            });
            
            // Sélectionner la première opération par défaut
            if (tool.operations && tool.operations.length > 0) {
                operationSelect.value = tool.operations[0].value;
                updateSimpleCommand(tool.operations[0].value);
            }
            
            // Notification
            showToast("Outil sélectionné", `L'outil "${tool.name}" a été sélectionné.`);
        }
    }

    // Retour à la liste des outils
    if (backToToolsBtn) {
        backToToolsBtn.addEventListener('click', () => {
            toolInterface.classList.add('d-none');
            toolSelector.classList.remove('d-none');
            appState.selectedTool = null;
        });
    }

    // Gestion du terminal
    if (executeBtn) {
        executeBtn.addEventListener('click', executeCommand);
    }

    if (commandInput) {
        commandInput.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') {
                executeCommand();
            }
        });
    }

    if (clearTerminalBtn) {
        clearTerminalBtn.addEventListener('click', () => {
            terminalOutput.textContent = 'Prêt à exécuter des commandes...';
        });
    }

    // Exécution de commande
    function executeCommand() {
        if (!commandInput.value.trim()) return;
        
        const command = commandInput.value.trim();
        terminalOutput.textContent = `Exécution de: ${command}\n\n`;
        
        simulateCommandExecution(command, terminalOutput)
            .then((output) => {
                const result = createResult(command, output);
                appState.results.push(result);
                updateResultsTable();
            });
    }

    // Mode simple
    if (operationSelect) {
        operationSelect.addEventListener('change', function() {
            const operation = this.value;
            updateSimpleCommand(operation);
        });
    }

    function updateSimpleCommand(operation) {
        if (appState.selectedTool && operation) {
            const command = appState.selectedTool.getCommand(operation);
            simpleCommandInput.value = command;
        }
    }

    if (simpleExecuteBtn) {
        simpleExecuteBtn.addEventListener('click', () => {
            if (!simpleCommandInput.value.trim()) return;
            
            const command = simpleCommandInput.value.trim();
            simpleOutput.classList.remove('d-none');
            simpleOutputText.textContent = `Exécution de: ${command}\n\n`;
            
            simulateCommandExecution(command, simpleOutputText)
                .then((output) => {
                    const result = createResult(command, output);
                    appState.results.push(result);
                    updateResultsTable();
                });
        });
    }

    if (clearOutputBtn) {
        clearOutputBtn.addEventListener('click', () => {
            simpleOutputText.textContent = '';
            simpleOutput.classList.add('d-none');
        });
    }

    // Remédiation
    remediationBtns.forEach((btn, index) => {
        btn.addEventListener('click', () => {
            const type = btn.getAttribute('data-type');
            const method = remediationMethods[index].value;
            
            if (method) {
                applyRemediation(type, method);
            } else {
                showToast("Erreur", "Veuillez sélectionner une méthode de remédiation.", "danger");
            }
        });
    });

    function applyRemediation(type, method) {
        const remediationOutputs = {
            "firewall": "Configuration du pare-feu terminée avec succès.\n\n- Règles configurées pour filtrer le trafic malveillant\n- Ports non nécessaires fermés\n- Journalisation des tentatives bloquées activée",
            "iptables": "Configuration iptables terminée avec succès.\n\n```\n# Règles ajoutées:\niptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --set\niptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 60 --hitcount 4 -j DROP\n```",
            "webapp": "Correctifs des vulnérabilités d'application web appliqués.\n\n- Validation des entrées renforcée\n- Protection XSS mise en place\n- Tokens CSRF implémentés\n- Headers de sécurité configurés"
        };
        
        const output = remediationOutputs[type] || "Remédiation appliquée avec succès.";
        
        const result = {
            id: `remediation-${Date.now()}`,
            timestamp: new Date().toISOString(),
            toolName: "Remédiation",
            command: `${method} pour ${type}`,
            details: "Résultat de la remédiation",
            rawOutput: output,
            target: appState.currentProject?.targetDomain || "",
            severity: "info",
            findingType: "Remédiation"
        };
        
        appState.results.push(result);
        updateRemediationTable();
        
        showToast("Remédiation appliquée", `${method} a été appliqué pour résoudre ${type}`);
    }

    // Simuler l'exécution de commande avec effet de frappe
    async function simulateCommandExecution(command, outputElement) {
        let output = "";
        
        if (command.includes("nmap")) {
            await typeText("Starting Nmap 7.94 ( https://nmap.org )\n", outputElement);
            await typeText("Scanning targets...\n", outputElement);
            await typeText("Scanning 1 host [1000 ports]\n", outputElement);
            await typeText("Discovered open port 80/tcp on 192.168.1.1\n", outputElement);
            await typeText("Discovered open port 443/tcp on 192.168.1.1\n", outputElement);
            await typeText("Discovered open port 22/tcp on 192.168.1.1\n", outputElement);
            output = "Port scanning completed. Found 3 open ports.";
        } else if (command.includes("sqlmap")) {
            await typeText("Initializing sqlmap engine...\n", outputElement);
            await typeText("Testing connection to the target URL\n", outputElement);
            await typeText("Checking if the target is protected by WAF/IPS\n", outputElement);
            await typeText("Testing for SQL injection vulnerabilities\n", outputElement);
            await typeText("Found SQL injection vulnerability in parameter 'id'\n", outputElement);
            await typeText("Extracting database information\n", outputElement);
            output = "Database extraction complete. Found 3 databases.";
        } else if (command.includes("owasp") || command.includes("zap")) {
            await typeText("Initializing OWASP ZAP...\n", outputElement);
            await typeText("Exploring the application...\n", outputElement);
            await typeText("Spider completed, found 24 unique URLs\n", outputElement);
            await typeText("Scanning for vulnerabilities...\n", outputElement);
            await typeText("Found Cross-Site Scripting (XSS) vulnerability\n", outputElement);
            await typeText("Found SQL Injection vulnerability\n", outputElement);
            output = "Scan completed. Found 5 high, 8 medium, 3 low vulnerabilities.";
        } else {
            await typeText("Exécution de la commande...\n", outputElement);
            await typeText("Traitement en cours...\n", outputElement);
            output = "Commande exécutée avec succès.";
        }
        
        await typeText("\n" + output + "\n", outputElement);
        return output;
    }

    // Effet de frappe
    async function typeText(text, element) {
        for (let i = 0; i < text.length; i++) {
            element.textContent += text.charAt(i);
            element.scrollTop = element.scrollHeight;
            await new Promise(resolve => setTimeout(resolve, Math.random() * 10));
        }
    }

    // Créer un résultat
    function createResult(command, output) {
        return {
            id: `result-${Date.now()}`,
            timestamp: new Date().toISOString(),
            toolName: appState.selectedTool?.name || "Unknown",
            command: command,
            details: "Résultat de l'exécution de la commande",
            rawOutput: output,
            target: appState.currentProject?.targetDomain || command.split(' ')[1],
            severity: Math.random() > 0.5 ? 'high' : 'medium',
            findingType: appState.selectedTool?.id === 'nmap' 
                ? 'Port Ouvert' 
                : appState.selectedTool?.id === 'sqlmap' 
                    ? 'Injection SQL' 
                    : 'Vulnérabilité'
        };
    }

    // Mise à jour des tableaux de résultats
    function updateResultsTable() {
        const filteredResults = appState.results.filter(r => r.toolName !== "Remédiation");
        updateTable(resultsTableBody, filteredResults);
    }

    function updateRemediationTable() {
        const filteredResults = appState.results.filter(r => r.toolName === "Remédiation");
        updateTable(remediationTableBody, filteredResults);
    }

    function updateTable(tableBody, results) {
        if (results.length === 0) {
            tableBody.innerHTML = `
                <tr>
                    <td colspan="8" class="text-center text-muted py-4">
                        Aucun résultat disponible.
                    </td>
                </tr>
            `;
            return;
        }

        tableBody.innerHTML = '';
        
        results.forEach(result => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>
                    <button class="btn btn-sm btn-link p-0 toggle-details" data-result-id="${result.id}">
                        <i class="bi bi-chevron-down"></i>
                    </button>
                </td>
                <td class="text-nowrap">${new Date(result.timestamp).toLocaleString()}</td>
                <td>${result.toolName}</td>
                <td class="text-truncate" style="max-width: 150px;">
                    <code>${result.command}</code>
                </td>
                <td>${result.target || '-'}</td>
                <td>${result.findingType || '-'}</td>
                <td>
                    ${result.severity ? getSeverityBadge(result.severity) : '-'}
                </td>
                <td>
                    <button class="btn btn-sm btn-link p-1 export-btn" title="Exporter" data-result-id="${result.id}">
                        <i class="bi bi-download"></i>
                    </button>
                </td>
            `;
            tableBody.appendChild(row);
            
            // Add event listeners for expand/collapse and export
            const toggleBtn = row.querySelector('.toggle-details');
            toggleBtn.addEventListener('click', () => {
                toggleResultDetails(result.id, toggleBtn);
            });
            
            const exportBtn = row.querySelector('.export-btn');
            exportBtn.addEventListener('click', () => {
                showResultDetails(result);
            });
        });
    }

    // Afficher/Masquer les détails d'un résultat
    function toggleResultDetails(resultId, button) {
        const result = appState.results.find(r => r.id === resultId);
        if (!result) return;
        
        const resultRow = button.closest('tr');
        let detailsRow = resultRow.nextElementSibling;
        
        if (detailsRow && detailsRow.classList.contains('details-row')) {
            // Hide details
            detailsRow.remove();
            button.innerHTML = '<i class="bi bi-chevron-down"></i>';
        } else {
            // Show details
            detailsRow = document.createElement('tr');
            detailsRow.classList.add('details-row');
            detailsRow.innerHTML = `
                <td colspan="8">
                    <div class="p-3 bg-light rounded">
                        <h6 class="fw-bold mb-2">Détails</h6>
                        <p class="mb-3">${result.details}</p>
                        
                        <h6 class="fw-bold mb-2">Sortie brute</h6>
                        <pre class="bg-dark text-light p-2 rounded" style="max-height: 200px; overflow: auto;">${result.rawOutput}</pre>
                    </div>
                </td>
            `;
            
            resultRow.parentNode.insertBefore(detailsRow, resultRow.nextSibling);
            button.innerHTML = '<i class="bi bi-chevron-up"></i>';
        }
    }

    // Afficher les détails du résultat dans une modal
    function showResultDetails(result) {
        const modal = new bootstrap.Modal(document.getElementById('resultDetailModal'));
        document.querySelector('.result-details').textContent = result.details;
        document.querySelector('.result-output').textContent = result.rawOutput;
        
        const exportBtn = document.querySelector('.export-result');
        exportBtn.onclick = () => {
            showToast("Export réussi", `Le résultat de ${result.toolName} a été exporté.`);
            modal.hide();
        };
        
        modal.show();
    }

    // Gestion des notifications
    function showToast(title, message, type = "info") {
        toastTitle.textContent = title;
        toastBody.textContent = message;
        
        // Reset classes
        const toastEl = document.getElementById('notificationToast');
        toastEl.className = 'toast';
        
        // Add appropriate color based on type
        if (type === "danger") {
            toastEl.classList.add('bg-danger', 'text-white');
        } else if (type === "warning") {
            toastEl.classList.add('bg-warning');
        } else if (type === "success") {
            toastEl.classList.add('bg-success', 'text-white');
        } else {
            toastEl.classList.add('bg-info', 'text-white');
        }
        
        toast.show();
    }

    // Utility functions
    function getSeverityBadge(severity) {
        let bgClass = '';
        switch (severity) {
            case 'critical': bgClass = 'bg-danger'; break;
            case 'high': bgClass = 'bg-danger'; break;
            case 'medium': bgClass = 'bg-warning'; break;
            case 'low': bgClass = 'bg-success'; break;
            case 'info': bgClass = 'bg-info'; break;
            default: bgClass = 'bg-secondary'; break;
        }
        
        return `<span class="badge ${bgClass}">${severity.toUpperCase()}</span>`;
    }

    // Initialisation
    function init() {
        // Mise à jour des tableaux
        updateResultsTable();
        updateRemediationTable();
    }

    init();
});
