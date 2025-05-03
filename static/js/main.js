
document.addEventListener('DOMContentLoaded', function() {
    // Toggle sidebar expansion on smaller screens
    const sidebar = document.querySelector('.sidebar');
    const toggleSidebar = document.getElementById('toggle-sidebar');
    
    if (toggleSidebar) {
        toggleSidebar.addEventListener('click', function() {
            sidebar.classList.toggle('collapsed');
            document.querySelector('.main-content').classList.toggle('expanded');
        });
    }
    
    // Initialize tooltips
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'))
    const tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl)
    });
    
    // Handle toast notifications
    const toastElList = [].slice.call(document.querySelectorAll('.toast'))
    const toastList = toastElList.map(function (toastEl) {
        return new bootstrap.Toast(toastEl)
    });
    
    // Show all toasts
    toastList.forEach(toast => toast.show());
    
    // Add date to header if element exists
    const dateElement = document.getElementById('current-date');
    if (dateElement) {
        const now = new Date();
        const options = { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' };
        dateElement.textContent = now.toLocaleDateString('fr-FR', options);
    }
});

// Terminal command handling function - used in tools page
function executeCommand(command, terminalOutput) {
    if (!terminalOutput) return;
    
    const timestamp = new Date().toLocaleTimeString();
    terminalOutput.innerHTML += `<div><span class="text-muted">[${timestamp}]</span> <span class="text-white-50">$</span> <span class="text-white">${command}</span></div>`;
    
    // Simulate command execution
    setTimeout(() => {
        let output = '';
        
        if (command.toLowerCase().includes('help')) {
            output = `Les commandes disponibles sont:
- scan [cible]: lance un scan de sécurité
- vuln: liste les vulnérabilités trouvées
- clear: efface le terminal
- help: affiche l'aide`;
        } else if (command.toLowerCase().includes('scan')) {
            const target = command.split(' ')[1] || 'localhost';
            output = `Lancement du scan sur ${target}...
[+] Scan en cours...
[+] Vérification des ports ouverts...
[+] Analyse des vulnérabilités...
[+] Scan terminé. Résultats affichés dans l'onglet Résultats.`;
        } else if (command.toLowerCase().includes('vuln')) {
            output = `Vulnérabilités détectées:
1. [CRITIQUE] Injection SQL - /admin/login.php
2. [ÉLEVÉE] XSS Persistant - /forum/message.php
3. [MOYENNE] CSRF - /user/settings.php
4. [FAIBLE] En-têtes de sécurité manquants`;
        } else if (command.toLowerCase().includes('clear')) {
            terminalOutput.innerHTML = '';
            return;
        } else {
            output = `Commande non reconnue: ${command}\nTapez 'help' pour voir les commandes disponibles.`;
        }
        
        terminalOutput.innerHTML += `<div class="ps-3">${output.replace(/\n/g, '<br>')}</div>`;
        terminalOutput.scrollTop = terminalOutput.scrollHeight;
    }, 500);
}
