
// JavaScript pour l'interface d'administration

document.addEventListener('DOMContentLoaded', function() {
    // Initialiser les tooltips Bootstrap
    var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'))
    var tooltipList = tooltipTriggerList.map(function(tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl)
    });

    // Initialiser les popovers Bootstrap
    var popoverTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="popover"]'))
    var popoverList = popoverTriggerList.map(function(popoverTriggerEl) {
        return new bootstrap.Popover(popoverTriggerEl)
    });

    // Fonction pour configurer les graphiques si Chart.js est disponible
    if (typeof Chart !== 'undefined') {
        setupAdminCharts();
    }

    // Support du mode sombre
    const darkModeToggle = document.getElementById('darkModeOption');
    if (darkModeToggle) {
        darkModeToggle.addEventListener('change', function() {
            document.body.classList.toggle('dark-mode', this.checked);
            localStorage.setItem('darkMode', this.checked ? 'enabled' : 'disabled');
        });

        // Appliquer le mode sombre si activé
        if (localStorage.getItem('darkMode') === 'enabled') {
            darkModeToggle.checked = true;
            document.body.classList.add('dark-mode');
        }
    }
});

// Configuration des graphiques pour le tableau de bord
function setupAdminCharts() {
    // Cette fonction sera appelée quand Chart.js est disponible
    // Les graphiques individuels sont configurés dans leurs vues respectives
}

// Fonction pour afficher les notifications d'administration
function showAdminNotification(message, type = 'info') {
    const notificationDiv = document.createElement('div');
    notificationDiv.className = `toast align-items-center text-white bg-${type} border-0`;
    notificationDiv.role = 'alert';
    notificationDiv.setAttribute('aria-live', 'assertive');
    notificationDiv.setAttribute('aria-atomic', 'true');
    
    notificationDiv.innerHTML = `
        <div class="d-flex">
            <div class="toast-body">
                ${message}
            </div>
            <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast" aria-label="Close"></button>
        </div>
    `;
    
    const toastContainer = document.getElementById('toastContainer');
    if (!toastContainer) {
        const container = document.createElement('div');
        container.className = 'toast-container position-fixed bottom-0 end-0 p-3';
        container.id = 'toastContainer';
        document.body.appendChild(container);
    }
    
    document.getElementById('toastContainer').appendChild(notificationDiv);
    const toast = new bootstrap.Toast(notificationDiv);
    toast.show();
    
    // Supprimer la notification après qu'elle soit cachée
    notificationDiv.addEventListener('hidden.bs.toast', function() {
        notificationDiv.remove();
    });
}
