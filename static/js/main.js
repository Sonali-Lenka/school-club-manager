// Wait for the DOM to be fully loaded
document.addEventListener('DOMContentLoaded', function() {
    // Initialize tooltips
    var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'))
    var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl)
    });

    // Auto-dismiss alerts
    var alerts = document.querySelectorAll('.alert');
    alerts.forEach(function(alert) {
        setTimeout(function() {
            var bsAlert = new bootstrap.Alert(alert);
            bsAlert.close();
        }, 5000);
    });

    // Theme switching functionality
    const themeButtons = document.querySelectorAll('[data-theme]');
    const htmlElement = document.documentElement;
    const themeStylesheet = document.getElementById('theme-stylesheet');

    // Load saved theme from localStorage
    const savedTheme = localStorage.getItem('preferred-theme') || 'dark';
    setTheme(savedTheme);

    // Theme switching event listeners
    themeButtons.forEach(button => {
        button.addEventListener('click', () => {
            const theme = button.getAttribute('data-theme');
            setTheme(theme);
        });
    });

    function setTheme(theme) {
        // Update data-bs-theme attribute
        htmlElement.setAttribute('data-bs-theme', theme);

        // Save theme preference
        localStorage.setItem('preferred-theme', theme);

        // Update stylesheet based on theme
        switch(theme) {
            case 'light':
                themeStylesheet.href = 'https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css';
                break;
            case 'dark':
                themeStylesheet.href = 'https://cdn.replit.com/agent/bootstrap-agent-dark-theme.min.css';
                break;
            default:
                themeStylesheet.href = 'https://cdn.replit.com/agent/bootstrap-agent-dark-theme.min.css';
        }
    }

    // Smooth scroll behavior for anchor links
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            document.querySelector(this.getAttribute('href')).scrollIntoView({
                behavior: 'smooth'
            });
        });
    });
});