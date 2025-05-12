import subprocess

def run_nmap(target):
    """Exécute un scan Nmap et retourne les résultats."""
    cmd = ["nmap", "-T4", "-F", target]
    return execute_scan(cmd)

def run_zap(target):
    """Exécute un scan OWASP ZAP et retourne les résultats."""
    cmd = ["zap-cli", "quick-scan", target]
    return execute_scan(cmd)

def run_sqlmap(target):
    """Exécute un scan SQLMap et retourne les résultats."""
    cmd = ["sqlmap", "-u", target, "--batch"]
    return execute_scan(cmd)

def run_openvas(target):
    """Exécute un scan OpenVAS et retourne les résultats."""
    cmd = ["gvm-cli", "--gmp-username", "admin", "--gmp-password", "admin", "scan", target]
    return execute_scan(cmd)

def run_nuclei(target):
    """Exécute un scan Nuclei et retourne les résultats."""
    cmd = ["nuclei", "-u", target]
    return execute_scan(cmd)

def run_apisec(target):
    """Exécute un scan API Security Scanner et retourne les résultats."""
    cmd = ["apisec", "scan", target]
    return execute_scan(cmd)

def execute_scan(cmd):
    """Exécute la commande et retourne le résultat brut."""
    try:
        result = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True)
        return result
    except subprocess.CalledProcessError as e:
        return f"Erreur lors de l'exécution du scan : {e.output}"

# Dictionnaire des outils avec les fonctions correspondantes
TOOL_FUNCTIONS = {
    'NMAP': run_nmap,
    'ZAP': run_zap,
    'SQLMAP': run_sqlmap,
    'OPENVAS': run_openvas,
    'NUCLEI': run_nuclei,
    'APISEC': run_apisec,
}
