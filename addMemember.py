import nmap
import string
import random
from lookup_Mac import lookup_mac
from mac_vendor_lookup import MacLookup

# Mise à jour de la base des fournisseurs MAC
MacLookup().update_vendors()

# Stockage des hôtes ajoutés pour éviter les doublons
ajoutes = set()

# Génération d'un nom aléatoire si aucun n'est trouvé
def random_string(length=6):
    chars = string.ascii_letters + string.digits
    return ''.join(random.choices(chars, k=length))

# Vérifie si un hôte est déjà présent dans `mynetwork.cfg`
def host_exists(nom):
    config_file = "/etc/nagios4/conf.d/mynetwork.cfg"
    try:
        with open(config_file, "r", encoding="utf-8") as f:
            for line in f:
                if f"host_name {nom}" in line:
                    return True
    except FileNotFoundError:
        print(f"⚠️ Fichier {config_file} non trouvé, un nouveau sera créé.")
    return False

# Nettoie les noms pour éviter les erreurs avec Nagios
def sanitize_hostname(hostname):
    hostname = hostname.strip()  # Supprime les espaces avant/après
    hostname = hostname.replace(" ", "-")  # Remplace les espaces par "-"
    hostname = hostname.replace(".", "")  # Supprime les points (évite erreurs Nagios)
    hostname = hostname.replace("'", "").replace('"', "")  # Supprime les guillemets
    hostname = hostname.replace(",", "")  # Supprime les virgules
    return hostname

# Ajoute un hôte dans la configuration Nagios
def nagios_add(nom, ip):
    config_file = "/etc/nagios4/conf.d/mynetwork.cfg"

    # Vérifie si l'hôte a déjà été ajouté
    if nom in ajoutes or host_exists(nom):
        print(f"⚠️ Hôte {nom} déjà ajouté, il ne sera pas dupliqué.")
        return

    ajoutes.add(nom)  # Ajoute au set des hôtes ajoutés

    # Ajout du nouvel hôte
    with open(config_file, "a", encoding="utf-8") as f:
        f.write("\n")
        f.write("define host {\n")
        f.write("    use                             linux-server\n")
        f.write(f"    host_name                       {nom}\n")
        f.write(f"    alias                           {nom}\n")
        f.write(f"    address                         {ip}\n")
        f.write("    max_check_attempts              3\n")
        f.write("}\n")

    # Mise à jour de `members routeur` pour inclure le nouvel hôte
    with open(config_file, "r", encoding="utf-8") as f:
        lines = f.readlines()

    with open(config_file, "w", encoding="utf-8") as f:
        for line in lines:
            if line.strip().startswith("members routeur"):
                f.write(line.strip() + f",{nom}\n")
            else:
                f.write(line)

# Scanner le réseau et ajouter les hôtes détectés
def scan_network(range_network):
    scanner = nmap.PortScanner()
    scanner.scan(range_network, arguments='-sn -R')

    for ip in scanner.all_hosts():
        # Récupération du nom DNS
        HOSTNAME = scanner[ip].get('hostnames', [{}])[0].get('name', '')

        if not HOSTNAME:  # Si aucun DNS trouvé
            try:
                mac_address = scanner[ip]['addresses'].get('mac', '')
                if mac_address:
                    HOSTNAME = lookup_mac(mac_address)
                    if not HOSTNAME:
                        raise ValueError("Nom MAC non trouvé")
                else:
                    raise ValueError("MAC introuvable")
            except:
                HOSTNAME = "unknown-" + random_string()

        # Nettoyage du nom d'hôte pour éviter les erreurs Nagios
        HOSTNAME = sanitize_hostname(HOSTNAME)

        # Empêcher les doublons en ajoutant un suffixe si nécessaire
        if HOSTNAME in ajoutes:
            last_octet = ip.split(".")[-1]
            HOSTNAME = f"{HOSTNAME}-{last_octet}"

        # Vérification de l'adresse IP
        IP = scanner[ip]['addresses'].get('ipv4', '')

        # Ajout uniquement si `IP` et `HOSTNAME` sont valides
        if IP and HOSTNAME:
            print(f"✅ Ajout de {HOSTNAME} → {IP}")
            nagios_add(HOSTNAME, IP)

# Exécute le scan sur la plage réseau
scan_network("192.168.1.0/24")

