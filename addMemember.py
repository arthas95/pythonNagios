import time  # Import du module time (pas utilisé dans le script)
import nmap  # Import du module python-nmap pour scanner le réseau
import string  # Import du module string pour générer des caractères aléatoires
import random  # Import du module random pour générer des chaînes aléatoires

# Fonction pour générer une chaîne de caractères aléatoire de `length` caractères
def random_string(length=6):
    chars = string.ascii_letters + string.digits  # Lettres (a-z, A-Z) + Chiffres (0-9)
    return ''.join(random.choices(chars, k=length))  # Génération d'une chaîne aléatoire

# Fonction pour ajouter un hôte dans le fichier de configuration Nagios
def nagios_add(nom, ip):
    config_file = "/etc/nagios4/conf.d/mynetwork.cfg"  # Chemin du fichier de config Nagios

    # 1. Ajouter un nouvel hôte à la configuration Nagios
    with open(config_file, "a", encoding="utf-8") as f:  # Ouvre le fichier en mode ajout
        f.write("define host {\n")
        f.write("    use                             linux-server\n")  # Utilisation du modèle linux-server
        f.write(f"    host_name                       {nom}\n")  # Définition du nom d'hôte
        f.write(f"    alias                           {nom}\n")  # Alias de l'hôte
        f.write(f"    address                         {ip}\n")  # Adresse IP de l'hôte
        f.write("}\n")

    # 2. Modifier la ligne `members routeur` pour ajouter le nouvel hôte au groupe
    with open(config_file, "r", encoding="utf-8") as f:  # Ouvre le fichier en mode lecture
        lines = f.readlines()  # Lit toutes les lignes du fichier

    with open(config_file, "w", encoding="utf-8") as f:  # Ouvre le fichier en mode écriture
        for line in lines:
            if line.strip().startswith("members routeur"):  # Vérifie si la ligne correspond à `members routeur`
                f.write(line.strip() + f",{nom}\n")  # Ajoute `nom` à la fin de la ligne (séparé par une virgule)
            else:
                f.write(line)  # Garde toutes les autres lignes inchangées

# Fonction pour scanner un réseau et ajouter les hôtes trouvés à Nagios
def scan_network(range_network):
    scanner = nmap.PortScanner()  # Initialise un scanner Nmap
    ip_address = range_network  # Définition de la plage réseau à scanner
    scanner.scan(ip_address, arguments='-sn -R')  # Exécution du scan en mode "ping scan" avec résolution DNS

    les_host = []  # Liste des noms d'hôtes détectés
    les_ip = []  # Liste des adresses IP détectées

    # Parcours des hôtes détectés par Nmap
    for ip in scanner.all_hosts():
        HOSTNAME = scanner[ip]['hostnames'][0]['name']  # Récupère le nom d'hôte (DNS)
        
        # Si aucun nom DNS n'est trouvé, on génère un nom aléatoire unique
        if HOSTNAME == '':
            HOSTNAME = "unknown" + random_string()

        IP = scanner[ip]['addresses']['ipv4']  # Récupère l'adresse IP de l'hôte
        les_host.append(HOSTNAME)  # Ajoute le nom d'hôte à la liste
        les_ip.append(IP)  # Ajoute l'adresse IP à la liste

    # Ajout des hôtes détectés à Nagios
    for i in range(len(les_host)):
        print(les_host[i], les_ip[i])  # Affichage des hôtes détectés
        hote = les_host[i]  # Récupération du nom de l'hôte
        ip = les_ip[i]  # Récupération de l'adresse IP
        nagios_add(hote, ip)  # Ajout de l'hôte dans la configuration Nagios

# Exécution du scan sur la plage réseau 192.168.1.0/24
scan_network("192.168.1.0/24")
