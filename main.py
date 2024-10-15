""""Bibliothèques utilisées"""
import wmi
from collections.abc import Callable
from typing import Any, Iterable, Mapping
from scapy.all import * 
from scapy.layers.inet import IP, TCP, UDP # toutes les définitions des protocoles
from scapy.config import conf 
from collections import Counter
from threading import Thread, Lock

""""Banniere"""
ROUGE = "\033[31m"
VERT = "\033[32m"
JAUNE = "\033[33m"
BLEU = "\033[34m"
MAGENTA = "\033[35m"
CYAN = "\033[36m"
BLANC = "\033[37m"

banniere = f"""{BLEU}
                                                     
                                                     
                                                     
                     .::---::.                       
              :=*#%@@@@@@@@@@@@@%#*+:                
          :+#@@@@@@@@@@@@@@@@@@@@@@@@@%*-            
       :*%@@@@@@@#+-::.......::-=*%@@@@@@@#-         
    .-%@@@@@@+:.                   .:=#@@@@@@*.      
  .=%@@@@%=.           .:::..          .:#@@@@@*:    
  :@@@@#-       .=#%@@@@@@@@@@@%%+:       .+@@@@+.   
   :==:      :#@@@@@@@@@@@@@@@@@@@@@%=.     .-+-.    
          .*@@@@@@@*-..      .:+%@@@@@@%.            
         =%@@@@%-.                :*@@@@@#           
         -%@@#                       =@@@#           
                   -%@@@@@@@@@@+.                    
                .#@@@@@@@@@@@@@@@%-                  
               .%@@@@#-     .+@@@@@=                 
                .*#=.          :*#-                  
                       .=++:.                        
                      *@@@@@%:                       
                     :%@@@@@@#                       
                      +@@@@@#.                       
                       .-+=:                         

            ┬ ┌┐┌ ┌┬┐ ┬─┐ ┬ ┬ ┌─┐ ┬ ┬ ┌─┐
            │ │││  │  ├┬┘ │ │ └─┐ └┬┘ └─┐
            ┴ ┘└┘  ┴  ┴└─ └─┘ └─┘  ┴  └─┘
     
                             
                                                                            
{BLANC}Projet NIDS (Intrusys) crée par Marwan, Vigine et Thomas
"""


volume_trafic = Counter() 
lock = Lock()

"""Alerte d'une attaque"""
class Alerte(Thread):
    def __init__(self):
        super().__init__()
    
    def Alerte(self, TypeAlerte, Paquet=None):
        print(f"[ALERTE !] Type d'attaque : {TypeAlerte} | Source : {Paquet[IP].src}")


"""Analyse et détection des attaques"""
class Analyse(Thread):
    def __init__(self):
        super().__init__()
        self.alerte = Alerte()
        self.scan_ports = {}
        self.brute_force_tentatives = {}  # Pour suivre les tentatives de brute force
        self.brute_force_seuil = 10  # Seuil de tentatives
        self.brute_force_fenetre_de_temps = timedelta(seconds=60)

        self.dos_horodatage = {}
        self.dos_seuil = 1500  # Seuil pour DoS
        self.dos_fenetre_de_temps = timedelta(seconds=60)

    """Détection DoS SYN"""
    def Analyse_DOS(self, Paquet):
        # for src_ip, count in volume_trafic.items(): 
        #     if count > 1500  :  # Seuil arbitraire 
        #         self.alerte.Alerte("DoS (+ 1.5k paquets)", Paquet=Paquet)
        #         volume_trafic[src_ip] = 0
        if IP in Paquet:
            src_ip = Paquet[IP].src
            current_time = datetime.now()
            
            if src_ip not in self.dos_horodatage:
                self.dos_horodatage[src_ip] = []

            # Enlever les timestamps anciens
            self.dos_horodatage[src_ip] = [
                timestamp for timestamp in self.dos_horodatage[src_ip]
                if current_time - timestamp < self.dos_fenetre_de_temps
            ]

            # Ajouter le timestamp actuel
            self.dos_horodatage[src_ip].append(current_time)

            # Vérifier si le nombre de paquets dépasse le seuil
            if len(self.dos_horodatage[src_ip]) >= self.dos_seuil:
                self.alerte.Alerte("DoS détecté (+ 1.5k Paquets)", Paquet=Paquet)
    
    def Analyse_BruteForce(self, Paquet):
        if TCP in Paquet and Paquet[TCP].dport == 22:  # Port SSH
            src_ip = Paquet[IP].src
        
        current_time = datetime.now()
        if src_ip not in self.brute_force_tentatives:
            self.brute_force_tentatives[src_ip] = []

        # Enlever les tentatives anciennes
        self.brute_force_tentatives[src_ip] = [
            timestamp for timestamp in self.brute_force_tentatives[src_ip]
            if current_time - timestamp < self.brute_force_time_window
        ]

        # Ajouter la tentative actuelle
        self.brute_force_tentatives[src_ip].append(current_time)

        # Vérifier si le nombre de tentatives dépasse le seuil
        if len(self.brute_force_tentatives[src_ip]) >= self.brute_force_seuil:
            self.alerte.Alerte(f"Brute force SSH", Paquet=Paquet)

    def Analyse_SCAN_Ports(self, Paquet):
        if TCP in Paquet and Paquet[TCP].flags == 'S':
            src_ip = Paquet[IP].src
            port_src = Paquet[TCP].sport
            port_dst = Paquet[TCP].dport
            
            # Initialiser l'entrée si l'IP n'est pas encore présente
            if src_ip not in self.scan_ports:
                self.scan_ports[src_ip] = set()
            
            # Ajouter le port scanné
            self.scan_ports[src_ip].add(port_dst)
            # Compter le nombre de ports scannés
            if len(self.scan_ports[src_ip]) >= 10:  # Seuil de 10 ports
                self.alerte.Alerte(f"Scan de ports", Paquet=Paquet)


    """Détection d'attaque dans le contenu du paquet"""
    def Analyse_Contenu(self, Paquet):
        contenu = None
        if Paquet.haslayer(Raw):
            contenu = bytes(Paquet[Raw]).decode(errors='replace')
        if contenu!=None:
            #print("Pas vide")
            """Injection SQL"""
            # Signatures d'injection SQL courantes
            attaque_signatures_sql = ["' OR 'a'='a","' OR 1=1","' AND 1=1","UNION SELECT","DROP TABLE","INSERT INTO","UPDATE SET","--",";--","'; --","' OR ''='"]
            for signature in attaque_signatures_sql:
                if signature in contenu :
                    self.alerte.Alerte("Injection SQL", Paquet=Paquet)
                """XSS"""
            if "<script>" in contenu :
                self.alerte.Alerte("Attaque XSS", Paquet=Paquet)

    def AnalyseDuPaquet(self, Paquet):
        self.Analyse_DOS(Paquet)
        self.Analyse_Contenu(Paquet)
        self.Analyse_SCAN_Ports(Paquet)




class Sniffer(Thread):

    def __init__(self, interface):

        super().__init__()
        self.stop = False
        self.interface = interface
        self.analyse = Analyse()
        self.historique = []

    def TraitementDePaquets(self, Paquet):
        try:
            # if Paquet.haslayer(Raw):
            #     print(bytes(Paquet[Raw]).decode(errors='replace'), len(bytes(Paquet[Raw]).decode(errors='replace')))
            ip_src, ip_dst, port_src, port_dst, protocole, flags, contenu = None, None, None, None, None, None, None
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
            """Récuperer les informations du paquet"""
            if IP in Paquet:
                ip_src = Paquet[IP].src
                ip_dst = Paquet[IP].dst
            else:
                return  # Si le paquet n'a pas de couche IP, on le ignore
            
            if TCP in Paquet:
                port_src = Paquet[TCP].sport
                port_dst = Paquet[TCP].dport
                protocole = "TCP"
                flags = Paquet[TCP].flags
            elif UDP in Paquet:
                port_src = Paquet[UDP].sport
                port_dst = Paquet[UDP].dport
                protocole = "UDP"

            if Paquet.haslayer(Raw):
                contenu = bytes(Paquet[Raw]).decode(errors='replace')

            # Mettre à jour le volume de trafic
            with lock:
                volume_trafic[ip_src] += 1

            self.historique.append([timestamp, ip_src, port_src, ip_dst, port_dst, protocole, flags, contenu])
            self.analyse.AnalyseDuPaquet(Paquet)

        except Exception as e:
            print(f"Erreur lors du traitement du paquet : {e}")


    def should_stop(self, packet):
        return self.stop  # Retourne True si le thread doit s'arrêter

    def stop_sniffer(self):
        self.stop = True

    def CaptureDePaquets(self, Paquet):
        #print(Paquet.summary())
        self.TraitementDePaquets(Paquet)
        # self.analyse.AnalyseDuPaquet(self.historique)
    
    """Capture des paquets"""    
    def run(self) -> None:
        try:
            sniff(iface=self.interface, prn=self.CaptureDePaquets, store=0, stop_filter=lambda x: self.stop)
        except Exception as e:
            print(f"Erreur lors de la capture : {e}")


class NIDS(object):
    def __init__(self):
        print(banniere)
        '''Recherche des interfaces disponible'''
        #Initialisation d'un objet WMI
        wmi_obj = wmi.WMI()
        #Initialisation d'une liste pour stocker les interfaces réseau
        interfaces = []
        #Boucle pour parcourir les interfaces réseau actives
        for nic in wmi_obj.Win32_NetworkAdapterConfiguration(IPEnabled=True):
            interfaces.append(nic.Description)  # Le friendly name de l'interface
        #Afficher les interfaces
        print("Voici les interfaces réseau disponible :")
        for i in range (len(interfaces)):
            print(f" [{i}] - {interfaces[i]}")
        #Demander l'utilisateur de choisir une interface
        choix_interface=int(input("Veuillez choisir l'une des interfaces disponibles : "))
        interfaces_choisi=interfaces[choix_interface]
        print(interfaces_choisi)
        print("[!] Lancement du système")
        
        self.sniffer = Sniffer(interfaces_choisi)
        self.sniffer.start() 
    def stop(self):
        self.sniffer.stop_sniffer()  # Arrêter le sniffer proprement
        self.sniffer.join()  # Attendre que le thread se termine


"""Boucle"""
try:
    nids = NIDS()
    while True:
        pass  # Garder le programme en cours d'exécution
except KeyboardInterrupt:
    print("Arrêt du programme...")
    nids.stop()  # Arrêter le sniffer proprement
    nids.sniffer.join()  # Attendre que le thread se termine
    print("Programme arrêté.")
