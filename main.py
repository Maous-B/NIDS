""""Bibliothèques utilisées"""
import wmi
from collections.abc import Callable
from typing import Any, Iterable, Mapping
from scapy.all import * 
from scapy.layers.inet import IP, TCP, UDP # toutes les définitions des protocoles
from scapy.config import conf 
from collections import *
from threading import Thread, Lock
from windows_toasts import WindowsToaster, Toast


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
              :=#%@@@@@@@@@@@@@%#+:                
          :+#@@@@@@@@@@@@@@@@@@@@@@@@@%*-            
       :%@@@@@@@#+-::.......::-=%@@@@@@@#-         
    .-%@@@@@@+:.                   .:=#@@@@@@*.      
  .=%@@@@%=.           .:::..          .:#@@@@@*:    
  :@@@@#-       .=#%@@@@@@@@@@@%%+:       .+@@@@+.   
   :==:      :#@@@@@@@@@@@@@@@@@@@@@%=.     .-+-.    
          .@@@@@@@-..      .:+%@@@@@@%.            
         =%@@@@%-.                :*@@@@@#           
         -%@@#                       =@@@#           
                   -%@@@@@@@@@@+.                    
                .#@@@@@@@@@@@@@@@%-                  
               .%@@@@#-     .+@@@@@=                 
                .#=.          :#-                  
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
    def _init_(self):
        super()._init_()
    
    def Alerte(self, TypeAlerte, Paquet=None):
        #Alerte console
        print(f"[ALERTE !] Type d'attaque : {TypeAlerte} | Source : {Paquet[IP].src}")
        # Prepare the toaster for bread (or your notification)
        toaster = WindowsToaster('NIDS')
        #Initialiser le Toast
        newToast = Toast()
        #Ecrire la notification
        newToast.text_fields = [f"[ALERTE !] Type d'attaque : {TypeAlerte} | Source : {Paquet[IP].src}"]
        #Afficher la notification
        toaster.show_toast(newToast)



"""Analyse et détection des attaques"""
class Analyse(Thread):
    def _init_(self):
        super()._init_()
        self.alerte = Alerte()
        self.scan_ports = {}
        self.brute_force_tentatives = {}  # Pour suivre les tentatives de brute force
        self.brute_force_seuil = 100  # Seuil de tentatives
        self.brute_force_fenetre_de_temps = timedelta(seconds=30)
        self.volume_trafic = Counter()
        self.dos_derniere_alerte = {}
        self.dos_horodatage = defaultdict(list)
        self.dos_seuil = 1500  # Seuil pour DoS
        self.dos_fenetre_de_temps = timedelta(seconds=10)
        self.dos_duree_alerte = timedelta(seconds=5)
    """Détection DoS SYN"""
    def Analyse_DOS_TCP(self, Paquet):
        # for src_ip, count in volume_trafic.items(): 
        #     if count > 1500  :  # Seuil arbitraire 
        #         self.alerte.Alerte("DoS (+ 1.5k paquets)", Paquet=Paquet)
        #         volume_trafic[src_ip] = 0
        if IP in Paquet and TCP in Paquet:    
            src_ip = Paquet[IP].src
            current_time = datetime.now()
            self.volume_trafic[src_ip] += 1
            if self.volume_trafic[src_ip] >= self.dos_seuil:
                # Vérifier le délai depuis la dernière alerte
                if src_ip not in self.dos_derniere_alerte or (current_time - self.dos_derniere_alerte[src_ip]) > self.dos_duree_alerte:
                    self.alerte.Alerte("DoS TCP détecté (+ 1.5k Paquets)", Paquet=Paquet)
                    self.dos_derniere_alerte[src_ip] = current_time  # Mettre à jour le timestamp de la dernière alerte
                    del self.volume_trafic[src_ip]
            # Reset le compteur si l'IP n'a pas été vue dans la fenêtre de temps
            for ip in list(self.volume_trafic.keys()):
                if current_time - self.dos_derniere_alerte.get(ip, current_time) > self.dos_fenetre_de_temps:
                    del self.volume_trafic[ip]  # Reset le compteur pour cette IP
    """Détection DoS UDP"""
    def Analyse_DOS_UDP(self, Paquet):
        if IP in Paquet and UDP in Paquet:    
            src_ip = Paquet[IP].src
            current_time = datetime.now()
            self.volume_trafic[src_ip] += 1
            if self.volume_trafic[src_ip] >= self.dos_seuil:
                # Vérifier le délai depuis la dernière alerte
                if src_ip not in self.dos_derniere_alerte or (current_time - self.dos_derniere_alerte[src_ip]) > self.dos_duree_alerte:
                    self.alerte.Alerte("DoS UDP détecté (+ 1.5k Paquets)", Paquet=Paquet)
                    self.dos_derniere_alerte[src_ip] = current_time  # Mettre à jour le timestamp de la dernière alerte
                    del self.volume_trafic[src_ip]
            # Reset le compteur si l'IP n'a pas été vue dans la fenêtre de temps
            for ip in list(self.volume_trafic.keys()):
                if current_time - self.dos_derniere_alerte.get(ip, current_time) > self.dos_fenetre_de_temps:
                    del self.volume_trafic[ip]  # Reset le compteur pour cette IP
    
    """Détection Bruteforce SSH"""
    def Analyse_BruteForce(self, Paquet):
        #Filtrer les paquets
        if IP in Paquet and TCP in Paquet and Paquet[TCP].dport == 22:  # Port SSH
            src_ip = Paquet[IP].src
            current_time = datetime.now()
            # Initialiser une liste de tentatives si l'IP n'a pas encore été vue
            if src_ip not in self.brute_force_tentatives:
                self.brute_force_tentatives[src_ip] = []
            # Supprimer les tentatives qui sont en dehors de la fenêtre de temps
            self.brute_force_tentatives[src_ip] = [
                timestamp for timestamp in self.brute_force_tentatives[src_ip]
                if current_time - timestamp < self.brute_force_fenetre_de_temps
            ]
            # Ajouter la tentative actuelle dans la liste
            self.brute_force_tentatives[src_ip].append(current_time)
            # Si le nombre de tentatives dépasse le seuil
            if len(self.brute_force_tentatives[src_ip]) >= self.brute_force_seuil:
                self.alerte.Alerte(f"Brute force SSH", Paquet=Paquet)
                # On pourrait aussi réinitialiser les tentatives après alerte
                self.brute_force_tentatives[src_ip] = []  # Réinitialiser après l'alerte

    """Détection Scan Port"""
    def Analyse_SCAN_Ports_TCP(self, Paquet):
        if TCP in Paquet :
            src_ip = Paquet[IP].src
            port_dst = Paquet[TCP].dport
            # Initialiser l'entrée si l'IP n'est pas encore présente
            if src_ip not in self.scan_ports:
                self.scan_ports[src_ip] = set()
            # Ajouter le port scanné
            self.scan_ports[src_ip].add(port_dst)
            # Compter le nombre de ports scannés
            if len(self.scan_ports[src_ip]) >= 10:  # Seuil de 10 ports
                self.alerte.Alerte(f"Scan de Ports (TCP)", Paquet=Paquet)


    """Détection d'attaque dans le contenu du paquet"""
    def Analyse_Contenu(self, Paquet):
        if TCP in Paquet and Paquet[TCP].dport == 80:
            contenu = None
            if Paquet.haslayer(Raw):
                contenu = bytes(Paquet[Raw]).decode(errors='replace')
            if contenu!=None:
                """Injection SQL"""
                # Signatures d'injection SQL courantes
                attaque_signatures_sql = ["' OR 'a'='a","' OR 1=1","' AND 1=1","UNION SELECT","DROP TABLE","INSERT INTO","UPDATE SET","' OR ''='"]
                for signature in attaque_signatures_sql:
                    if signature in contenu :
                        self.alerte.Alerte("Injection SQL", Paquet=Paquet)
                    """XSS"""
                if "<script>" in contenu :
                    self.alerte.Alerte("Attaque XSS", Paquet=Paquet)

    def AnalyseDuPaquet(self, Paquet):
        self.Analyse_DOS_TCP(Paquet)
        self.Analyse_Contenu(Paquet)
        self.Analyse_SCAN_Ports_TCP(Paquet)
        self.Analyse_BruteForce(Paquet)




class Sniffer(Thread):

    def _init_(self, interface):

        super()._init_()
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
    def _init_(self):
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


nids = None 

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
