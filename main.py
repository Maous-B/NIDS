

from typing import Any, Iterable, Mapping
from scapy.all import * 
from scapy.config import conf 
from collections import Counter
from threading import Thread, Lock

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

print(banniere)

volume_trafic = Counter() 
lock = Lock()


class Analyse(Thread):
    def __init__(self):
        super().__init__()

    def AnalyseDuPaquet(Paquet):
        pass

class Sniffer(Thread):
    def __init__(self, interface):
        super().__init__()
        self.stop = None
        self.interface = interface
        self.analyse = Analyse()

    def TraitementDePaquets(Paquet):
        src_ip = Paquet[IP].src 
        volume_trafic[src_ip] += 1

    def CaptureDePaquets(self, Paquet):
        #print(Paquet.summary())
        self.TraitementDePaquets(Paquet)
        self.analyse.AnalyseDuPaquet(Paquet)
        
    def run(self) -> None:
        sniff(iface=self.interface, prn=self.CaptureDePaquets, store=0)

class NIDS(object):

    def __init__(self):
        print(banniere)
        self.sniffer = Sniffer(interface="Realtek PCIe 2.5GbE Family Controller") 
        print("[!] Lancement du système")
        self.sniffer.start() 

nids = NIDS()