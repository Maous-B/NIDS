from scapy.all import *

iface_name = "Realtek PCIe 2.5GbE Family Controller"

packet = Ether()/IP(dst="192.168.1.1", src="1.2.3.4")/UDP()/Raw(load="Hello, UDP!")

sendp(packet, iface=iface_name, loop=1)