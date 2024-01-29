#Name: Sotomayor, Nygel
#UIN: 655654678
#NetID: nsotom3
import sys
import argparse
import socket
import scapy.all as scapy
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP,TCP
from scapy.sendrecv import send
from scapy.packet import *
from collections import deque

packetdictionary = {}

def dns_detector(pkt):
    tcp = False 
    udp = False
    if pkt.haslayer(TCP) or pkt.haslayer(UDP):
        if pkt.haslayer(DNS) and pkt.haslayer(DNSRR) and pkt[DNS].qr == 1:
            if len(packetdictionary) != 0:
                if pkt[DNS].id in packetdictionary:
                    storedpacket = packetdictionary[pkt[DNS].id]
                    print(storedpacket)
                    if storedpacket[IP].src == pkt[IP].src and storedpacket[IP].dst == pkt[IP].dst and storedpacket[IP].payload != pkt[IP].payload and (storedpacket[DNS].qd).qname == (pkt[DNS].qd).qname and storedpacket[DNSRR].rdata != pkt[DNSRR].rdata:
                            print (time.strftime("%Y-%m-%d %H:%M") + " DNS poisoning attempt")
                            print ("TXID [%s] Request [%s]"%(storedpacket[DNS].id, ((storedpacket[DNS].qd).qname).rstrip('.')))
                            print ("Answer1 ",)
                            for rrcount in range(storedpacket[DNS].ancount):
                                if storedpacket[DNS].an[rrcount].type == 1:
                                    dnsrr = storedpacket[DNS].an[rrcount]
                                    print ("[%s] "%dnsrr.rdata,)
                            print ('\b')
                            print ("Answer2 ",)
                            for rrcount in range(pkt[DNS].ancount):
                                if pkt[DNS].an[rrcount].type == 1:
                                    dnsrr = pkt[DNS].an[rrcount]
                                    print ("[%s] "%dnsrr.rdata,)
                            print ('\b')
            packetdictionary[pkt[DNS].id] = pkt


def main():
    global args
    parser = argparse.ArgumentParser(add_help=False)
    interface = "en0"
    parser.add_argument("-i","--interface", default = interface)
    parser.add_argument("-r", "--tracefile")
    args = parser.parse_args()
    print(args.interface)
    if args.tracefile != None:
        print("here1")
        scapy.sniff(filter = '', offline = str(args.tracefile), prn = dns_detector)
    elif args.interface != None:
        print("here2")
        scapy.sniff(filter = '', iface = str(args.interface), prn = dns_detector)
    else:
        print("here3")
        scapy.sniff(filter = '', prn = dns_detector)
if __name__ == '__main__':
    main()