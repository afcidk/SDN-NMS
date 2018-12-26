import os
import sys
from scapy.all import *

def handle(pkt):

    if IP in pkt and pkt[IP].dst == sys.argv[1]:
        print('received from {}'.format(pkt[IP].src))

def main():
    if len(sys.argv) < 2:
        print('Usage: python3 receive.py <your_ip>')
        exit(1)
    iface = list(filter(lambda i: 'eth' in i, os.listdir('/sys/class/net/')))
    iface = iface[0]
    print("listening on {}".format(iface))
    sniff(iface=iface, prn=handle)

if __name__=='__main__':
    main()
