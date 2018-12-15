import os
from scapy.all import sniff

def handle(pkt):
    pkt.show2()

def main():
    iface = list(filter(lambda i: 'eth' in i, os.listdir('/sys/class/net/')))
    iface = iface[0]
    print("listening on {}".format(iface))
    sniff(iface=iface, prn=handle)

if __name__=='__main__':
    main()
