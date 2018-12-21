import socket
import sys
import socket
from time import sleep
from scapy.all import sendp, send, get_if_list, get_if_hwaddr
from scapy.all import Ether, IP

def get_if():
    ifs = get_if_list()
    iface = None
    for i in get_if_list():
        if 'eth0' in i:
            iface=i
            break
    if not iface:
        print('No eth0 interface')
        exit(1)
    return iface


def main():
    if len(sys.argv) < 3:
        print('Usage: ./send.py <src_ip> <dst_ip>')
        exit(1)

    src_ip = sys.argv[1]
    dst_ip = sys.argv[2]
    iface = get_if()

    pkt = IP(src=src_ip, dst=dst_ip)

    pkt.show2()
    try:
        while True:
            send(pkt, iface=iface)
            sleep(1)
    except KeyboardInterrupt:
        pass

if __name__ == '__main__':
    main()
