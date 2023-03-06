from scapy.all import *
import time

from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.dns import DNSRR, DNS, DNSQR
from scapy.layers.inet import UDP, IP
from scapy.layers.l2 import Ether
from scapy.sendrecv import sendp



def dhcp_discover():

    dhcp_discover1 = Ether(dst="ff:ff:ff:ff:ff") / \
                    IP(src='0.0.0.0', dst='255.255.255.255') / \
                    UDP(sport=68, dport=67) / \
                    BOOTP(op=1, chaddr="4a:e4:66:e8:7a:00", xid=23567342) / \
                    DHCP(options=[("message-type", "discover"), "end"])

    sendp(dhcp_discover1)


# Define a function to handle DHCP responses
def got_dhcp_offer():

    pkt = sniff(filter="udp and port 68", count=1, iface="enp0s3")[0]

    global client_ip
    client_ip = pkt[BOOTP].yiaddr

    if client_ip == "0.0.0.0":
        print("there is no more available ips from the server")
        return

    print("the client_ip is:", client_ip)

    print("got offer from server")
    if DHCP in pkt:
        if pkt[DHCP].options[0][1] == 2:
            print("DHCP Offer received")

            # Craft DHCP Request
            dhcp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / \
                           IP(src="0.0.0.0", dst="255.255.255.255") / \
                           UDP(sport=68, dport=67) / \
                           BOOTP(op=1, chaddr="4a:e4:66:e8:7a:00", xid=pkt[BOOTP].xid) / \
                           DHCP(options=[("message-type", "request"),
                                         ("requested_addr", pkt[BOOTP].yiaddr),
                                         ("server_id", pkt[IP].src),
                                         "end"])

            time.sleep(1)

            # Send DHCP Request
            sendp(dhcp_request)


def got_dhcp_ack():

    pkt = sniff(filter="udp and port 68", count=1, iface="enp0s3")[0]  #got the pkt in the spot 0

    if DHCP in pkt and pkt[DHCP].options[0][1] == 5:
        print("DHCP ack received")




def dns_client(domain):
    dns_packet = IP(dst='8.8.8.8')/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname=domain))
    response = sr1(dns_packet, verbose=0)
    if response and response.haslayer(DNSRR):
        print(response[DNSRR].rdata)
    else:
        print('DNS query failed.')
    domain = 'example.com'
    dns_client(domain)


if __name__ == "__main__":
    dhcp_discover()
    got_dhcp_offer()
    got_dhcp_ack()
