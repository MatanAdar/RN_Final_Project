from scapy.all import *
import time

from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.inet import UDP, IP
from scapy.layers.l2 import Ether

global dhcp_ip, end_ip, list_of_ips
dhcp_ip = "10.0.0.1"
end_ip= 0
list_of_ips=["10.0.2.15"]


# Define a function to handle DHCP requests
def got_dhcp_discover():

    pkt = sniff(filter="udp and port 67", count=1, iface="enp0s3")[0]

    global end_ip, list_of_ips

    print("got packet from client")

    if DHCP in pkt and pkt[DHCP].options[0][1] == 1:
        print("DHCP Discover received")

        #checking if the ip is in use already or if there no more ips
        client_ip = "10.0.5."+str(end_ip)
        while client_ip in list_of_ips:
            print("the ip:", client_ip, "in use already")
            end_ip += 1
            if end_ip > 254:
                print("we cant make anymore ip's")
                end_ip = 0
                client_ip = "0.0.0.0"  # if there is no more available ips with the 10.0.2. we make the client ip back to 0.0.0.0
                break
            client_ip = "10.0.2."+str(end_ip)

        # Craft DHCP Offer
        dhcp_offer1 = Ether(dst="ff:ff:ff:ff:ff:ff") / \
                      IP(src="0.0.0.0", dst="255.255.255.255") / \
                      UDP(sport=67, dport=68) / \
                      BOOTP(op=2, yiaddr=client_ip, siaddr="10.0.0.1", giaddr="0.0.0.0", chaddr=pkt[Ether].src, xid=pkt[BOOTP].xid) / \
                      DHCP(options=[("message-type", "offer"),
                                    ("subnet_mask", "255.255.255.0"),
                                    ("router", "10.0.0.1"),
                                    ("name_server", "10.0.0.1"),
                                    "end"])

        print("finished offer")

        time.sleep(1)

        # Send DHCP Offer
        sendp(dhcp_offer1)
    else:
        print("there is no dhcp")

def dhcp_ack():

    pkt = sniff(filter="udp and port 68", count=1, iface="enp0s3")[0]

    print("got request from client")

    if DHCP in pkt and pkt[DHCP].options[0][1] == 3:
        print("DHCP Request received")

        # Craft DHCP Ack
        dhcp_ack1 = Ether(dst="ff:ff:ff:ff:ff:ff") / \
                    IP(src="0.0.0.0", dst="255.255.255.255") / \
                    UDP(sport=67, dport=68) / \
                    BOOTP(op=2, yiaddr=pkt[BOOTP].yiaddr, siaddr="10.0.0.1", giaddr="0.0.0.0",
                          chaddr=pkt[Ether].src, xid=pkt[BOOTP].xid) / \
                    DHCP(options=[("message-type", "ack"),
                                  ("subnet_mask", "255.255.255.0"),
                                  ("router", "10.0.0.1"),
                                  ("name_server", "10.0.0.1"),
                                  "end"])

        time.sleep(1)

        # Send DHCP Ack
        sendp(dhcp_ack1)


if __name__=="__main__":

    #sniff(filter="udp and port 68", prn=got_dhcp_discover, iface="enp0s3")
    while True:
        got_dhcp_discover()
        dhcp_ack()
