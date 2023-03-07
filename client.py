from scapy.all import *
import time
import socket

from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.dns import DNSRR, DNS, DNSQR
from scapy.layers.inet import UDP, IP
from scapy.layers.l2 import Ether
from scapy.sendrecv import sendp


global client_ip_from_server


def dhcp_discover():

    dhcp_discover1 = Ether(dst="ff:ff:ff:ff:ff") / \
                    IP(src='0.0.0.0', dst='255.255.255.255') / \
                    UDP(sport=68, dport=67) / \
                    BOOTP(op=1, chaddr="4a:e4:66:e8:7a:00", xid=23567342) / \
                    DHCP(options=[("message-type", "discover"), "end"])

    # send DHCP discover to the server
    sendp(dhcp_discover1)


# Define a function to handle DHCP responses
def got_dhcp_offer():

    global client_ip_from_server

    pkt = sniff(filter="udp and port 68", count=1, iface="enp0s3")[0]

    if DHCP in pkt and pkt[DHCP].options[0][1] == 2:
        print("DHCP Offer received")

        client_ip_from_server = pkt[BOOTP].yiaddr

        if client_ip_from_server == "0.0.0.0":
            print("there is no more available ips from the server")
            return

        print("the client_ip that the server offer is:", client_ip_from_server)

        print("ok, i want this ip address:", client_ip_from_server, "can i lease it?")

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
        print("sending dhcp request to the server")
        # Send DHCP Request to the server
        sendp(dhcp_request)


def got_dhcp_ack():

    pkt = sniff(filter="udp and port 68", count=1, iface="enp0s3")[0]  #got the pkt in the spot 0

    if DHCP in pkt and pkt[DHCP].options[0][1] == 5:
        print("DHCP ack received")

        print("so my ip address is:", client_ip_from_server)


def dns_client(domain):
    dns_packet = IP(dst='8.8.8.8')/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname=domain))
    response = sr1(dns_packet, verbose=0)
    if response and response.haslayer(DNSRR):
        print(response[DNSRR].rdata)
    else:
        print('DNS query failed.')
    domain = 'example.com'
    dns_client(domain)


def dns_socket():

    dns_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    dns_sock.connect(("127.0.0.1", 53))

    input_domain = input("DNS please input a domain:")

    dns_sock.sendto(input_domain.encode("utf-8"), ("127.0.0.1", 53))

    ip_address = dns_sock.recvfrom(4096)

    print("the ip of the address is:", ip_address[0].decode("utf-8"))

    dns_sock.close()

def app_client():

     # Configure the server address and port number
    server_address = '127.0.0.1'
    server_port = 20529

    # Create a UDP socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Send a request to the server
    request = 'Please redirect me to the remote server'.encode()
    client_socket.sendto(request, (server_address, server_port))

    # Receive the redirect response from the server
    redirect_response, server_address = client_socket.recvfrom(1024)

    print('Received redirect response from server at {}:{}'.format(server_address[0], server_address[1]))

    # Parse the IP address and port number of the remote server from the redirect response
    remote_server_address, remote_server_port = redirect_response.decode().split(':')

    print('Connecting to remote server at {}:{}'.format(remote_server_address, remote_server_port))

    # Connect to the remote server and download the file
    remote_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    remote_server_socket.connect((remote_server_address, int(remote_server_port)))
    remote_server_socket.sendall('Please send me the file'.encode())

    with open('file.txt', 'wb') as f:
        while True:
            data = remote_server_socket.recv(1024)
            if not data:
                break
            f.write(data)

    print('File downloaded from remote server')


# main
if __name__ == "__main__":
    #dhcp_discover()
    #got_dhcp_offer()
    #got_dhcp_ack()

    dns_socket()

    #app_client()
