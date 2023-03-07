
from scapy.all import *
import time
from scapy.layers.dns import DNSQR, DNS, DNSRR
from scapy.layers.inet import UDP, IP

import socket


def dns_server1():

    dns_server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    dns_server_socket.bind(("127.0.0.1", 53))



    global cache_of_domains
    cache_of_domains = {}

    while True:
        domain, client_addr = dns_server_socket.recvfrom(4096)
        domain = domain.decode("utf-8")

        print("Checking if the domain in the cache:")
        if domain not in cache_of_domains:
            try:
                print("The domain is NOT in the cache")
                # get the info of the domain from the DNS server
                info = socket.getaddrinfo(domain, 80, socket.AF_INET, socket.SOCK_DGRAM)

                # found the ip in the touple
                ip_address = info[0][4][0]

                ip_address_to_send = ip_address.encode("utf-8")

                # sending the ip to the client
                dns_server_socket.sendto(ip_address_to_send, client_addr)
                print("The domain added to the cache successfully")

                print("found the ip address from the DNS")

                #We added to the cache the domain
                cache_of_domains[domain] = ip_address

                print("The domain added to the cache successfully")
                return
            except socket.gaierror:
                print("there is no ip for this domain! the domain not found in DNS server")
                return
        else:
            print("The domain is in the cache")
            ip_address = cache_of_domains[domain].encode("utf-8")
            dns_server_socket.sendto(ip_address, client_addr)
            print("send the ip_address to the client")
            return


if __name__ == "__main__":
    dns_server1()
