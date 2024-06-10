#!/usr/bin/env python3

import scapy.all as scapy
import argparse

def get_arguments():
    parser = argparse.ArgumentParser(description="ARP Scanner")
    parser.add_argument("-t", "--target", required=True, dest="target", help="Host / IP range to scan")
    args = parser.parse_args()
    return args.target
def scan(ip):
    arp_packet = scapy.ARP(pdst=ip)
    broadcast_packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")

    arp_request_broadcast = broadcast_packet/arp_packet

    answered, unanswered  = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)
    response = answered.summary()

    print("IP\t\t\tMAC Address\n-----------------------------------------")
    for sent, received in answered:
        print(f"{received.psrc}\t\t{received.hwsrc}")

    if response:
        print(response)

def main():
    target = get_arguments()
    scan(target)

if __name__=='__main__':
    main()