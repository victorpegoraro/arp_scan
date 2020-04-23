#!/usr/bin/env python

import scapy.all as scapy
import optparse


def get_args():
    parser = optparse.OptionParser()

    parser.add_option("-t", "--target", dest="ipaddr", help="Enter IP address or IP range EX: 192.168.0.1/24")

    options, args = parser.parse_args()

    if not options.ipaddr:

        parser.error("[-] Please enter an ip address, --help for more info.")

    return options.ipaddr


def scan(ip):

    arp_request = scapy.ARP(pdst=ip)

    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")

    arp_request_broadcast = broadcast/arp_request

    answered = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    clients = []

    for item in answered:

        client = {"ip": item[0].pdst, "mac": item[1].src}

        clients.append(client)

    return clients


def print_results(clients):

    print("IP\t\t\tMac Address\t\n---------------------------------------------")

    for cl in clients:

        print(cl["ip"] + "\t\t" + cl["mac"])


if __name__ == '__main__':

    options = get_args()

    results = scan(options)

    print_results(results)