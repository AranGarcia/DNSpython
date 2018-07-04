#!/usr/bin/env python3
''' Python DNS server '''

import configparser
import random
import socket

import dns

HOST = ''
PORT = 53
OUTPORT = 8877


class DNSserver:
    def __init__(self, config):
        self.forward_servers = config["DEFAULT"]["dns_servers"].split(";")

        # A resource dictionary that maps a name to a list of IP addresses
        self.resources = {}
        for resource in [r for r in config.keys() if r != "DEFAULT"]:
            self.resources[resource] = config[resource]["url"].split()

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((HOST, PORT))

    def start(self):
        print("Starting domain name service.")
        print("hostname:", HOST + ',', "port", PORT)

        while True:
            data, addr = self.sock.recvfrom(1024)
            print("Query recieved from", addr)

            query = dns.DNSmessage(data)
            print(query)

            if self.__name_exists(query.questions):
                # An answer can be made from local data
                print("Name exists")
            else:
                if query.flags["rd"]:
                    # Query will be forwarded to another DNS server
                    print("\nRedirecting to default DNS server (Recursion desired):",
                          self.forward_servers[0])

                    self.__redirect_query(query)
                else:
                    # If an answer cannot be made with a recursive query, return a list of other DNS servers
                    print(
                        "\nReturning a list of other DNS servers (Recursion not desired).")

    def __redirect_query(self, query):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.sendto(bytes(query), (self.forward_servers[0], 53))

        data, address = self.sock.recvfrom(1024)
        response = dns.DNSmessage(data)
        print("\nResponse received from", address)
        print(response)

    def __name_exists(self, questions):

        for q in questions:
            qname = q.qname
            if qname.startswith("www."):
                other_name = qname[4:]
            else:
                other_name = 'www.' + qname

            if qname in self.resources or other_name in self.resources:
                return True

        return False


if __name__ == '__main__':
    # Configuration load
    conf = configparser.ConfigParser()
    conf.read("dns.config")

    ds = DNSserver(conf)

    try:
        ds.start()
    except KeyboardInterrupt:
        print("\rStopping server.")
