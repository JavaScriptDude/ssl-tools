#!/usr/bin/env python

# By: Lawrence Ong
# Created: 20161029
# Description: To quickly get the SSL certificate chain from an endpoint

from sys import argv, stdout
from socket import socket
from OpenSSL.SSL import TLSv1_METHOD, Context, Connection
from pprint import pprint

def main():

    if len(argv) < 3:
        print('Usage: %s <hostname> <port>'.format(argv[0]))
        return 1

    hostname  = str(argv[1])
    port    = int(argv[2])

    client = socket()

    print('Connecting...')
    stdout.flush()
    client.connect((hostname, port))
    print('Connected to', client.getpeername())

    client_ssl = Connection(Context(TLSv1_METHOD), client)
    client_ssl.set_connect_state()
    client_ssl.set_tlsext_host_name(hostname.encode('utf-8'))
    client_ssl.do_handshake()
    chain = client_ssl.get_peer_cert_chain()
    
    print("\n>> Certificate Chain:\n")
    i = 0
    for cert in reversed(chain):
        i += 1
        asterisks = "*" * i
        print(" [+] {:<10} {}".format(asterisks, cert.get_subject()))

    print("\n>> Certificate Details:\n")
    for cert in reversed(chain):
        pkey = cert.get_pubkey()
        print("." * 80)
        print("- [Subject]:\t\t{}".format(cert.get_subject()))
        print("- [Issuer]:\t\t{}".format(cert.get_issuer()))
        print("- [Valid from]:\t\t{}".format(cert.get_notBefore()))
        print("- [Valid until]:\t{}".format(cert.get_notAfter()))
        print("- [Has Expired]:\t{}".format(cert.has_expired()))

    print("\n")
    client_ssl.close()
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
