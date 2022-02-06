from scapy.all import *
import sys

#def handle_packet(p):
#    print(p)

if len(sys.argv) < 2:
    print("syntax: python3 bplus_test.py <key_value>")

k = sys.argv[1]

pkt = Ether(dst='52:54:00:4a:49:df') /\
      IP(dst="192.160.50.150")/ \
      UDP(sport=0x1234, dport=0xaaaa)/\
      Raw(int(k).to_bytes(4, 'little'))

resp = srp1(pkt, iface="virbr1", verbose=True)

print(resp['Raw'][0])
