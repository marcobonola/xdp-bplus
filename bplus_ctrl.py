from scapy.all import *
import sys

#def handle_packet(p):
#    print(p)

if len(sys.argv) < 3:
    print("syntax: python3 bplus_test.py <cmd> <key_value>")

cmd = sys.argv[1]
key = sys.argv[2]

pkt = Ether(dst='52:54:00:4a:49:df') /\
      IP(dst="192.160.50.150") /\
      UDP(sport=0x1234, dport=0xaaaa) /\
      Raw(int(cmd).to_bytes(4, 'little')) /\
      Raw(int(key).to_bytes(4, 'little'))

resp = srp1(pkt, iface="virbr1", verbose=True)

print(resp['Raw'][0])
