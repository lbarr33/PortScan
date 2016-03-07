#! /usr/bin/python

import logging
import sys
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

with open(sys.argv[1], 'r') as f:
        hostlist = f.read().splitlines()
with open(sys.argv[2], 'r') as f:
        portlist = f.read().splitlines()
src_port = RandShort()
for dst_ip in hostlist:
        for str_dst_port in portlist:
                dst_port = int(str_dst_port)
                tcp_connect_scan_resp = sr1(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags="S"),timeout=10)
                if(str(type(tcp_connect_scan_resp))=="<type 'NoneType'>"):
                        print "Port " +str(dst_port)+ " is closed on " + str(dst_ip)
                elif(tcp_connect_scan_resp.haslayer(TCP)):
                        if(tcp_connect_scan_resp.getlayer(TCP).flags == 0x12):
                                send_rst = sr(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags="AR"),timeout=10)
                                print "Port " +str(dst_port)+ " is open on " +str(dst_ip)
                        elif (tcp_connect_scan_resp.getlayer(TCP).flags == 0x14):
                                print "Port " +str(dst_port)+ " is closed on " +str(dst_ip)
