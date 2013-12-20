from __future__ import division
import os, sys, commands
import time

#expect two log files, recording when the packet_in message is received and when the flow_mod is sent by the C based controller

flow_mod = 'packet_mod_time.txt'
packet_in = 'packet_in_time.txt'
packet_out = 'packet_out_time.txt'

pcap_in = 'conn.in.pcap'
pcap_out = 'conn.out.pcap'

global flow_mode_timestamp
flow_mode_timestamp = {}
global packet_in_timestamp
packet_in_timestamp = {}
global packet_out_timestamp
packet_out_timestamp = {}



global pcap_pkt_in
pcap_pkt_in = {}

global pcap_pkt_out
pcap_pkt_out = {}


for line in open(packet_out):
        line = line.strip()
        words = line.split(' ')
	srcip = words[0][4:]
	dstip = words[1][4:]
        key = (srcip, dstip) #
        flow_mode_timestamp[key] = float(words[3])

for line in open(packet_in):
        line = line.strip()
        words = line.split(' ')
        srcip = words[0][4:]
        dstip = words[1][4:]
        key = (srcip, dstip) #
        packet_in_timestamp[key] = float(words[3])

for line in open(pcap_in,'r'):
	line = line.strip()
	if line[0] == '#':
		continue
	else:
		words = line.split()
		timestamp = words[0]
		srcip = words[2]
		dstip = words[4]
		key = (srcip, dstip)
		
		pcap_pkt_in[key[ = float(timestamp)


for line in open(pcap_out,'r'):
        line = line.strip()
        if line[0] == '#':
                continue
        else:
                words = line.split()
                timestamp = words[0]
                srcip = words[2]
                dstip = words[4]
                key = (srcip, dstip)

                pcap_pkt_out[key[ = float(timestamp)

w1 = open('pkt_in_out_delays,txt','w')

for key in packet_in_timestamp:
	print key, packet_in_timestamp[key], pcap_pkt_in[key], packet_out_timestamp[key],  pcap_pkt_out[key]
	
	w1.write('%s %s %d %d\n' % (key[0], key[1], (packet_in_timestamp[key] - pcap_pkt_in[key]) * 1000, (packet_out_timestamp[key] - pcap_pkt_out[key]) * 1000))
w1.close()



