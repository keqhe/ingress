from __future__ import division
import os, sys, commands
import time

#expect two log files, recording when the packet_in message is received and when the flow_mod is sent by the C based controller

flow_mod = ''
packet_in = ''


global flow_mode_timestamp
flow_mode_timestamp = {}
global packet_in_timestamp
packet_in_timestamp = {}


for line in open(flow_mod):
        line = line.strip()
        words = line.split()
        key = (words[0], words[1]) #
        flow_mode_timestamp[key] = float(words[3])

for line in open(packet_in):
        line = line.strip()
        words = line.split()
        key = (words[0], words[1]) #
        packet_in_timestamp[key] = float(words[3])
