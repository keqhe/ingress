import os, sys, commands
import time

#export PATH=/usr/local/bro/bin/:$PATH
direct1_in = 'in.pcap'
direct1_out = 'out.pcap'

stat, output = commands.getstatusoutput('/usr/local/bro/bin/bro  -r ' + direct1_in)
print stat
stat, output = commands.getstatusoutput('mv conn.log ' + 'conn.' + direct1_in)
print stat

stat, output = commands.getstatusoutput('/usr/local/bro/bin/bro  -r ' + direct1_out)
print stat
stat, output = commands.getstatusoutput('mv conn.log ' + 'conn.' + direct1_out)
print stat

