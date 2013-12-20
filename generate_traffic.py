import os, sys, commands
import time
#when -i  u1.0 or u2.0, about 13-15K flows per second
#when -i u0.5, about 100K flows per second
#set environment variables for bro2.1
#export PATH=/usr/local/bro/bin:$PATH
tries = 1 
interval = 10
for i in xrange(tries):
	#time.sleep(interval)
	#now = i + 6000
	#stat, output = commands.getstatusoutput('sudo  -S hping3 --udp -I eth0 -i u10000.0 ' + '-s ' + str(now) + ' --scan 1-10 192.168.56.100')
	#for j in xrange(6000, 6015):
	#stat, output = commands.getstatusoutput('sudo  -S hping3 -I eth3 --udp -F  -i u1 -s 10 '  + ' 192.168.56.100 -c 1')
	#print output
	stat, output = commands.getstatusoutput('sudo  -S hping3 -I eth2 --udp -F  -i u20000 --rand-source  '  + ' 192.168.10.100 -c 50')
	#stat, output = commands.getstatusoutput('sudo  -S hping3 -I eth2 --udp  -i u50000.0  -s 0  192.168.56.10 -c 50')
	#time.sleep(10)
	print output
