#! 
#clear
#flowrate and rule time out value is set in traffic generator and the controller
#make sure that the time out value is suitabel for a given flow rate and number of flows 
#clean the process if they are already running
ps aux | grep -ie flowvisor | awk '{print $2}' | xargs kill -9
ps aux | grep -ie controller | awk '{print $2}' | xargs kill -9
ps aux | grep -ie tcpdump | awk '{print $2}' | xargs kill -9
ps aux | grep -ie hping | awk '{print $2}' | xargs kill -9

#start the controller, running in the background
../openflow/controller/controller ptcp:6632 &

#start the flowvisor, make sure that the flowvisor connects to the controller successfully
./flowvisor ptcp:6633 &

#wait for everying to be running and connected successfully
sleep  30

#start the tcpdump and record the traces
tcpdump -w in.pcap -i eth2 &  #where the trace is injected
ip netns exec net3  tcpdump -w out.pcap -i eth3 & #where the trace is out from the switch

#sleep 120 && pkill -HUP -f tcpdump  & #terminate the tcpdump, note the parameter 60sec, that means we need to make sure the experiment can be finised in 60 seconds

#sleep for sometime so the tcpdump is initlized successfully
sleep 5

#generate the flows using the packet_generator 
python generate_traffic.py #essentially call hping3

#wait some time before we close the experiments
sleep 10

# close the measurement session
ps aux | grep -ie flowvisor | awk '{print $2}' | xargs kill -9
ps aux | grep -ie controller | awk '{print $2}' | xargs kill -9
#ps aux | grep -ie tcpdump | awk '{print $2}' | xargs kill -9
pkill -HUP -f tcpdump
ps aux | grep -ie hping | awk '{print $2}' | xargs kill -9

#process the recorded file and get the delay caculation
export PATH=/usr/local/bro/bin/:$PATH
python bro_trace.py
python parse_control.py

