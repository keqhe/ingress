ps aux | grep -ie flowvisor | awk '{print $2}' | xargs kill -9
ps aux | grep -ie controller | awk '{print $2}' | xargs kill -9
ps aux | grep -ie tcpdump | awk '{print $2}' | xargs kill -9
ps aux | grep -ie hping | awk '{print $2}' | xargs kill -9
