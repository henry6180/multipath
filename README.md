# Multipath routing using Ryu and Mininet  
## Environment Setup  
### 1. Install Mininet  
```
sudo apt update
sudo apt install mininet
```
Verify:
```
sudo mn --test pingall
``` 
### 2. Install Ryu
**Do not Use python 3.10.x**: There are some bugs in package eventlet when installing ryu,
we prefer you to use **python3.8.x**.  
Install ryu:
```
pip install ryu
```
Check the version of ryu-manager:
```
ryu-manager --version
```
If the package setuptools has bugs, please uninstall it and install a lower version:
```
pip uninstall setuptools
pip install setuptools==59.5.0
```
Same if the package eventlet has bugs:
```
pip uninstall eventlet
pip install eventlet==0.30.2
```
Then install ryu again.  
Check the location of ryu-manager:
```
sudo find / -name ryu-manager 2>/dev/null
```
Run the Ryu Controller:
```
'location of ryu-manager'/ryu-manager ryu.app.simple_switch
```
### 3. Install other tools
(i) iperf:
```
sudo apt update
sudo apt install iperf
```
Verify:
```
iperf --version
```
(2) networkx:
```
pip install networkx
```
(3) matplotlib:
```
pip install matplotlib
```
(4)(optional) xterm:
```
sudo apt update
sudo apt install xterm
```
## Usage
### 1. First start the ryu application: multipath.py
```
'location of ryu-manager'/ryu-manager multipath.py --observe-links
```
### 2. Create the topology: fullyconnected.py
```
sudo python3 fullyconnected.py
```
### 3. Start iperf test
After entering the Mininet terminal, use iperf to test the topology.
In the following example, we  
(1) Let h1 be the iperf server and let h2 be the iperf client.  
(2) The default ip address of h1 is 10.0.0.1, you can change this in the fullyconnected.py.  
(3) Set the bandwidth limit to 10Mbps, test the topology 60 seconds, and report the result every 5 seconds.  
See <https://iperf.fr/> for more information about iperf.
```
h1 iperf -s &
h2 iperf -c 10.0.0.1 -b 10M -t 60 -i 5
```
### 4. Build multiple iperf sessions to see the effect of multipath
### 5. Exit and clean up the mininet
```
exit
sudo mn -c
```
The first line is to leave the mininet terminal and the second line is to clean up all setting about mininet including terminating the ryu application.
