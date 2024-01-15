from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.link import TCLink
from mininet.topo import Topo
import time

SWITCHNUM = 6

class CompleteTopo( Topo ):
    def build( self ):
        s=[self.addSwitch(f's{i+1}', cls=OVSSwitch) for i in range(SWITCHNUM)]
        h=[self.addHost(f'h{i+1}',mac=f'00:00:00:00:00:0{i+1}') for i in range(SWITCHNUM)]
        for i in range(SWITCHNUM):
            self.addLink(s[i],h[i], cls=TCLink, bw=100)
            for j in range(SWITCHNUM):
                if j>i: self.addLink(s[i],s[j], cls=TCLink, bw=100)

def createTopo():
    topo = CompleteTopo()
    c1=RemoteController(name='c1',ip='127.0.0.1',port=6653)
    net = Mininet(topo=topo,controller=c1,link=TCLink,switch=OVSSwitch)

    print("Starting network")
    net.start()
    net.pingAll()
    # print("Running CLI")
    # CLI(net)
    src = net.get('h1')
    dst = net.get('h2')
    src.cmd(f'iperf -s & ')
    count = 0
    while count<=100:
        count+=1
        result = dst.cmd(f'iperf -c {src.IP()} -b 100M -t 1')
        result=result.split('\n')
        print('\n'.join(result[0:]))
        time.sleep(2)
    print("Stopping network")
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    createTopo()
