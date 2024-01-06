from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.link import TCLink
from mininet.topo import Topo
import time

SWITCHNUM = 5

class SampleTopo( Topo ):
    def build( self ):
        s=[self.addSwitch(f's{i+1}', cls=OVSSwitch) for i in range(SWITCHNUM)]
        h=[self.addHost(f'h{i+1}',mac=f'00:00:00:00:00:0{i+1}') for i in range(SWITCHNUM)]
        # link si to hi for i=1,2,...,SWITCHNUM and fully connect these switches.
        # self.addLink(h[0],s[0], cls=TCLink, bw=10)
        # self.addLink(h[1],s[SWITCHNUM-1], cls=TCLink, bw=10)
        for i in range(SWITCHNUM):
            self.addLink(s[i],h[i], cls=TCLink, bw=10)
            for j in range(SWITCHNUM):
                if j>i: self.addLink(s[i],s[j], cls=TCLink, bw=10)

def createTopo():
    topo = SampleTopo()
    c1=RemoteController(name='c1',ip='127.0.0.1',port=6653)
    net = Mininet(topo=topo,controller=c1,link=TCLink,switch=OVSSwitch)

    print("Starting network")
    net.start()

    net.pingAll()
    print("Running CLI")
    CLI(net)
    # time.sleep(2)

    print("Stopping network")
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    createTopo()
