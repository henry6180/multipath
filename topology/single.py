from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.link import TCLink
from mininet.topo import Topo
import time

SWITCHNUM = 6

class SingleTopo( Topo ):
    def build( self ):
        s=[self.addSwitch(f's{i+1}', cls=OVSSwitch) for i in range(SWITCHNUM)]
        h=[self.addHost(f'h{i+1}',mac=f'00:00:00:00:00:0{i+1}') for i in range(SWITCHNUM)]
        for i in range(SWITCHNUM-1):
            self.addLink(s[i],s[i+1], cls=TCLink, bw=5)
        for i in range(int(SWITCHNUM/2)):
            self.addLink(h[i],s[0], cls=TCLink, bw=5)
        for i in range(int(SWITCHNUM/2), SWITCHNUM):
            self.addLink(h[i],s[SWITCHNUM-1], cls=TCLink, bw=5)

def createTopo():
    topo = SingleTopo()
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
