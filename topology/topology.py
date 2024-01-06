from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.link import TCLink
from mininet.topo import Topo
import time

def runIperf(net, src, dst, bw_limit, duration=10):
    print("Starting iperf session from {} to {} with bandwidth limit {} Mbps".format(src, dst, bw_limit))
    # TODO (runIperf function)
    src,dst = net.get(src,dst)
    src_port = 5001
    src.cmd(f'iperf -s -p {src_port} & ')
    result = dst.cmd(f'iperf -c {src.IP()} -p {src_port} -b {bw_limit}M -t {duration}')
    result=result.split('\n')
    print('\n'.join(result[0:]))

class SampleTopo( Topo ):
    def build( self ):
        s=[self.addSwitch(f's{i+1}', cls=OVSSwitch) for i in range(6)]
        h=[self.addHost(f'h{i+1}',mac=f'00:00:00:00:00:0{i+1}') for i in range(9)]
        self.addLink(s[1],s[2], cls=TCLink)
        self.addLink(s[0],s[1], cls=TCLink)
        self.addLink(s[0],s[3], cls=TCLink)
        self.addLink(s[3],s[4], cls=TCLink)
        self.addLink(s[4],s[5], cls=TCLink)

        self.addLink(h[0],s[0], cls=TCLink)
        self.addLink(h[1],s[0], cls=TCLink)
        
        self.addLink(s[1],h[2], cls=TCLink)
        
        self.addLink(s[2],h[3], cls=TCLink)
        self.addLink(s[2],h[4], cls=TCLink)
        
        self.addLink(s[3],h[5], cls=TCLink)
        
        self.addLink(s[4],h[6], cls=TCLink)
        
        self.addLink(s[5],h[7], cls=TCLink)
        self.addLink(s[5],h[8], cls=TCLink)

def createTopo():
    # TODO (Generate Topology)
    topo = SampleTopo()
    c1=RemoteController(name='c1',ip='127.0.0.1',port=6653)
    net = Mininet(topo=topo,controller=c1,link=TCLink,switch=OVSSwitch)

    print("Starting network")
    net.start()

    # TODO (Set up iperf sessions)
    # runIperf(net=net,src='h1',dst='h2',bw_limit=5)
    # runIperf(net=net,src='h1',dst='h3',bw_limit=10)
    # runIperf(net=net,src='h4',dst='h5',bw_limit=15)
    # runIperf(net=net,src='h6',dst='h8',bw_limit=20)

    # print("Running CLI")
    # CLI(net)
    net.pingAll()
    # time.sleep(2)

    print("Stopping network")
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    createTopo()
