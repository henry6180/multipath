from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types

from ryu.lib.packet import ipv4
from ryu.topology import event
from ryu.topology.api import get_switch, get_link
import networkx as nx
import matplotlib.pyplot as plt
from itertools import islice
# import inspect
# import os.path
# from operator import itemgetter



class Multipath(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(Multipath, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.port2mac = {}
        self.switches=[]
        self.links=[]
        self.hosts={}
        '''
        mac_to_port={1: {mac1:port1, mac2:port2, ...},
                     2: {mac1:port1, mac2:port2, ...},
                     3: {mac1:port1, mac2:port2, ...},
                     ...
                     }
        where 1,2,3,... are dpid of switches and maci are all hosts in the network.

        port2mac={1: {port1: mac1, port2: mac2, ...},
                  2: {port1: mac1, port2: mac2, ...},
                  ...
                  }
            where porti in the {port1: mac1, port2: mac2, ...} are belongs to 1 switches.
        This table is to maintain the relationship between port number and mac address of each switch.

        switch = [1,2,3,4,5,...]
            where 1,2,3, ... are dpid of switches.

        links = [(1,2,{'port': 1}),
                 (2,1,{'port': 2}),
                 (2,3,{'port': 1}),
                 (3,2,{'port': 3}),
                 ...
                 (u,v,{'port': i}),
                 ...
                ]
            where u uses port i to connect to v.

        hosts = {'00:00:00:00:00:01': {dpid1: port_no1},
                 '00:00:00:00:00:02': {dpid2: port_no2},
                 ...
                }
            where host '00:00:00:00:00:0X' is connected to port_noX of dpidX.
        '''
        self.net=nx.DiGraph()
        self.count=0
    def k_shortest_paths(self, G, source, target, k, weight=None):
        return list(islice(nx.shortest_simple_paths(G, source, target, weight), k))

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    def plotNet(self, file_name='network.png'):
        options = {
            "font_size": 12,
            "node_size": 1000,
            "node_color": "white",
            "edgecolors": "black",
            "linewidths": 3,
            "width": 3,
        }
        pos=nx.spring_layout(self.net)
        nx.draw(self.net, pos, with_labels = True , **options)
        plt.savefig(file_name)
        plt.close()

    def show_dir(self, thing):
        print(thing)
        print(f'class: {thing.__class__}')
        print('elements:')
        for x in dir(thing):
            if not x[0].startswith('_'):
                print(x)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        dst = eth.dst
        src = eth.src
        '''
        if packet is lldp, then ignore
        if packet is ipv4, then use the shortest path
        if packet is not ipv4, then use the switch learning
        '''
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        if eth.ethertype == 0x0800:  #Ipv4 packet
            ip = pkt.get_protocol(ipv4.ipv4)
            src_ip = ip.src
            dst_ip = ip.dst
            # Shortest path
            if src_ip not in self.net:
                self.net.add_node(src_ip)
                self.net.add_edge(src_ip,dpid)
                self.net.add_edge(dpid,src_ip,**{'port':in_port})
                self.plotNet()
            if dst_ip in self.net:
                path = nx.shortest_path(self.net, src_ip, dst_ip)
                next_hop = path[path.index(dpid)+1]
                out_port = self.net[dpid][next_hop]['port']
            else:
                out_port = ofproto.OFPP_FLOOD
        else: #Not Ipv4 packet
            # switch learning
            self.mac_to_port[dpid][src] = in_port
            if dst in self.mac_to_port[dpid]:
                out_port = self.mac_to_port[dpid][dst]
            else:
                out_port = ofproto.OFPP_FLOOD
        self.logger.info("packet in %s %s %s %s, eth=%s", dpid, src, dst, in_port,hex(eth.ethertype))

        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            if eth.ethertype==0x0800:
                match = parser.OFPMatch(eth_type=eth.ethertype,
                                        ipv4_src=src_ip,
                                        ipv4_dst=dst_ip)
            else:
                match = parser.OFPMatch(eth_type=eth.ethertype,
                                        in_port=in_port, 
                                        eth_dst=dst, 
                                        eth_src=src)
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    @set_ev_cls(event.EventSwitchEnter)
    def get_topology_data(self, ev):
        # Get the relationship between port number and mac address of switches
        self.port2mac.setdefault(ev.switch.ports[0].dpid,{})
        for x in ev.switch.ports:
            self.port2mac[x.dpid][x.port_no] = x.hw_addr

        # Get all the dpid of switches
        switch_list = get_switch(self, None)
        self.switches=[switch.dp.id for switch in switch_list]
        self.net.add_nodes_from(self.switches)

        # Get all the links between switches
        links_list = get_link(self, None)
        self.links=[(link.src.dpid,link.dst.dpid,{'port':link.src.port_no}) for link in links_list]
        self.net.add_edges_from(self.links)

        # Plot the network that only consists of switches
        self.plotNet('switch.png')

    @set_ev_cls(event.EventHostAdd)
    def host_add_handler(self, ev):
        self.hosts.setdefault(ev.host.mac,{})
        self.hosts[ev.host.mac][ev.host.port.dpid] = ev.host.port.port_no