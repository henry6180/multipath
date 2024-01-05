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
from ryu.topology.api import get_switch, get_link, get_host
import networkx as nx
from itertools import islice
import inspect
import matplotlib.pyplot as plt
import os.path
from operator import itemgetter



class Multipath(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(Multipath, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.switches=[]
        self.links=[]
        self.hosts=[]
        self.net=nx.DiGraph()
        self.count=0
        self.addHost_count = 0
    
    def k_shortest_paths(self, G, source, target, k, weight=None):
        return list(islice(nx.shortest_simple_paths(G, source, target, weight), k))

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        # print([x for x in dir(ev.msg) if not x[0].startswith('_')])
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

    def plotNet(self, file_name='test2.png'):
        options = {
            "font_size": 12,
            "node_size": 200,
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
        print(f'class: {thing.__class__}')
        for x in dir(thing):
            if not x[0].startswith('_'):
                print(x)
        print('')

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        if eth.ethertype == 34525: #Ipv6 packet
            return
        
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s, eth=%s", dpid, src, dst, in_port,hex(eth.ethertype))

        # print(eth.ethertype == ether_types.ETH_TYPE_IP)

        # if self.count == 0:
        #     # print(self.net)
        #     # print(src.__class__)
        #     print([x for x in dir(eth) if not x[0].startswith('_')])
        # self.count = (self.count+1)%300

        # Shortest path
        if src not in self.net:
            # print(f'{eth.ethertype == ether_types.ETH_TYPE_IP} (src)')
            # host_list = get_host(self)
            # for host in host_list:
            #     print(f'mac: {host.mac}, port: {host.port}, ipv4: {host.ipv4}')
            # print([x for x in inspect.getmembers(host_list[0]) if not x[0].startswith('_')])
            # print(host.to_dict(host) for host in host_list)
            self.net.add_node(src)
            self.net.add_edge(src,dpid)
            self.net.add_edge(dpid,src,**{'port':in_port})
            # print(f'self.net: {self.net}')
            self.plotNet()
        if dst in self.net:
            # print(f'{eth.ethertype == ether_types.ETH_TYPE_IP} (dst)')
            # host_list = get_host(self)
            # for host in host_list:
            #     print(f'mac: {host.mac}, port: {host.port}, ipv4: {host.ipv4}')
            path = nx.shortest_path(self.net, src, dst)
            next_hop = path[path.index(dpid)+1]
            out_port = self.net[dpid][next_hop]['port']
        else:
            out_port = ofproto.OFPP_FLOOD

        # switch learning
        # self.mac_to_port[dpid][src] = in_port
        # if dst in self.mac_to_port[dpid]:
        #     out_port = self.mac_to_port[dpid][dst]
        # else:
        #     out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            if eth.ethertype == ether_types.ETH_TYPE_IP:
                ip = pkt.get_protocol(ipv4.ipv4)
                srcip = ip.src
                dstip = ip.dst
                match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                        ipv4_src=srcip,
                                        ipv4_dst=dstip
                                        )
                # match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
                # verify if we have a valid buffer_id, if yes avoid to send both
                # flow_mod & packet_out
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
        # print([(x.dpid,x.port_no,x.hw_addr,x.ip) for x in ev.switch.ports])
        # print(f'address = {ev.switch.dp.address}')
        # self.show_dir(ev.switch.ports.hw_addr)
        switch_list = get_switch(self, None)
        self.switches=[switch.dp.id for switch in switch_list]
        self.net.add_nodes_from(self.switches)
        # print(self.switches)

        links_list = get_link(self, None)
        self.links=[(link.src.dpid,link.dst.dpid,{'port':link.src.port_no}) for link in links_list]
        self.net.add_edges_from(self.links)
        # print(self.links)
        # print(f'self.net: {self.net}')

        self.plotNet('test.png')

    @set_ev_cls(event.EventHostAdd)
    def host_add_handler(self, ev):
        # self.show_dir(ev.host)
        # print(ev.host.port)
        # print(ev.host.mac)
        # self.addHost_count+=1
        # print(f'addHost: {self.addHost_count}')
        self.hosts.append((ev.host.port.dpid, ev.host.port.port_no, ev.host.mac))
        # host_list = get_host(self)
        # self.hosts = [(host.port.dpid, host.port.port_no, host.mac) for host in host_list]
        self.hosts=sorted(self.hosts, key=itemgetter(0))
        # print(self.hosts)
        # if self.addHost_count==9:
            # for host in self.hosts:
            #     print(host)
            # for host in host_list:
            #     print(f'mac: {host.mac}, port: {host.port}, ipv4: {host.ipv4}, ipv6: {host.ipv6}')