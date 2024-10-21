from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import (CONFIG_DISPATCHER, MAIN_DISPATCHER,
                                    set_ev_cls)
from ryu.lib.packet import arp, ether_types, ethernet, packet
from ryu.ofproto import ofproto_v1_3
from ryu.topology import event
from ryu.topology.api import get_link, get_switch

class Topo():
    def __init__(self):
        super().__init__()

    def dfs(self, src, dst, vis, cur_path, all_paths):
        if src == dst:
            all_paths.append(cur_path)
            return
        for neighbor in self.neighbors(src):
            if not vis[neighbor]:
                vis[neighbor] = True
                cur_path.append(neighbor)
                self.dfs(neighbor, dst, vis, cur_path, all_paths)

                cur_path.pop()  # 回溯
                vis[neighbor] = False

    def find_longest_path(self,src,dst,first_port,last_port):
        vis = {}  
        for s in list(self.nodes):
            vis[s] = False  # 除 src 外，初始化为 False，即都未经过
        vis[src] = True

        cur_path = []
        cur_path.append(src)
        all_paths = []
        self.dfs(self, src, dst, vis, cur_path, all_paths)

        print("Found {} paths:".format(len(all_paths)))

        longest_path = max(all_paths,key = len)
        shortest_path = min(all_paths, key = len)
        print("Longest path: ", longest_path, "length: ", len(longest_path), sep=' ')
        print("Shortest path: ", shortest_path, "length: ", len(shortest_path), sep=' ')

        if src == dst:
            path = [src]
        else:
            path = longest_path

        ryu_path = []
        in_port = first_port
        for s1, s2 in zip(path[:-1], path[1:]):
            out_port = self.edges[s1, s2]["port"]
            ryu_path.append((s1, in_port, out_port))
            in_port = self.edges[s2, s1]["port"]
        ryu_path.append((dst, in_port, last_port))

        return ryu_path
    
class DFSController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(DFSController, self).__init__(*args, **kwargs)
        self.datapaths = []  # 保存受控制的交换机
        self.host_mac_to = {}  # 记录与主机直接相连的交换机 ID 与端口
        self.topo = Topo()  # 控制器发现的拓扑
        self.arp_history = {}  # ARP 历史记录
        self.discovery_limit = 4

    def find_datapath_by_id(self, dpid):
        for datapath in self.datapaths:
            if datapath.id == dpid:
                return datapath
        return None
    
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    def configure_path(self, path, src_mac, dst_mac):
        self.logger.info("Configuring related switches...")
        path_str = src_mac
        for switch, in_port, out_port in path:
            datapath = self.find_datapath_by_id(int(switch))
            assert datapath

            parser = datapath.ofproto_parser
            match = parser.OFPMatch(in_port=in_port, eth_src=src_mac, eth_dst=dst_mac)
            actions = [parser.OFPActionOutput(out_port)]
            self.add_flow(datapath, 1, match, actions)
            path_str += "--{}-{}-{}".format(in_port, switch, out_port)

        path_str += "--" + dst_mac
        self.logger.info("Path: {} has been configured.".format(path_str))
    
    def packet_in_handler(self, event):
        msg = event.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        dpid = datapath.id
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth.ethertype == ether_types.ETH_TYPE_LLDP or eth.ethertype == ether_types.ETH_TYPE_IPV6:
            return
        
        dst_mac = eth.dst
        src_mac = eth.src
        if src_mac not in self.host_mac_to.keys():
            self.host_mac_to[src_mac] = (dpid, in_port)

        if dst_mac in self.host_mac_to.keys():
            src_switch, first_port = self.host_mac_to[src_mac]
            dst_switch, final_port = self.host_mac_to[dst_mac]

            path = self.topo.find_longest_path(src_switch, dst_switch, first_port, final_port)
            self.configure_path(path, src_mac, dst_mac)
            out_port = None
            for switch, _, op in path:
                if switch == dpid:
                    out_port = op
            assert out_port
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER, in_port=in_port, actions=actions, data=msg.data)
        datapath.send_msg(out)

    @set_ev_cls(event.EventSwitchEnter)
    def switch_enter_handler(self, event):
        self.logger.info("SwitchEnterEvent received, start topology discovery...")
        if self.discovery_limit == 0:
            return

        self.topo.clear()
        
        # 保存交换机信息
        all_switches = get_switch(self)
        self.topo.add_nodes_from([s.dp.id for s in all_switches])
        self.switches = [s.dp for s in all_switches]
        self.logger.info("Total {} switches:".format(len(self.topo.nodes)))
        self.logger.info(self.topo.nodes)

        all_links = get_link(self)
        self.topology.add_edges_from([(l.src.dpid, l.dst.dpid, {"port": l.src.port_no}) for l in all_links])
        self.topology.add_edges_from([(l.dst.dpid, l.src.dpid, {"port": l.dst.port_no}) for l in all_links])
        self.logger.info("Total {} links: ".format(len(all_links)))
        self.logger.info(self.topo.edges())
        self.logger.info('Topology discovery succeeded.')

        self.discovery_limit -= 1




