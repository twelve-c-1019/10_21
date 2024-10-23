from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.lib.packet import arp, ether_types, ethernet, packet
from ryu.ofproto import ofproto_v1_3
from ryu.topology import event
from ryu.topology.api import get_link, get_switch
import networkx as nx

class NetworkTopology():
    def __init__(self):
        super().__init__()

    def dfs_search(self, src, dst, visited, current_path, paths):
        if src == dst:
            paths.append(current_path)
            return
        for neighbor in self.neighbors(src):
            if not visited[neighbor]:
                visited[neighbor] = True
                current_path.append(neighbor)
                self.dfs_search(neighbor, dst, visited, current_path, paths)
                current_path.pop()
                visited[neighbor] = False

    def find_paths(self, src, dst, first_port, last_port):
        visited = {}
        for s in self.nodes:
            visited[s] = False
        visited[src] = True
        current_path = [src]
        all_paths = []

        self.dfs_search(src, dst, visited, current_path, all_paths)

        if not all_paths:
            return []

        shortest_path = min(all_paths, key=len)
        longest_path = max(all_paths, key=len)

        path = longest_path if src != dst else [src]

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
        self.switches = []
        self.host_mac_to = {}

        self.topo = NetworkTopology()
        self.arp_cache = {}

    def get_switch_by_id(self, dpid):
        for dp in self.switches:
            if dp.id == dpid:
                return dp
        return None

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.msg.datapath
        ofproto = dp.ofproto
        parser = dp.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(dp, 0, match, actions)

    def add_flow(self, dp, priority, match, actions, buffer_id=None):
        ofproto = dp.ofproto
        parser = dp.ofproto_parser
        instructions = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=dp, buffer_id=buffer_id, priority=priority, match=match, instructions=instructions)
        else:
            mod = parser.OFPFlowMod(datapath=dp, priority=priority, match=match, instructions=instructions)
        dp.send_msg(mod)

    def configure_path(self, path, src_mac, dst_mac):
        path_str = src_mac
        for switch, in_port, out_port in path:
            dp = self.get_switch_by_id(int(switch))
            if not dp:
                continue

            parser = dp.ofproto_parser
            match = parser.OFPMatch(in_port=in_port, eth_src=src_mac, eth_dst=dst_mac)
            actions = [parser.OFPActionOutput(out_port)]
            self.add_flow(dp, 1, match, actions)
            path_str += "--{}-{}-{}".format(in_port, switch, out_port)

        path_str += "--" + dst_mac
        self.logger.info("Path: {} has been configured.".format(path_str))

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, event):
        msg = event.msg
        dp = msg.datapath
        ofproto = dp.ofproto
        parser = dp.ofproto_parser

        dpid = dp.id
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth.ethertype == ether_types.ETH_TYPE_LLDP or eth.ethertype == ether_types.ETH_TYPE_IPV6:
            return

        dst_mac = eth.dst
        src_mac = eth.src

        # 没太懂
        if src_mac not in self.host_mac_to.keys():
            self.host_mac_to[src_mac] = (dpid, in_port)

        if dst_mac in self.host_mac_to.keys():
            src_switch, first_port = self.host_connections[src_mac]
            dst_switch, final_port = self.host_connections[dst_mac]

            path = self.topo.find_paths(src_switch, dst_switch, first_port, final_port)
            if path:
                self.configure_path(path, src_mac, dst_mac)
                out_port = next((out for sw, _, out in path if sw == dpid), None)
                assert out_port is not None
            else:
                out_port = ofproto.OFPP_FLOOD
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]
        if msg.buffer_id != ofproto.OFP_NO_BUFFER:
            out = parser.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id, in_port=in_port, actions=actions)
        else:
            out = parser.OFPPacketOut(datapath=dp, buffer_id=ofproto.OFP_NO_BUFFER, in_port=in_port, actions=actions, data=msg.data)
        dp.send_msg(out)

    @set_ev_cls(event.EventSwitchEnter)
    def switch_enter_handler(self, event):

        all_switches = get_switch(self)
        self.topo.add_nodes_from([s.dp.id for s in all_switches])
        self.switches = [s.dp for s in all_switches]

        all_links = get_link(self)
        self.topo.add_edges_from([(l.src.dpid, l.dst.dpid, {"port": l.src.port_no}) for l in all_links])
        self.topo.add_edges_from([(l.dst.dpid, l.src.dpid, {"port": l.dst.port_no}) for l in all_links])
