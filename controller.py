from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_2
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import icmp

IP_GROUP = [['10.0.0.{}'.format(i) for i in range(1, 4)],
            ['10.0.0.{}'.format(i) for i in range(4, 7)],
            ['10.0.1.0']]


class Controller(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_2.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(Controller, self).__init__(*args, **kwargs)
        self.ip_addr = "10.0.1.0"  # controller's ip
        self.hw_addr = "66:66:66:66:66:66"  # controller's MAC addr
        self.mac_to_port = {}  # Records the mac-port mapping

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        self.add_flow(datapath, 0, 0, match, inst)
        self.send_group_mod(datapath)
        self.group_stats_request(datapath)

    # This function helps add flow entry to switch's flow table 
    # TODO: Insert different flow entries.
    #       Some action should be redirected to match other flow table 
    #       (Multiple flow table pipeline packet processing)
    def add_flow(self, datapath, table_id, priority, match, inst):
        ofproto = datapath.ofproto

        # Use FlowMod to add flow entry to flow table
        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, table_id=table_id,
            priority=priority, match=match, instructions=inst)

        datapath.send_msg(mod)

    def send_group_mod(self, datapath):
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser

        port = 1
        max_len = 2000
        actions = [ofp_parser.OFPActionOutput(port, max_len)]
        weight = 100
        watch_port = 0
        watch_group = 0
        buckets = [ofp_parser.OFPBucket(weight, watch_port, watch_group,
                                        actions)]
        group_id = 1

        req = ofp_parser.OFPGroupMod(datapath, ofp.OFPGC_ADD,
                                     ofp.OFPGT_SELECT, group_id, buckets)

        datapath.send_msg(req)

    def group_stats_request(self, datapath):
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser

        req = ofp_parser.OFPGroupStatsRequest(datapath, 0, ofp.OFPG_ALL)

        datapath.send_msg(req)
    # The packet in handler, flows that cannot be parsed by switches
    # will be sent as a PacketIn to controller
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath  # Datapath instance helps connect to switch
        ofproto = datapath.ofproto
        in_port = msg.match['in_port']

        ################## TODO: Extract and filter packet here ##############
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        '''
        handle ping from host to controller 
        a complete ping request include
        step1: handle arp pkt from host
        step2: handle icmp pkt from host
        if pkt is not for controller,it will be handled as normal
        '''
        pkt_arp = pkt.get_protocol(arp.arp)
        # step1 : arp request just for controller
        if pkt_arp and pkt_arp.opcode == arp.ARP_REQUEST and pkt_arp.dst_ip == self.ip_addr:
            self._handle_arp(datapath, in_port, eth, pkt_arp)
            return
        # step2 : icmp ping request just for controller
        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
        pkt_icmp = pkt.get_protocol(icmp.icmp)
        if pkt_icmp and pkt_icmp.type == icmp.ICMP_ECHO_REQUEST and pkt_ipv4.dst == self.ip_addr:
            self._handle_icmp(datapath, in_port, eth, pkt_ipv4, pkt_icmp)
            return

        self._packet_filter(msg, datapath)

    def _packet_filter(self, msg, datapath):
        in_port = msg.match['in_port']
        ofproto = datapath.ofproto
        pkt = packet.Packet(msg.data)
        pkt_eth = pkt.get_protocol(ethernet.ethernet)
        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
        parser = datapath.ofproto_parser
        dpid = datapath.id

        eth_dst = pkt_eth.dst
        eth_src = pkt_eth.src

        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][eth_src] = in_port

        # Find which port should we send to 
        if eth_dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][eth_dst]
        else:  # No records, flooding
            out_port = ofproto.OFPP_FLOOD

        # Insert entry into switch
        actions = [parser.OFPActionOutput(port=out_port)]
        if out_port != ofproto.OFPP_FLOOD:

            match = parser.OFPMatch(in_port=in_port)
            # Parse port first (Table ID = 0)
            if in_port > 3:  # Illegal port, drop
                inst = [parser.OFPInstructionActions(ofproto.OFPIT_CLEAR_ACTIONS, [])]
                self.add_flow(datapath, 0, 1, match, inst)
                actions = []
            else:  # Forward to table 1
                inst = [parser.OFPInstructionGotoTable(1)]
                self.add_flow(datapath, 0, 1, match, inst)


                if pkt_ipv4:
                    # table 1
                    src_cat, src_group = self._categorize(pkt_ipv4.src)
                    dst_cat, dst_group = self._categorize(pkt_ipv4.dst)

                    match = parser.OFPMatch(in_port=in_port, ipv4_src=pkt_ipv4.src, ipv4_dst=pkt_ipv4.dst,
                                            eth_type=0x0800)
                    if src_cat == 'Internal' and dst_cat == 'External':  # Drop
                        print('here')
                        inst = [parser.OFPInstructionActions(ofproto.OFPIT_CLEAR_ACTIONS, [])]
                        actions = []
                    elif src_cat == 'External' and dst_cat == 'Internal':  # Forward
                        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
                    elif src_group == dst_group:  # Forward
                        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
                    else:  # Drop
                        inst = [parser.OFPInstructionActions(ofproto.OFPIT_CLEAR_ACTIONS, [])]
                        actions = []

                    self.add_flow(datapath, 1, 1, match, inst)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        # Send PacketOut message back to the switch
        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port,
            actions=actions, data=data)
        datapath.send_msg(out)

    def _categorize(self, addr):
        for i in range(len(IP_GROUP)):
            if addr in IP_GROUP[i]:
                return 'Internal', 'Group' + str(i)
        return 'External', None

    def _handle_arp(self, datapath, port, pkt_ethernet, pkt_arp):
        pkt = packet.Packet()
        pkt.add_protocol(ethernet.ethernet(ethertype=pkt_ethernet.ethertype,
                                           dst=pkt_ethernet.src,
                                           src=self.hw_addr))
        pkt.add_protocol(arp.arp(opcode=arp.ARP_REPLY,
                                 src_mac=self.hw_addr,
                                 src_ip=pkt_arp.dst_ip,
                                 dst_mac=pkt_arp.src_mac,
                                 dst_ip=pkt_arp.src_ip))
        self._send_packet(datapath, port, pkt)

    def _handle_icmp(self, datapath, port, pkt_ethernet, pkt_ipv4, pkt_icmp):
        pkt = packet.Packet()
        pkt.add_protocol(ethernet.ethernet(ethertype=pkt_ethernet.ethertype,
                                           dst=pkt_ethernet.src,
                                           src=self.hw_addr))
        pkt.add_protocol(ipv4.ipv4(dst=pkt_ipv4.src,
                                   src=pkt_ipv4.dst,
                                   proto=pkt_ipv4.proto))
        pkt.add_protocol(icmp.icmp(type_=icmp.ICMP_ECHO_REPLY,
                                   code=icmp.ICMP_ECHO_REPLY_CODE,
                                   csum=0,
                                   data=pkt_icmp.data))
        self._send_packet(datapath, port, pkt)

    def _send_packet(self, datapath, port, pkt):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt.serialize()
        data = pkt.data
        actions = [parser.OFPActionOutput(port=port)]
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER,
                                  actions=actions,
                                  data=data)
        datapath.send_msg(out)
