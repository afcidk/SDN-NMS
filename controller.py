from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_2
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet   
from ryu.lib.packet import ether_types
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import icmp

class Controller(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_2.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(Controller, self).__init__(*args, **kwargs)
        self.ip_addr="10.0.1.0" # controller's ip
        self.hw_addr="66:66:66:66:66:66" # controller's MAC addr
        self.mac_to_port = {}  # Records the mac-port mapping

    
    # This function helps add flow entry to switch's flow table 
    # TODO: Insert different flow entries.
    #       Some action should be redirected to match other flow table 
    #       (Multiple flow table pipeline packet processing)
    def add_flow(self, datapath, port, dst, src, actions):
        ofproto = datapath.ofproto
     #   print("new flow entry %s %s %s", port, dst, src)

        # The flow entry
        match = datapath.ofproto_parser.OFPMatch(in_port=port,
                                                 eth_dst=dst,
                                                 eth_src=src)

        inst = [datapath.ofproto_parser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS, actions)]

        # Use FlowMod to add flow entry to flow table
        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, cookie=0, cookie_mask=0, table_id=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=0, buffer_id=ofproto.OFP_NO_BUFFER,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            flags=0, match=match, instructions=inst)

        datapath.send_msg(mod)

    # The packet in handler, flows that cannot be parsed by switches
    # will be sent as a PacketIn to controller
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath # Datapath instance helps connect to switch
        ofproto = datapath.ofproto
        in_port = msg.match['in_port']

        ################## TODO: Extract and filter packet here ##############
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        #print(pkt.protocols)  # Can extract different protocols here
  
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
        if pkt_icmp and pkt_icmp.type == icmp.ICMP_ECHO_REQUEST and pkt_ipv4.dst==self.ip_addr:	
		self._handle_icmp(datapath, in_port, eth, pkt_ipv4, pkt_icmp)
		return
		

        dst = eth.dst
        src = eth.src

        dpid = datapath.id

#        self.logger.info("PacketIn\n"
#                        "DatapathId: %s\n"
#                        "Source %s\n"
#                        "Dest %s\n"
#                        "Port %s\n", dpid, src, dst, in_port)

        self.mac_to_port.setdefault(dpid, {})
        # Learn the mac address (datapath with this address should go to that port)
        self.mac_to_port[dpid][src] = in_port

        # Find which port should we send to 
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else: # No records, flooding
            out_port = ofproto.OFPP_FLOOD
        ####################################################################


        # The message object
        actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]

        # Insert entry into switch
        if out_port != ofproto.OFPP_FLOOD:
            self.add_flow(datapath, in_port, dst, src, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER: 
            data = msg.data

        # Send PacketOut message back to the switch
        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port,
            actions=actions, data=data)
        datapath.send_msg(out) 

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
