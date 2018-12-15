from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_2
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet   
from ryu.lib.packet import ether_types


class Controller(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_2.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(Controller, self).__init__(*args, **kwargs)
        self.mac_to_port = {}  # Records the mac-port mapping

    # This function helps add flow entry to switch's flow table 
    # TODO: Insert different flow entries.
    #       Some action should be redirected to match other flow table 
    #       (Multiple flow table pipeline packet processing)
    def add_flow(self, datapath, port, dst, src, actions):
        ofproto = datapath.ofproto
        print("new flow entry %s %s %s", port, dst, src)

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
        print(pkt.protocols)  # Can extract different protocols here
        

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.logger.info("PacketIn\n"
                        "DatapathId: %s\n"
                        "Source %s\n"
                        "Dest %s\n"
                        "Port %s\n", dpid, src, dst, in_port)

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
