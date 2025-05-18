from __future__ import print_function
from operator import attrgetter
import array

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import icmp
from ryu.lib import snortlib
from ryu.lib import hub


import socket
import datetime

UDP_IP = "127.0.0.1"
UDP_PORT = 8094

class SimpleSwitchSnort(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'snortlib': snortlib.SnortLib}

    def __init__(self, *args, **kwargs):
        super(SimpleSwitchSnort, self).__init__(*args, **kwargs)
        self.snort = kwargs['snortlib']
        self.snort_port = 6
        self.mac_to_port = {}
        self.datapaths = {}

        socket_config = {'unixsock': True}

        self.snort.set_config(socket_config)
        self.snort.start_socket_server()

        self.monitor_thread = hub.spawn(self._monitor)
        self.blocked_ips = set()

    def packet_print(self, pkt):
        pkt = packet.Packet(array.array('B', pkt))

        eth = pkt.get_protocol(ethernet.ethernet)
        _ipv4 = pkt.get_protocol(ipv4.ipv4)
        _icmp = pkt.get_protocol(icmp.icmp)

        if _icmp:
            self.logger.info("%r", _icmp)

        if _ipv4:
            self.logger.info("%r", _ipv4)

        if eth:
            self.logger.info("%r", eth)

    def extract_ip(self, pkt):
        pkt = packet.Packet(pkt)
        _ipv4 = pkt.get_protocol(ipv4.ipv4)
        if _ipv4:
            return _ipv4.src
        return None

    def block_ip(self, ip_src):
        self.protected_hosts = ['10.0.0.4', '10.0.0.5'] #Hosts confiables (servidores)

        if ip_src in self.protected_hosts:
            self.logger.warning("IP %s es víctima, no atacante. No se bloquea.", ip_src)
            return  # No bloquear víctimas

        if ip_src in self.blocked_ips:
            self.logger.info("La IP %s ya ha sido bloqueada. Ignorando...", ip_src)
            return

        for dp in self.datapaths.values():
            parser = dp.ofproto_parser
            match = parser.OFPMatch(eth_type=0x0800, ipv4_src=ip_src)
            actions = []
            self.add_flow(dp, 100, match, actions)
            self.logger.info("Regla instalada: bloquear todo IP desde %s", ip_src)

    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(10)

    def _request_stats(self, datapath):
#        self.logger.debug('send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)

    @set_ev_cls(snortlib.EventAlert, MAIN_DISPATCHER)
    def _dump_alert(self, ev):
        msg = ev.msg
        alert_msg = msg.alertmsg[0].decode()

        print('Alerta Snort recibe: %s' % alert_msg)

        # Aquí filtrem només els missatges que indiquen DoS o DDoS
        if ("ICMP flood" in alert_msg) or ("Possible DoS Attack Type" in alert_msg):
            ip_src = self.extract_ip(msg.pkt)
            if ip_src:
                self.logger.info("[BLOQUEO] Bloqueando IP sospechosa: %s", ip_src)
                self.block_ip(ip_src)
        else:
            self.logger.info("Alerta ignorada (no DoS/DDoS): %s", alert_msg)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        dpid = datapath.id
        self.datapaths[dpid] = datapath  # <-- Guardem datapath

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        # self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port),
                   parser.OFPActionOutput(self.snort_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            self.add_flow(datapath, 1, match, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        FLOW_MSG = "flows,datapath=%x in-port=%x,eth-dst=\"%s\",out-port=%x,packets=%d,bytes=%d %d"
        body = ev.msg.body
 #       self.logger.info('stats received: %016x', ev.msg.datapath.id)

        for stat in sorted([flow for flow in body if flow.priority == 1],
                           key=lambda flow: (flow.match['in_port'],
                                             flow.match['eth_dst'])):
            timestamp = int(datetime.datetime.now().timestamp() * 1000000000)
            msg = FLOW_MSG % (ev.msg.datapath.id,
                             stat.match['in_port'], stat.match['eth_dst'],
                             stat.instructions[0].actions[0].port,
                             stat.packet_count, stat.byte_count,
                             timestamp)
#            self.logger.info(msg)
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(msg.encode(), (UDP_IP, UDP_PORT))

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        PORT_MSG = "ports,datapath=%x,port=%x rx-pkts=%d,rx-bytes=%d,rx-error=%d,tx-pkts=%d,tx-bytes=%d,tx-error=%d %d"
        body = ev.msg.body
#        self.logger.info('stats received: %016x', ev.msg.datapath.id)

        for stat in sorted(body, key=attrgetter('port_no')):
            timestamp = int(datetime.datetime.now().timestamp() * 1000000000)
            msg = PORT_MSG % (ev.msg.datapath.id, stat.port_no,
                             stat.rx_packets, stat.rx_bytes, stat.rx_errors,
                             stat.tx_packets, stat.tx_bytes, stat.tx_errors,
                             timestamp)
#            self.logger.info(msg)
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(msg.encode(), (UDP_IP, UDP_PORT))
