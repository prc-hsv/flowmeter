from scapy.sessions import DefaultSession, TCPSession
from scapy.layers.inet import TCP, IP, UDP
from scapy.layers.l2 import ARP
from scapy.plist import PacketList
from flowmeter.flowmeter import Flowmeter
import time

FLOW_TIMEOUT = 120  # seconds
ACTIVITY_TIMEOUT = 5  # seconds

class FlowSession(TCPSession):

    def __init__(self, 
            flow_timeout: float = FLOW_TIMEOUT, 
            activity_timeout: float = ACTIVITY_TIMEOUT,
            *args, **kwargs):
        super(FlowSession, self).__init__(*args, **kwargs)
        self.flows = Flowmeter()
        self.flow_timeout = flow_timeout
        self.activity_timeout = activity_timeout
        self._first = True

    def _output_flow(self, sess_pkts: PacketList):
        self.lst = [pkt for pkt in self.lst if pkt not in sess_pkts]

        self.flows._pcap = sess_pkts
        try:
            self.flows.build_feature_dataframe().to_csv('test.csv', mode='a', header=self._first)
        except ValueError:
            print('Packet Summary:')
            print(sess_pkts.summary())
            raise
        self._first = False

    def on_packet_received(self, pkt):
        """Hook to the Sessions API: entry point of the dissection.
        This will defragment IP if necessary, then process to
        TCP reassembly.
        """
        # Get current time for later checks
        now = time.time()

        # Now see if we need to return a complete session
        pkt_list = self.toPacketList()
        sessions = pkt_list.sessions(self.flows._get_sessions)

        for k, sess in sessions.items():
            packet_times = [packet.time for packet in sess]
            if k == "Other" or "Ethernet" in k or "ARP" in k:
                # print('Got one!')
                continue
            if len(packet_times) < 2:
                continue
            if now - max(packet_times) >= self.activity_timeout:
                self._output_flow(sess)
                continue
            if now - min(packet_times) >= self.flow_timeout:
                self._output_flow(sess)
                continue

        # First, defragment IP if necessary
        pkt = self._ip_process_packet(pkt)
        # Now handle TCP reassembly
        pkt = self._process_packet(pkt)

        if not pkt:
            return
        
        DefaultSession.on_packet_received(self, pkt)

        if TCP in pkt:
            if pkt[TCP].flags.F or pkt[TCP].flags.R:
                pkt_list = self.toPacketList()
                sessions = pkt_list.sessions(self.flows._get_sessions)
                sess_id = self.flows._get_sessions(pkt)
                sess_pkts = sessions[sess_id]
                self._output_flow(sess_pkts)
            return
        