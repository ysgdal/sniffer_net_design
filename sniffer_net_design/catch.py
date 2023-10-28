import scapy.utils
from scapy.all import *
from PyQt5.QtWidgets import *
from data import PacketInfo
import time
import re
import signal

class PacketSniffer:

    def __init__(self, gui_interface: QWidget):
        self.signal_triggers = signal.Signals()
        self.gui: QWidget = gui_interface
        self.network_interface = ''
        self.filter_criteria = ''
        self.packet_count = 0
        self.capture_time = 0
        self.sniffer_instance = None
        self.capture_active = False
        self.current_packet_data = None
        self.packet_list = []

    def activate(self):
        self.network_interface = self.gui.if_box.currentText()
        if self.network_interface == '网卡':
            return
        self.reset_data()  # Reset data before activating
        self.capture_active = True
        self.sniffer_instance = AsyncSniffer(
            iface=self.network_interface, prn=self.process_packet,
            filter=self.filter_criteria
        )
        self.capture_time = time.time()
        self.sniffer_instance.start()

    def deactivate(self):
        self.sniffer_instance.stop()
        self.capture_active = False

    def reset_data(self):
        self.packet_count = 0
        self.packet_list.clear()

    def update_filter(self, filter_string):
        self.filter_criteria = filter_string


    def identify_protocol(self):
        protocol_chain = self.current_packet_data.summary().split('/')
        arp_protocol_list = ['ARP', 'RARP', 'DHCP']
        for protocol in arp_protocol_list:
            if protocol in protocol_chain[1]:
                return protocol
        if 'IP' in protocol_chain[1]:
            if 'Raw' in protocol_chain[-1] or 'Padding' in protocol_chain[-1]:
                upper_protocol = protocol_chain[-2]
            else:
                upper_protocol = protocol_chain[-1]
            return upper_protocol.strip().split(' ')[0]
        elif 'IPv6' in protocol_chain[1]:
            return 'IPv6/' + protocol_chain[2].strip().split(' ')[0]
        else:
            protocol = protocol_chain[2].strip().split(' ')[0]
            if protocol != '':
                protocol += '/'
            protocol += protocol_chain[2].split(' ')[1]
            return protocol

    def fetch_packet_info(self, protocol):
        protocol_chain = self.current_packet_data.summary().split("/")
        if "Ether" in protocol_chain[0]:
            if 'ARP' in protocol:
                arp_info = protocol_chain[1].strip()
                pattern_request = r'ARP who has (\S+) says (\S+)'
                pattern_reply = r'ARP is at (\S+) says (\S+)'
                if match := re.match(pattern_request, arp_info):
                    target = match.group(1)
                    sender = match.group(2)
                    info = f'Who has {target}? Tell {sender}'
                elif match := re.match(pattern_reply, arp_info):
                    mac = match.group(1)
                    sender = match.group(2)
                    info = f'{sender} is at {mac}'
                else:
                    info = protocol_chain[1].strip()
            elif 'DNS' in protocol:
                info = protocol_chain[-1].strip()
            elif 'TCP' in protocol or 'UDP' in protocol:
                info = ' '.join(protocol_chain[2:]).strip()
            else:
                info = ' '.join(protocol_chain[1:]).strip()
            return info
        else:
            return self.current_packet_data.summary()

    def extract_src_and_dst(self):
        if self.current_packet_data.haslayer('IP'):
            src = self.current_packet_data['IP'].src
            dst = self.current_packet_data['IP'].dst
        else:
            src = self.current_packet_data[0].src
            dst = self.current_packet_data[0].dst
            if dst == 'ff:ff:ff:ff:ff:ff':
                dst = 'Broadcast'
        return src, dst

    def process_packet(self, pkt: Packet):
        self.packet_count += 1
        self.current_packet_data = pkt
        raw_output = pkt.show(dump=True)
        hex_output = scapy.utils.hexdump(pkt, dump=True)
        packet_timestamp = str(pkt.time - self.capture_time)[0:9]
        src, dst = self.extract_src_and_dst()
        protocol = self.identify_protocol()
        packet_length = len(pkt)
        info = self.fetch_packet_info(protocol)
        packet_detail = PacketInfo()
        payload_output = str(bytes(pkt.payload.payload.payload))
        packet_detail.from_args(
            self.packet_count, packet_timestamp, src, dst,
            protocol, packet_length, info, raw_output, hex_output, payload_output
        )
        self.packet_list.append(packet_detail)
        self.signal_triggers.update_table.emit(packet_detail)

    def reset_data(self):  # New method to reset data
        self.packet_count = 0
        self.packet_list.clear()
