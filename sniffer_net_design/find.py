import re

class PacketFinder:

    def __init__(self, packet_records, search_terms: str):
        self.packet_records = packet_records
        self.search_terms_list = search_terms.lower().split(';')
        self.found_packets = []

    def find_packets(self):
        self.found_packets.clear()
        for term in self.search_terms_list:
            term = term.replace(' ', '')
            if match := re.match(r'(.+)\.(.+)=(.+)', term):
                layer = match.group(1)
                key = match.group(2)
                value = match.group(3)
                for packet in self.packet_records:
                    for p_layer, p_layer_info in packet.detail_info.items():
                        if layer == p_layer.lower():
                            for p_key, p_value in p_layer_info.items():
                                if key in p_key and p_value == value:
                                    self.found_packets.append(packet)
            elif match := re.match(r'(.+)in(.+)\.(.+)', term):
                value = match.group(1)
                layer = match.group(2)
                key = match.group(3)
                for packet in self.packet_records:
                    for p_layer, p_layer_info in packet.detail_info.items():
                        if layer == p_layer.lower():
                            for p_key, p_value in p_layer_info.items():
                                if key in p_key and value in p_value:
                                    self.found_packets.append(packet)
            elif match := re.match(r'(.+)', term):
                protocol = match.group(1)
                for packet in self.packet_records:
                    if packet.protocol.lower() == protocol:
                        self.found_packets.append(packet)
            else:
                pass

        return self.found_packets
