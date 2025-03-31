from core.dissector import Dissector
from dissectors.b_network_layer.ipv4 import *
from dissectors.b_network_layer.ipv6 import *
from dissectors.b_network_layer.arp import *
from core.registry import *
from utils.byte_ops import extract_mac, read_uint16_be


class EthernetDissector(Dissector):
    def dissect(self, packet):
        header = packet.get_payload()
        dest_mac = extract_mac(header[0:6])
        src_mac = extract_mac(header[6:12])
        ethertype = read_uint16_be(header[12:14])

        packet.add_layer('Ethernet', {
            'dest_mac': dest_mac,
            'src_mac': src_mac,
            'ethertype': f"0x{ethertype:04x}"
        })
        
        next_dissector = DissectorRegistry.get_dissector('ethertype', ethertype)
        packet.set_current_offset(14)
        return packet.get_payload(), next_dissector
    




