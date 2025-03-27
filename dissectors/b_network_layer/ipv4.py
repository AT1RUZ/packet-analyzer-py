from core.dissector import Dissector
from core.registry import *
from dissectors.c_transport_layer.tcp import *
from dissectors.c_transport_layer.udp import *
from utils.byte_ops import read_uint8

class IPv4Dissector(Dissector):
    def dissect(self, packet):
        header = packet.raw_data[:20]
        version = header[0] >> 4
        ihl = (header[0] & 0x0F) * 4
        protocol = read_uint8(header[9])
        
        packet.add_layer('IPv4', {
            'src_ip': '.'.join(map(str, header[12:16])),
            'dst_ip': '.'.join(map(str, header[16:20])),
            'protocol': protocol
        })
        
        next_dissector = DissectorRegistry.get_dissector('ip_proto', protocol)
        return packet.get_payload(ihl), next_dissector

DissectorRegistry.register('ip_proto', 6, TCPDissector)
DissectorRegistry.register('ip_proto', 17, UDPDissector)
