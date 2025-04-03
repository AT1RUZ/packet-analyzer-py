from dissectors.dissector import Dissector
from dissectors.registry import *
from dissectors.c_transport_layer.tcp import *
from dissectors.c_transport_layer.udp import *
from utils import byte_ops

class IPv6Dissector(Dissector):
    def dissect(self, packet):
        header = packet.get_payload()
        
        version = header[0] >> 4
        traffic_class = ((header[0] & 0x0F) << 4) | (header[1] >> 4)
        flow_label = ((header[1] & 0x0F) << 16) | byte_ops.read_uint16_be(header[2:4])
        payload_length = byte_ops.read_uint16_be(header[4:6])
        next_header = header[6]
        hop_limit = header[7]
        src_ip = byte_ops.read_ipv6_address(header[8:24])
        dst_ip = byte_ops.read_ipv6_address(header[24:40])
        
        packet.add_layer('IPv6', {
            'version': version,
            'traffic_class': traffic_class,
            'flow_label': flow_label,
            'payload_length': payload_length,
            'next_header': next_header,
            'hop_limit': hop_limit,
            'src_ip': src_ip,
            'dst_ip': dst_ip
        })
        
        next_dissector = DissectorRegistry.get_dissector('ip_proto', next_header)
        packet.set_current_offset(packet.get_current_offset() + 40)
        return packet.get_payload(), next_dissector

# Registro para protocolos comunes sobre IPv6
# DissectorRegistry.register('ip_proto', 6, TCPDissector)  # TCP
# DissectorRegistry.register('ip_proto', 17, UDPDissector) # UDP