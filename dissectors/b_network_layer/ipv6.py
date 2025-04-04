from dissectors.dissector import Dissector
from dissectors.registry import *
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
        
        layer_data = ('IPv6', {
            'version': version,
            'traffic_class': traffic_class,
            'flow_label': flow_label,
            'payload_length': payload_length,
            'next_header': next_header,
            'hop_limit': hop_limit,
            'src_ip': src_ip,
            'dst_ip': dst_ip
        })
        
        next_dissector_type =  'ip_proto_types'
        next_dissector_id = next_header
        
        packet.set_current_offset(packet.get_current_offset() + 40)
        return packet.get_payload(), next_dissector_type, next_dissector_id, layer_data