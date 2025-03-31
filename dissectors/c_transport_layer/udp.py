from core.dissector import Dissector
from core.registry import *
from dissectors.d_application_layer.dns import DNSDissector
from dissectors.d_application_layer.ssdp import SSDPDissector
from utils import byte_ops

class UDPDissector(Dissector):
    def dissect(self, packet):
        info = packet.get_payload()
        src_port = byte_ops.read_uint16_be(info[0:2])
        dst_port = byte_ops.read_uint16_be(info[2:4])
        length = byte_ops.read_uint16_be(info[4:6])
        
        packet.add_layer('UDP', {
            'src_port': src_port,
            'dst_port': dst_port,
            'length': length
        })
        
        next_dissector = DissectorRegistry.get_dissector('udp_port', dst_port)
        
        packet.set_current_offset(packet.get_current_offset() + 8)
        
        return packet.get_payload(), next_dissector

DissectorRegistry.register('ip_proto', 17, UDPDissector)
