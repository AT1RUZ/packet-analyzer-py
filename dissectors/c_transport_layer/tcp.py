from core.dissector import Dissector
from core.registry import *
from dissectors.d_application_layer.http import *
from utils.byte_ops import read_uint16_be

class TCPDissector(Dissector):
    def dissect(self, packet):
        info = packet.get_payload()
        src_port = read_uint16_be(info[0:2])
        dst_port = read_uint16_be(info[2:4])
        
        packet.add_layer('TCP', {
            'src_port': src_port,
            'dst_port': dst_port
        })
        
        next_dissector = DissectorRegistry.get_dissector('tcp_port', dst_port)
        
        packet.set_current_offset(packet.get_current_offset()+20)
        
        return packet.get_payload(), next_dissector

# Registro para puerto 80 (HTTP)
DissectorRegistry.register('tcp_port', 80, HTTPDissector)