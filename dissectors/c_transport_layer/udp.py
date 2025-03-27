from core.dissector import Dissector
from core.registry import *
from dissectors.d_application_layer.dns import *
from utils import byte_ops

class UDPDissector(Dissector):
    def dissect(self, packet):
        print("DENTRO DE UDP")
        info = packet.get_payload()
        src_port = byte_ops.read_uint16_be(info[0:2])
        print(src_port)
        dst_port = byte_ops.read_uint16_be(info[2:4])
        print(dst_port)
        length = byte_ops.read_uint16_be(info[4:6])
        print(length)
        
        packet.add_layer('UDP', {
            'src_port': src_port,
            'dst_port': dst_port,
            'length': length
        })
        
        print(packet.layers)
        
        next_dissector = DissectorRegistry.get_dissector('udp_port', dst_port)
        
        packet.set_current_offset(packet.get_current_offset() + 8)
        
        return packet.get_payload(), next_dissector

# Registro para puertos conocidos
DissectorRegistry.register('udp_port', 53, DNSDissector)  # DNS