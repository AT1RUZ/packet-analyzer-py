from core.dissector import Dissector
from core.registry import *
from utils import byte_ops

class UDPDissector(Dissector):
    def dissect(self, packet):
        src_port = byte_ops.read_uint16_be(packet.raw_data[0:2])
        dst_port = byte_ops.read_uint16_be(packet.raw_data[2:4])
        length = byte_ops.read_uint16_be(packet.raw_data[4:6])
        
        packet.add_layer('UDP', {
            'src_port': src_port,
            'dst_port': dst_port,
            'length': length
        })
        
        header_length = 8
        next_dissector = DissectorRegistry.get_dissector('udp_port', dst_port)
        return packet.get_payload(header_length), next_dissector

# Registro para puertos conocidos
DissectorRegistry.register('udp_port', 53, UDPDissector)  # DNS