from core.dissector import Dissector
from core.registry import *
from utils.byte_ops import read_uint16_be

class TCPDissector(Dissector):
    def dissect(self, packet):
        src_port = read_uint16_be(packet.raw_data[0:2])
        dst_port = read_uint16_be(packet.raw_data[2:4])
        
        packet.add_layer('TCP', {
            'src_port': src_port,
            'dst_port': dst_port
        })
        print("HOLA")
        header_length = (packet.raw_data[12] >> 4) * 4
        next_dissector = DissectorRegistry.get_dissector('tcp_port', dst_port)
        return packet.get_payload(header_length), next_dissector

# Registro para puerto 80 (HTTP)
DissectorRegistry.register('tcp_port', 80, TCPDissector)