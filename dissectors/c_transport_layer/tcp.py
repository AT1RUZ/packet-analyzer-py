from dissectors.dissector import Dissector
from dissectors.registry import *
from dissectors.d_application_layer.http import HTTPDissector
from dissectors.d_application_layer.ftp import FTPDissector
from utils.byte_ops import read_uint16_be

class TCPDissector(Dissector):
    def dissect(self, packet):
        payload = packet.get_payload()
        src_port = read_uint16_be(payload[0:2])
        dst_port = read_uint16_be(payload[2:4])
        
        header_length = ((payload[12] >> 4) & 0x0F) * 4
        
        
        if header_length < 20:
            raise ValueError(f"TCP header length inválido: {header_length} bytes")
        
        layer_data = ('TCP', {
            'src_port': src_port,
            'dst_port': dst_port,
            'header_length': header_length
        })
        
        next_dissector_type =  'tcp_port_types'
        next_dissector_id = dst_port
        
        # Actualizar el offset basado en el header length real
        packet.set_current_offset(packet.get_current_offset() + header_length)
        
        return packet.get_payload(), next_dissector_type, next_dissector_id, layer_data 