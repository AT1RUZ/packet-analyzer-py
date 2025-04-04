from dissectors.dissector import Dissector
from dissectors.registry import *
from dissectors.c_transport_layer.tcp import *
from dissectors.c_transport_layer.udp import *
from utils.byte_ops import read_uint8

class IPv4Dissector(Dissector):
    def dissect(self, packet):
        payload = packet.get_payload()
        
        ihl = (payload[0] & 0x0F) * 4
        
        if ihl < 20 or ihl > 60:
            raise ValueError(f"IHL inválido: {ihl} bytes")
            
        protocol = read_uint8(payload[9])
        layer_data = ('IPv4', {
            'src_ip': '.'.join(map(str, payload[12:16])),
            'dst_ip': '.'.join(map(str, payload[16:20])),
            'protocol': protocol,
            'header_length': ihl
        })
        
        next_dissector_type =  'ip_proto_types'
        next_dissector_id = protocol
        
        # Actualizar el offset para el siguiente protocolo
        packet.set_current_offset(packet.get_current_offset() + ihl)
        
        return packet.get_payload(), next_dissector_type, next_dissector_id, layer_data 

