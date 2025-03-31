from core.dissector import Dissector
from core.registry import *
from dissectors.c_transport_layer.tcp import *
from dissectors.c_transport_layer.udp import *
from utils.byte_ops import read_uint8

class IPv4Dissector(Dissector):
    def dissect(self, packet):
        payload = packet.get_payload()
        # El IHL está en los 4 bits menos significativos del primer byte
        ihl = (payload[0] & 0x0F) * 4  # multiplicamos por 4 para obtener bytes
        
        # Verificar que el IHL sea válido (mínimo 20 bytes, máximo 60 bytes)
        if ihl < 20 or ihl > 60:
            raise ValueError(f"IHL inválido: {ihl} bytes")
            
        protocol = read_uint8(payload[9])
        packet.add_layer('IPv4', {
            'src_ip': '.'.join(map(str, payload[12:16])),
            'dst_ip': '.'.join(map(str, payload[16:20])),
            'protocol': protocol,
            'header_length': ihl
        })
        
        next_dissector = DissectorRegistry.get_dissector('ip_proto', protocol)
        
        # Actualizar el offset para el siguiente protocolo
        packet.set_current_offset(packet.get_current_offset() + ihl)
        
        return packet.get_payload(), next_dissector
    
DissectorRegistry.register('ethertype', 0x0800, IPv4Dissector)


