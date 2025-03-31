from core.dissector import Dissector
from core.registry import *
from dissectors.d_application_layer.http import HTTPDissector
from dissectors.d_application_layer.ftp import FTPDissector
from utils.byte_ops import read_uint16_be

class TCPDissector(Dissector):
    def dissect(self, packet):
        payload = packet.get_payload()
        src_port = read_uint16_be(payload[0:2])
        dst_port = read_uint16_be(payload[2:4])
        
        # El data offset está en los 4 bits más significativos del byte 12
        # Se multiplica por 4 para obtener el número de bytes
        header_length = ((payload[12] >> 4) & 0x0F) * 4
        
        # Verificar que el header length sea válido (mínimo 20 bytes)
        if header_length < 20:
            raise ValueError(f"TCP header length inválido: {header_length} bytes")
        
        packet.add_layer('TCP', {
            'src_port': src_port,
            'dst_port': dst_port,
            'header_length': header_length
        })
        
        # Verificar tanto puerto origen como destino para FTP
        next_dissector = None
        if dst_port in [20, 21] or src_port in [20, 21]:
            next_dissector = FTPDissector
        else:
            next_dissector = DissectorRegistry.get_dissector('tcp_port', dst_port)
        
        # Actualizar el offset basado en el header length real
        packet.set_current_offset(packet.get_current_offset() + header_length)
        
        return packet.get_payload(), next_dissector

DissectorRegistry.register('ip_proto', 6, TCPDissector)
