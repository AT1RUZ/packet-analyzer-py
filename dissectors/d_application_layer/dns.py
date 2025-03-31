from core.dissector import Dissector
from utils import byte_ops

class DNSDissector(Dissector):
    def dissect(self, packet):
        data = packet.get_payload()
        transaction_id = byte_ops.read_uint16_be(data[0:2])
        flags = byte_ops.read_uint16_be(data[2:4])
        qdcount = byte_ops.read_uint16_be(data[4:6])
        ancount = byte_ops.read_uint16_be(data[6:8])
        
        dns_info = {
            'transaction_id': f"0x{transaction_id:04x}",
            'flags': f"0x{flags:04x}",
            'questions': qdcount,
            'answers': ancount,
            'queries': []
        }
        
        offset = 12
        # Leer preguntas
        for _ in range(qdcount):
            qname, offset = byte_ops.read_dns_name(data, offset)
            qtype = byte_ops.read_uint16_be(data[offset:offset+2])
            qclass = byte_ops.read_uint16_be(data[offset+2:offset+4])
            offset += 4
            
            dns_info['queries'].append({
                'name': qname,
                'type': qtype,
                'class': qclass
            })
        
        packet.add_layer('DNS', dns_info)
        return None, None  # Fin de la cadena


DNSDissector.register('udp_port', 53, DNSDissector)